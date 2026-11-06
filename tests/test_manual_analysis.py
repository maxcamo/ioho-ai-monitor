import os
import secrets
from pathlib import Path
from datetime import datetime, timezone

os.environ.setdefault('DATABASE_URL', 'sqlite:////tmp/ioho-monitor-v05-test-%s.db' % os.getpid())
os.environ.setdefault('DASHBOARD_USER', 'admin')
os.environ.setdefault('DASHBOARD_PASSWORD', 'test-dashboard-pass')
os.environ.setdefault('ZABBIX_WEBHOOK_TOKEN', 'test-webhook-token')
os.environ.setdefault('OPENAI_API_KEY', '')

from fastapi.testclient import TestClient
from app.main import app
from app.db import init_db, Session, Server, Job, token_digest
from app.analysis import safe_ai_payload, rule_based
from agent.collector import collect


def setup_module(module):
    init_db()


def _server():
    with Session.begin() as db:
        s = Server(name='test-on-demand-%s' % secrets.token_hex(4),
                   zabbix_host='zbx-%s' % secrets.token_hex(4),
                   token_hash=token_digest(secrets.token_urlsafe(40)))
        db.add(s)
        db.flush()
        return s.id


def test_dashboard_and_buttons():
    sid = _server()
    client = TestClient(app)
    auth = ('admin', 'test-dashboard-pass')
    index = client.get('/', auth=auth)
    assert index.status_code == 200, index.text
    assert 'Analizza accessi 10m' in index.text
    assert 'Analizza applicativi 24h' in index.text
    page = client.get(f'/server/{sid}', auth=auth)
    assert page.status_code == 200, page.text
    assert 'Analizza accessi 10m' in page.text
    assert 'Analizza applicativi 24h' in page.text
    assert 'OpenAI non configurata' in page.text


def test_post_actions_are_limited_and_same_origin():
    sid = _server()
    client = TestClient(app)
    auth = ('admin', 'test-dashboard-pass')
    path = f'/server/{sid}/analyze/access'
    assert client.post(path, headers={'Origin':'https://evil.example'}, auth=auth).status_code == 403
    assert client.post(path, auth=auth).status_code == 403
    assert client.post(path,headers={'Origin':'http://testserver'}).status_code == 401
    r = client.post(path, headers={'Origin':'http://testserver'},auth=auth,follow_redirects=False)
    assert r.status_code == 303, r.text
    first = r.headers['location']
    assert first.startswith('/incident/')
    r2 = client.post(path, headers={'Origin':'http://testserver'},auth=auth,follow_redirects=False)
    assert r2.status_code == 303 and r2.headers['location'] == first
    a = client.post(f'/server/{sid}/analyze/app',headers={'Origin':'http://testserver'},auth=auth,follow_redirects=False)
    assert a.status_code == 303 and a.headers['location'] != first
    with Session() as db:
        jobs=db.query(Job).filter(Job.server_id==sid).all()
    assert sorted((job.kind, job.context['minutes']) for job in jobs) == [('access_check',10), ('app_check',1440)]
    for job in jobs:
        detail=client.get(f'/incident/{job.id}',auth=auth)
        assert detail.status_code == 200, detail.text


def test_collector_scoped_log_reading(tmp_path):
    moment=datetime.now(timezone.utc)
    stamp=moment.astimezone().strftime('%d/%b/%Y:%H:%M:%S %z')
    p=tmp_path/'access.log'
    p.write_text(f'192.0.2.1 - - [{stamp}] "GET /shopby?cat=5 HTTP/1.1" 200 20 "-" "crawler"\n')
    app=tmp_path/'system.log'
    app.write_text(f'[{moment.isoformat()}] main.ERROR: Missing required argument $name of Monolog Logger [] []\n')
    config={'access_logs':[str(p)],'app_logs':[str(app)],'nginx_error_logs':[],'server_timezone':'Europe/Rome'}
    a=collect(config,10,['access'])
    assert a['access']['total']==1 and not a['logs'] and a['traffic']['windows']['10']['total']==1
    b=collect(config,60,['app'])
    assert b['access']['total']==0 and b['traffic'] is None and 'system' in b['logs']
    assert b['logs']['system']['total']==1
    assert b['coverage']['no_access_log'] is False


def test_ai_traffic_has_no_ip_and_app_excludes_access():
    data={'traffic':{'windows':{'10':{'total':10,'top_clients':[{'ip':'192.0.2.1','count':10,'top_urls':[['/cat',10]]}], 'top_ip_urls':[{'ip':'192.0.2.1','url':'/cat','count':10}], 'top_urls':[{'url':'/cat','count':10}]}}},'access':{'top_clients':[['192.0.2.1',10]],'top_user_agents':[{'ua':'abc'}]},'logs':{}}
    safe=safe_ai_payload(data)
    assert '192.0.2.1' not in repr(safe)
    assert safe['traffic_aggregates']['10']['top_client_request_counts'][0]['count']==10
    assert safe['traffic_aggregates']['10']['top_urls'][0]['url']=='/cat'
    assert rule_based({'access':{'total':0},'coverage':{'no_access_log':True}}, 'access_check')['severity']=='unknown'


def test_traffic_and_app_reports_render_separately():
    sid = _server()
    with Session.begin() as db:
        a=Job(server_id=sid,kind='access_check',state='done',incident_name='Accessi test',context={'minutes':10},payload={
           'access': {'total':5,'statuses':{'200':5},'top_paths':[['/shopby',5]],'top_clients':[['192.0.2.1',5]],'filtered_requests':5,'known_bot_user_agent_hits':0},
           'coverage':{'matched':1,'truncated':False,'access_truncated':False,'no_access_log':False},'traffic':{'captured_at':'2026-11-06T10:00:00+00:00','windows':{}},'processes':[],'logs':{}})
        b=Job(server_id=sid,kind='app_check',state='done',incident_name='Applicativi test',context={'minutes':60},payload={
           'access':{'total':0,'statuses':{}},'coverage':{'matched':1,'truncated':True,'no_access_log':False},'logs':{'system':{'total':1,'groups':[{'signature':'main.ERROR: test exception','count':1,'count_5m':1,'count_15m':1,'count_60m':1,'peak_per_minute':1,'first_seen':'2026-11-06T10:00:00+00:00','last_seen':'2026-11-06T10:00:00+00:00','examples':[]}]}}})
        a.payload['traffic']['windows']={k:{'total':5,'peak_per_minute':2,'rpm':1,'unique_ips_observed':1,'filtered_hits':5,'blocked_hits':0,'http_5xx':0,'bot_ua_hits':0,'observed_from':None,'observed_to':None,'aggregation_capped':False,'top_urls':[],'top_clients':[],'top_ip_urls':[],'top_filtered_urls':[],'per_minute':[]} for k in ('5','10')}
        db.add_all([a,b]);db.flush();aid,bid=a.id,b.id
    client=TestClient(app);auth=('admin','test-dashboard-pass')
    for jid,should,not_expected in [(aid,'Chi sta chiamando Magento?', 'Errori applicativi per frequenza'),(bid,'Errori applicativi per frequenza','Chi sta chiamando Magento?')]:
        body=client.get(f'/incident/{jid}',auth=auth)
        assert body.status_code==200,body.text
        assert should in body.text
        assert not_expected not in body.text
