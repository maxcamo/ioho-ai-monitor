"""v0.7: verifiche report access log con payload legacy e limiti di campionamento."""
import os
import secrets

os.environ.setdefault('DATABASE_URL', f'sqlite:////tmp/ioho-v07-tests-{os.getpid()}.db')
os.environ.setdefault('DASHBOARD_USER','admin')
os.environ.setdefault('DASHBOARD_PASSWORD','test-dashboard-pass')
os.environ.setdefault('ZABBIX_WEBHOOK_TOKEN','test-webhook-token')
os.environ.setdefault('OPENAI_API_KEY','')

from fastapi.testclient import TestClient
from app.traffic_view import make_traffic_report
from app.db import init_db, Session, Server, Job, Analysis, token_digest
from app.main import app


def sample():
    window={
        'total': 300, 'rpm':30.0,'peak_per_minute':150,
        'unique_ips_observed':3,'filtered_hits':70,'blocked_hits':12,'http_5xx':6,
        'bot_ua_hits':45,'sampling_truncated':True,'observed_from':'2026-11-06T11:00+00:00',
        'observed_to':'2026-11-06T11:10+00:00',
        'statuses':{'200':280,'502':6,'403':12,'301':2},
        'top_clients':[{'ip':'192.0.2.55','count':160,'peak_per_minute':150,
                        'filtered':55,'blocked':9,'indicators':['molti filtri'],
                        'top_urls':[['/shopby/?cat',100]]}],
        'top_urls':[{'url':'/shopby/?cat','count':100,'filtered':60,'blocked':9},
                    {'url':'/catalogo','count':90,'filtered':0,'blocked':0}],
        'top_filtered_urls':[['/shopby/?cat',60]],
        'top_ip_urls':[{'ip':'192.0.2.55','url':'/shopby/?cat','count':100}],
        'per_minute':[['2026-11-06 11:09 UTC',150],['2026-11-06 11:08 UTC',60]],
    }
    return {'traffic':{'captured_at':'2026-11-06T11:10:00+00:00','windows':{'10':window,'5':window}},
            'access':{'top_user_agents':[['crawler',100]],'total':300,'statuses':window['statuses']},
            'coverage':{'access_truncated':True,'matched':1}}


def test_summary_legacy_and_partial_page_totals():
    report=make_traffic_report(sample())
    t=report['windows']['10']
    assert t['filtered_urls']==[{'url':'/shopby/?cat','count':60,'share':20.0}]
    assert [u['count'] for u in t['plain_urls']]==[90,40]
    assert t['plain_url_limited'] is True
    assert t['clients'][0]['share']==53.3
    assert t['clients'][0]['peak_per_minute']==150
    assert t['statuses'][0]['code']=='200'
    assert t['timeline'][1]['width']==100
    assert t['partial'] is True
    assert any('5xx' in finding for finding in t['findings'])


def test_html_access_report_shows_ip_filters_plain_and_no_duplicate_legacy():
    init_db()
    with Session.begin() as db:
        server=Server(name='v07-'+secrets.token_hex(5),
                      zabbix_host='z-v07-'+secrets.token_hex(5),
                      token_hash=token_digest(secrets.token_urlsafe(40)))
        db.add(server);db.flush()
        job=Job(server_id=server.id,kind='access_check',state='done',
                incident_name='Analisi access.log - ultimi 10 minuti',payload=sample(),context={'minutes':10})
        db.add(job);db.flush();jid=job.id
        db.add(Analysis(job_id=jid,severity='warning',summary='Traffico da verificare',diagnosis={
            'summary':'Traffico da verificare','probable_cause':'Indeterminata',
            'confidence':'low','evidence':[], 'recommendations':[], 'limitations':[]},ai_used=False))
    r=TestClient(app).get(f'/incident/{jid}',auth=('admin','test-dashboard-pass'))
    assert r.status_code==200,r.text[:1000]
    assert 'IP più attivi' in r.text
    assert 'Pagine con filtri Magento' in r.text
    assert 'Pagine senza filtri' in r.text
    assert '192.0.2.55' in r.text
    assert 'classifica parziale' in r.text.lower()
    assert 'Copertura incompleta' in r.text
    assert 'Chi sta chiamando Magento?' in r.text
    assert 'Traffico: URL e IP principali' not in r.text


def test_missing_traffic_shows_compatibility_notice():
    result=make_traffic_report({'coverage':{'no_access_log':True}})
    assert result['windows']=={}
    assert result['access_missing'] is True
