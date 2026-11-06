import os
import secrets
from datetime import timedelta

os.environ.setdefault('DATABASE_URL', 'sqlite:////tmp/ioho-monitor-v06-test-%s.db' % os.getpid())
os.environ.setdefault('DASHBOARD_USER', 'admin')
os.environ.setdefault('DASHBOARD_PASSWORD', 'test-dashboard-pass')
os.environ.setdefault('ZABBIX_WEBHOOK_TOKEN', 'test-webhook-token')
os.environ.setdefault('OPENAI_API_KEY', '')

from fastapi.testclient import TestClient
from app.db import init_db, Session, Server, Job, Analysis, token_digest, utcnow
from app.main import app, domain_result, display_servers
from app.analysis import rule_based


def setup_module(module):
    init_db()


def test_domain_separation_and_time_freshness():
    with Session.begin() as db:
        server = Server(name='split-' + secrets.token_hex(4), zabbix_host='z-' + secrets.token_hex(4),
                        token_hash=token_digest(secrets.token_urlsafe(40)))
        db.add(server)
        db.flush()
        sid = server.id
        app_job = Job(server_id=sid, kind='app_check', context={'minutes': 1440}, state='done', updated_at=utcnow())
        access_job = Job(server_id=sid, kind='access_check', state='done', updated_at=utcnow())
        mixed = Job(server_id=sid, kind='incident', state='done', updated_at=utcnow())
        db.add_all([app_job, access_job, mixed]); db.flush()
        db.add_all([
            Analysis(job_id=app_job.id, severity='warning', summary='Magento exception', diagnosis={}, ai_used=False),
            Analysis(job_id=access_job.id, severity='critical', summary='HTTP 5xx', diagnosis={}, ai_used=False),
            Analysis(job_id=mixed.id, severity='ok', summary='legacy', diagnosis={}, ai_used=False),
        ])
    with Session() as db:
        app_check = domain_result(db, sid, 'app', utcnow())
        access_check = domain_result(db, sid, 'access', utcnow())
        assert app_check['status'] == 'warning'
        assert access_check['status'] == 'critical'
        assert app_check['summary'] == 'Magento exception'
        assert access_check['summary'] == 'HTTP 5xx'
        rows = display_servers(db)
        row = next(r for r in rows if r['id'] == sid)
        assert row['app']['status'] == 'warning' and row['access']['status'] == 'critical'
    auth=('admin', 'test-dashboard-pass')
    r = TestClient(app).get('/', auth=auth)
    assert r.status_code == 200, r.text
    assert 'Problemi applicativi' in r.text and 'Traffico e crawler' in r.text
    assert 'Magento exception' in r.text and 'HTTP 5xx' in r.text
    with Session.begin() as db:
        job = db.get(Job, access_job.id)
        job.updated_at = utcnow() - timedelta(minutes=22)
    with Session() as db:
        assert domain_result(db, sid, 'access', utcnow())['status'] == 'unknown'
        assert domain_result(db, sid, 'access', utcnow())['outdated'] is True
        assert domain_result(db, sid, 'app', utcnow())['status'] == 'warning'


def test_app_24h_traffic_does_not_influence_application_severity():
    app_data = {'window_minutes': 1440, 'access': {'total': 12345, 'statuses': {'502': 230}},
                'logs': {'exception': {'total': 120, 'groups': [{'count_60m': 0, 'peak_per_minute': 2}]}},
                'coverage': {'truncated': False}}
    d = rule_based(app_data, 'app_check')
    assert d['severity'] == 'warning'
    assert '24 ore' in d['summary']
    clean = dict(app_data, logs={'exception': {'total': 1, 'groups': [{'count_60m': 0, 'peak_per_minute': 1}]}})
    assert rule_based(clean, 'app_check')['severity'] == 'ok'
    assert rule_based({'access': {'total': 12345, 'statuses': {'502': 230}},
                       'logs': {}, 'coverage': {}}, 'app_check')['severity'] == 'unknown'
