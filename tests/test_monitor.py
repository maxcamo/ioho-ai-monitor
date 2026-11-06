import importlib
import os
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import secrets

os.environ['DATABASE_URL'] = 'sqlite:///' + str(Path(tempfile.gettempdir()) / f'ioho_monitor_test_{os.getpid()}.db')
os.environ['DASHBOARD_USER'] = 'admin'
os.environ['DASHBOARD_PASSWORD'] = 'test-dashboard-pass'
os.environ['ZABBIX_WEBHOOK_TOKEN'] = 'test-webhook-token'
os.environ['OPENAI_API_KEY'] = ''

from fastapi.testclient import TestClient
from sqlalchemy import select
from app.db import init_db, Session, Server, Job, Analysis, token_digest
from app.main import app
from app.analysis import rule_based, safe_ai_payload
from agent.collector import collect


def setup_module(module):
    init_db()


def test_rules():
    data = {'access': {'total': 200, 'statuses': {'200': 170, '502': 30}}, 'logs': {}, 'coverage': {}}
    result = rule_based(data, 'nightly')
    assert result['severity'] == 'critical'
    assert rule_based({'access': {'total': 0, 'statuses': {}}, 'logs': {}, 'coverage': {'no_access_log': True}}, 'nightly')['severity'] == 'unknown'
    assert rule_based({'access': {'total': 50, 'statuses': {'200': 50}}, 'logs': {}, 'coverage': {}}, 'incident')['severity'] == 'warning'


def test_ai_payload_never_contains_ips():
    source = {'access': {'top_clients': [['1.2.3.4', 100]], 'top_user_agents': [['chrome', 12]], 'total': 100}, 'logs': {'exception': {'total': 1, 'samples': ['topsecret']}}, 'processes': [{'pid': 5, 'command': 'php-fpm'}]}
    safe = safe_ai_payload(source)
    assert '1.2.3.4' not in str(safe)
    assert 'topsecret' not in str(safe)
    assert 'pid' not in str(safe)


def test_collector(tmp_path):
    now = datetime.now().astimezone().strftime('%d/%b/%Y:%H:%M:%S %z')
    access = tmp_path / 'access.log'
    access.write_text(f'192.0.2.5 - - [{now}] "GET /catalog?cat=12&token=abc HTTP/1.1" 502 230 "-" "Googlebot"\n')
    app_log = tmp_path / 'exception.log'
    app_log.write_text(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ' main.CRITICAL: database timeout\n')
    config = {'access_logs': [str(access)], 'app_logs': [str(app_log)], 'nginx_error_logs': [], 'server_timezone': str(datetime.now().astimezone().tzinfo) if '/' in str(datetime.now().astimezone().tzinfo) else 'Europe/Rome'}
    result = collect(config, 20)
    assert result['access']['total'] == 1
    assert result['access']['filtered_requests'] == 1
    assert result['access']['statuses']['502'] == 1
    assert 'abc' not in str(result)


def test_end_to_end():
    token = secrets.token_urlsafe(32)
    with Session.begin() as db:
        server = Server(name='Polti TEST', zabbix_host='polti-test', token_hash=token_digest(token))
        db.add(server)
    client = TestClient(app)
    headers = {'X-Webhook-Token': 'test-webhook-token'}
    event = {'event_id': 'ZB-1', 'host': 'polti-test', 'name': 'CPU high', 'status': 'PROBLEM'}
    r = client.post('/api/zabbix/event', json=event, headers=headers)
    assert r.status_code == 200, r.text
    job_id = r.json()['job_id']
    assert client.post('/api/zabbix/event', json=event, headers=headers).json()['status'] == 'deduplicated'
    assert client.post('/api/zabbix/event', json=event).status_code == 401
    agent_headers = {'X-Agent-Token': token}
    next_job = client.get('/api/agent/next', headers=agent_headers)
    assert next_job.status_code == 200
    assert next_job.json()['job']['id'] == job_id
    evidence = {'window_minutes': 20, 'access': {'total': 100, 'statuses': {'200': 99, '502': 1}, 'top_clients': [['203.0.113.12', 55]], 'top_paths': [['/catalog', 70]]}, 'logs': {}, 'coverage': {'matched': 1, 'no_access_log': False, 'truncated': False}}
    result = client.post('/api/agent/result', json={'job_id': job_id, 'data': evidence}, headers=agent_headers)
    assert result.status_code == 200, result.text
    import worker
    assert worker.run_one() is True
    with Session() as db:
        job = db.get(Job, job_id)
        assert job.state == 'done'
        assert job.analysis.severity == 'warning'
        assert not job.analysis.ai_used
    auth = ('admin', 'test-dashboard-pass')
    assert client.get('/', auth=auth).status_code == 200
    assert client.get('/server/1', auth=auth).status_code == 200
    incident_page = client.get(f'/incident/{job_id}', auth=auth)
    assert incident_page.status_code == 200, incident_page.text
    assert '203.0.113.12' in incident_page.text
    assert client.get('/').status_code == 401


def test_ai_structured_response_with_mock(monkeypatch):
    import types
    import json
    from app.analysis import analyze
    captured = {}
    diagnosis = {'severity': 'warning', 'summary': 'Traffico sospetto, causa non certa', 'probable_cause': 'Potenziale bot', 'confidence': 'low', 'evidence': ['Picco richieste'], 'recommendations': ['Verificare Nginx'], 'limitations': ['Serve confronto con processi']}
    class FakeResponses:
        def create(self, **kwargs):
            captured.update(kwargs)
            return types.SimpleNamespace(output_text=json.dumps(diagnosis))
    class FakeClient:
        def __init__(self, **kwargs):
            self.responses = FakeResponses()
    monkeypatch.setenv('OPENAI_API_KEY', 'fake-test-key')
    monkeypatch.setitem(__import__('sys').modules, 'openai', types.SimpleNamespace(OpenAI=FakeClient))
    data = {'access': {'total': 50, 'statuses': {'200': 50}, 'top_clients': [['192.0.2.44', 50]], 'top_paths': [['/catalog', 50]]}, 'logs': {'nginx_error': {'total': 0, 'samples': ['secret-token']}}, 'coverage': {}}
    result, used = analyze(data, 'incident', {'name': 'CPU alta'})
    assert used and result['severity'] == 'warning'
    assert '192.0.2.44' not in captured['input'][1]['content']
    assert 'secret-token' not in captured['input'][1]['content']
    assert captured['store'] is False
