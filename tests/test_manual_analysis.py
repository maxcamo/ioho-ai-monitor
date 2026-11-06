import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/ioho-monitor-v05-tests-%s.db" % os.getpid())
os.environ.setdefault("DASHBOARD_USER", "admin")
os.environ.setdefault("DASHBOARD_PASSWORD", "test-dashboard-pass")
os.environ.setdefault("ZABBIX_WEBHOOK_TOKEN", "test-webhook-token")
os.environ.setdefault("OPENAI_API_KEY", "")

from fastapi.testclient import TestClient
from app.main import app
from app.db import init_db, Session, Server, Job, token_digest
from app.analysis import safe_ai_payload, rule_based
from agent.collector import collect


def setup_module(module):
    init_db()


def _server():
    with Session.begin() as db:
        server = Server(name="manual-%s" % secrets.token_hex(4),
                        zabbix_host="zabbix-%s" % secrets.token_hex(4),
                        token_hash=token_digest(secrets.token_urlsafe(40)))
        db.add(server)
        db.flush()
        return server.id


def test_dashboard_has_both_actions():
    sid = _server()
    client = TestClient(app)
    auth = ("admin", "test-dashboard-pass")
    overview = client.get("/", auth=auth)
    assert overview.status_code == 200
    assert "Accessi 10m" in overview.text
    assert "Applicativi 60m" in overview.text
    details = client.get("/server/%s" % sid, auth=auth)
    assert details.status_code == 200
    assert "Analizza access.log + AI" in details.text
    assert "Analizza log Magento + AI" in details.text


def test_manual_jobs_are_authentic_and_deduplicated():
    sid = _server()
    client = TestClient(app)
    url = "/server/%s/analyze/access" % sid
    auth = ("admin", "test-dashboard-pass")
    assert client.post(url, headers={"Origin": "https://evil.invalid"}, auth=auth).status_code == 403
    assert client.post(url, auth=auth).status_code == 403
    assert client.post(url, headers={"Origin": "http://testserver"}).status_code == 401
    response = client.post(url, headers={"Origin": "http://testserver"}, auth=auth, follow_redirects=False)
    assert response.status_code == 303
    duplicate = client.post(url, headers={"Origin": "http://testserver"}, auth=auth, follow_redirects=False)
    assert duplicate.headers["location"] == response.headers["location"]
    second = client.post("/server/%s/analyze/app" % sid,
                         headers={"Origin": "http://testserver"}, auth=auth, follow_redirects=False)
    assert second.status_code == 303
    assert second.headers["location"] != response.headers["location"]
    with Session() as db:
        jobs = db.query(Job).filter(Job.server_id == sid).all()
    assert sorted((job.kind, job.context["minutes"]) for job in jobs) == [
        ("access_check", 10), ("app_check", 60)
    ]


def test_collector_reads_only_requested_log_type(tmp_path):
    moment = datetime.now(timezone.utc)
    timestamp = moment.astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
    access = tmp_path / "access.log"
    access.write_text(f'192.0.2.1 - - [{timestamp}] "GET /shopby?cat=5 HTTP/1.1" 200 20 "-" "crawler"\\n')
    app_log = tmp_path / "system.log"
    app_log.write_text(f'[{moment.isoformat()}] main.ERROR: Magento test exception [] []\\n')
    config = {"access_logs": [str(access)], "app_logs": [str(app_log)],
              "nginx_error_logs": [], "server_timezone": "Europe/Rome"}
    http = collect(config, 10, ["access"])
    assert http["access"]["total"] == 1 and not http["logs"] and http["traffic"]["windows"]["10"]["total"] == 1
    app_report = collect(config, 60, ["app"])
    assert app_report["access"]["total"] == 0 and app_report["traffic"] is None
    assert app_report["logs"]["system"]["total"] == 1
    assert app_report["coverage"]["no_access_log"] is False


def test_ai_payload_does_not_contain_client_ips():
    data = {"traffic": {"windows": {"10": {
        "total": 10,
        "top_clients": [{"ip": "192.0.2.1", "count": 10}],
        "top_ip_urls": [{"ip": "192.0.2.1", "url": "/cat", "count": 10}],
        "top_urls": [{"url": "/cat", "count": 10}]
    }}}, "access": {"top_clients": [["192.0.2.1", 10]]}, "logs": {}}
    safe = safe_ai_payload(data)
    assert "192.0.2.1" not in repr(safe)
    assert safe["traffic_aggregates"]["10"]["top_client_request_counts"][0]["count"] == 10
    assert safe["traffic_aggregates"]["10"]["top_urls"][0]["url"] == "/cat"
    assert rule_based({"access": {"total": 0}, "coverage": {"no_access_log": True}}, "access_check")["severity"] == "unknown"
