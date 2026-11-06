"""v0.9: Zabbix CPU snapshot, hourly jobs and UI separation."""
import os
import secrets
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", f"sqlite:////tmp/ioho-v09-tests-{os.getpid()}.db")
os.environ.setdefault("DASHBOARD_USER", "admin")
os.environ.setdefault("DASHBOARD_PASSWORD", "test-dashboard-pass")
os.environ.setdefault("ZABBIX_WEBHOOK_TOKEN", "test-webhook-token")
os.environ.setdefault("OPENAI_API_KEY", "")

from fastapi.testclient import TestClient
from app.zabbix_cpu import _choose_cpu_item, fetch_cpu_history
from app.db import init_db, Session, Server, Job, Analysis, token_digest, utcnow
from app.main import app, domain_result
import worker


def setup_module(_):
    init_db()


def test_cpu_zabbix_history_uses_exact_server_and_capture_time(monkeypatch):
    monkeypatch.setenv("ZABBIX_API_URL", "https://zabbix.invalid/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_API_TOKEN", "unit-test-token")
    monkeypatch.delenv("ZABBIX_CPU_ITEM_KEY", raising=False)
    captured = []
    point = datetime(2026, 11, 6, 12, 40, tzinfo=timezone.utc)

    def fake_rpc(url, token, method, params):
        assert url.endswith("/api_jsonrpc.php")
        assert token == "unit-test-token"
        captured.append((method, params))
        if method == "host.get":
            assert params["filter"]["host"] == ["eweki.it"]
            return [{"hostid": "1001", "host": "eweki.it"}]
        if method == "item.get":
            return [{"itemid": "2001", "key_": "system.cpu.util", "name": "CPU utilization",
                     "value_type": "0", "status": "0"},
                    {"itemid": "2002", "key_": "system.cpu.util[,user]",
                     "name": "CPU user time", "value_type": "0", "status": "0"}]
        if method == "history.get":
            assert params["itemids"] == ["2001"]
            assert params["time_from"] == int((point - timedelta(minutes=10)).timestamp())
            assert params["time_till"] == int(point.timestamp())
            return [{"clock": str(int((point - timedelta(minutes=2)).timestamp())), "value": "95"},
                    {"clock": str(int((point - timedelta(minutes=1)).timestamp())), "value": "65"}]
        raise AssertionError(method)

    result = fetch_cpu_history("eweki.it", {"traffic": {"captured_at": point.isoformat()}}, rpc=fake_rpc)
    assert [name for name, _ in captured] == ["host.get", "item.get", "history.get"]
    assert result["status"] == "ok"
    assert result["avg_pct"] == 80.0 and result["peak_pct"] == 95.0
    assert result["minutes"][0]["minute"] == "2026-11-06 12:38 UTC"
    assert result["sample_count"] == 2


def test_cpu_idle_is_inverted_but_user_cpu_is_not_accepted(monkeypatch):
    candidates = [{"itemid": "1", "name": "CPU user time", "key_": "system.cpu.util",
                   "status": "0", "value_type": "0"},
                  {"itemid": "2", "name": "CPU idle time", "key_": "system.cpu.util[,idle]",
                   "status": "0", "value_type": "0"}]
    item, invert = _choose_cpu_item(candidates)
    assert item["itemid"] == "2" and invert is True
    monkeypatch.setenv("ZABBIX_API_URL", "https://zabbix.invalid/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_API_TOKEN", "test-token")
    def fake_rpc(_url, _token, method, _params):
        if method == "host.get":
            return [{"hostid": "1"}]
        if method == "item.get":
            return candidates
        return [{"clock": str(int(datetime.now(timezone.utc).timestamp()) - 30), "value": "20"}]
    result = fetch_cpu_history("testhost", {}, rpc=fake_rpc)
    assert result["status"] == "ok"
    assert result["last_pct"] == 80.0


def test_missing_credentials_does_not_require_zabbix(monkeypatch):
    monkeypatch.delenv("ZABBIX_API_TOKEN", raising=False)
    result = fetch_cpu_history("eweki.it", {"timestamp_utc": "2026-11-06T12:40:00Z"})
    assert result == {"status": "not_configured"}


def test_hourly_scheduler_is_idempotent_and_status_has_75min_window(monkeypatch):
    monkeypatch.setenv("HOURLY_ACCESS_ENABLED", "true")
    fake_now = datetime(2026, 11, 6, 19, 3, tzinfo=timezone(timedelta(hours=1)))
    monkeypatch.setattr(worker, "local_now", lambda: fake_now)
    with Session.begin() as db:
        server = Server(name="hourly-" + secrets.token_hex(5),
                        zabbix_host="z-hourly-" + secrets.token_hex(5),
                        token_hash=token_digest(secrets.token_urlsafe(40)))
        db.add(server)
        db.flush()
        sid = server.id
    worker.enqueue_hourly_access()
    worker.enqueue_hourly_access()
    with Session() as db:
        jobs = db.query(Job).filter(Job.server_id == sid, Job.kind == "access_check").all()
        assert len(jobs) == 1
        assert jobs[0].context["minutes"] == 10 and jobs[0].context["automatic"]
    with Session.begin() as db:
        job = db.get(Job, jobs[0].id)
        job.state = "done"
        job.updated_at = utcnow() - timedelta(minutes=62)
        db.add(Analysis(job_id=job.id, severity="warning", summary="Crawler traffic",
                        diagnosis={}, ai_used=False))
    with Session() as db:
        status = domain_result(db, sid, "access", utcnow())
        assert status["status"] == "warning"
        assert status["outdated"] is False


def test_dashboard_severity_is_report_link_and_redundant_sentence_removed():
    auth = ("admin", "test-dashboard-pass")
    response = TestClient(app).get("/", auth=auth)
    assert response.status_code == 200
    assert "ogni ora" in response.text
    assert "Le due colonne sono indipendenti." not in response.text
    assert "OpenAI non configurata: analisi per regole locali." not in response.text
    assert "status-report-link" in response.text
    main_table = response.text.split("Stato per tipologia", 1)[1].split("Attività recente", 1)[0]
    assert "class=\"domain-updated\"" in main_table
    assert "class=\"domain-summary\"" not in main_table
