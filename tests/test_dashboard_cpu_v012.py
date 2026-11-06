"""v0.12: CPU Zabbix visibile nella panoramica dal report HTTP persistito."""
import os
import secrets
from datetime import timedelta

os.environ.setdefault("DATABASE_URL", f"sqlite:////tmp/ioho-v012-tests-{os.getpid()}.db")
os.environ.setdefault("DASHBOARD_USER", "admin")
os.environ.setdefault("DASHBOARD_PASSWORD", "test-dashboard-pass")
os.environ.setdefault("ZABBIX_WEBHOOK_TOKEN", "test-webhook-token")
os.environ.setdefault("OPENAI_API_KEY", "")

from fastapi.testclient import TestClient
from app.db import Session, Server, Job, Analysis, init_db, token_digest, utcnow
from app.main import app, display_servers, cpu_from_access_audit


def setup_module(_):
    init_db()


def make_server_job(cpu_payload, minutes_ago=2):
    with Session.begin() as db:
        s = Server(name="cpu-v012-" + secrets.token_hex(5),
                   zabbix_host="z-cpu-v012-" + secrets.token_hex(5),
                   token_hash=token_digest(secrets.token_urlsafe(40)),
                   enabled=True, last_seen=utcnow())
        db.add(s)
        db.flush()
        j = Job(server_id=s.id, kind="access_check", state="done",
                context={"minutes": 10},
                updated_at=utcnow() - timedelta(minutes=minutes_ago),
                payload={"zabbix_cpu": cpu_payload})
        db.add(j)
        db.flush()
        db.add(Analysis(job_id=j.id, severity="warning",
                        summary="Report CPU tests", diagnosis={}, ai_used=False))
        return s.id, j.id


def test_cpu_last_and_peak_retrieved_from_latest_http_audit():
    sid, jid = make_server_job({"status": "ok", "last_pct": 34.3,
                                "peak_pct": 40.7, "avg_pct": 34.8})
    with Session() as db:
        rows = display_servers(db)
        row = next(row for row in rows if row["id"] == sid)
        cpu = row["access"]["cpu"]
        assert cpu["last_pct"] == 34.3
        assert cpu["peak_pct"] == 40.7
        assert cpu["stale"] is False
        assert row["app"]["cpu"] is None
    response = TestClient(app).get("/", auth=("admin", "test-dashboard-pass"))
    assert response.status_code == 200, response.text[:1200]
    overview = response.text.split("Stato per tipologia", 1)[1].split("Attività recente", 1)[0]
    # La nuova home usa l'ultimo campione live, non i dati del report orario.
    # I dati del job storico rimangono comunque accessibili per il dettaglio.
    assert "CPU" in overview
    assert f'/incident/{jid}' in overview


def test_cpu_stale_and_unavailable_never_fake_zero():
    sid, _ = make_server_job({"status": "ok", "last_pct": "12", "peak_pct": "22"},
                             minutes_ago=90)
    sid_missing, _ = make_server_job({"status": "item_missing", "message": "No item"})
    sid_bad, _ = make_server_job({"status": "ok", "last_pct": "nan", "peak_pct": 40})
    with Session() as db:
        rows = display_servers(db)
        by_id = {row["id"]: row for row in rows}
        assert by_id[sid]["access"]["cpu"]["stale"] is True
        assert by_id[sid_missing]["access"]["cpu"] is None
        assert by_id[sid_bad]["access"]["cpu"] is None
    page = TestClient(app).get("/", auth=("admin", "test-dashboard-pass")).text
    # I dati vecchi restano nel job; la home v0.13 mostra solo il live Zabbix.
    assert "Load 1m" in page
    assert "Processi" in page


def test_cpu_missing_payload_returns_none():
    now = utcnow()
    class DummyJob:
        updated_at = now
        payload = {"zabbix_cpu": {"status": "ok", "last_pct": "bad", "peak_pct": 30}}
    assert cpu_from_access_audit(DummyJob(), now) is None
    assert cpu_from_access_audit(None, now) is None
