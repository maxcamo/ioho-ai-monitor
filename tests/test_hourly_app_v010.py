"""v0.10 — due scheduler orari separati e panoramica minimale."""
import os
import secrets
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", f"sqlite:////tmp/ioho-v010-tests-{os.getpid()}.db")
os.environ.setdefault("DASHBOARD_USER", "admin")
os.environ.setdefault("DASHBOARD_PASSWORD", "test-dashboard-pass")
os.environ.setdefault("ZABBIX_WEBHOOK_TOKEN", "test-webhook-token")
os.environ.setdefault("OPENAI_API_KEY", "")

from fastapi.testclient import TestClient
from app.db import Session, Server, Job, Analysis, init_db, token_digest, utcnow
from app.main import app, domain_result
import worker


def setup_module(_):
    init_db()


def _create_server():
    with Session.begin() as db:
        server = Server(
            name="v010-" + secrets.token_hex(6),
            zabbix_host="z-v010-" + secrets.token_hex(6),
            token_hash=token_digest(secrets.token_urlsafe(40)),
            enabled=True,
        )
        db.add(server)
        db.flush()
        return server.id


def test_both_hourly_domains_run_once_and_keep_correct_windows(monkeypatch):
    monkeypatch.setenv("HOURLY_ACCESS_ENABLED", "true")
    monkeypatch.setenv("HOURLY_APP_ENABLED", "true")
    monkeypatch.setattr(worker, "local_now", lambda: datetime(
        2026, 11, 6, 22, 4, tzinfo=timezone(timedelta(hours=1))))
    sid = _create_server()
    worker.enqueue_hourly_access()
    worker.enqueue_hourly_app()
    worker.enqueue_hourly_access()
    worker.enqueue_hourly_app()
    with Session() as db:
        jobs = db.query(Job).filter(Job.server_id == sid,
                                    Job.kind.in_(("app_check", "access_check"))).all()
        assert sorted((job.kind, job.context["minutes"]) for job in jobs) == [
            ("access_check", 10), ("app_check", 1440)
        ]
        assert all(job.context["automatic"] is True for job in jobs)
        assert all(job.state == "queued" for job in jobs)


def test_hourly_app_does_not_duplicate_recent_manual_result(monkeypatch):
    monkeypatch.setenv("HOURLY_APP_ENABLED", "true")
    monkeypatch.setattr(worker, "local_now", lambda: datetime(
        2026, 11, 6, 20, 4, tzinfo=timezone(timedelta(hours=1))))
    sid = _create_server()
    with Session.begin() as db:
        db.add(Job(server_id=sid, kind="app_check", state="done",
                   incident_name="Manual", created_at=utcnow() - timedelta(minutes=2),
                   context={"minutes": 1440}))
    worker.enqueue_hourly_app()
    with Session() as db:
        jobs = db.query(Job).filter(Job.server_id == sid, Job.kind == "app_check").all()
        assert len(jobs) == 1
        assert jobs[0].incident_name == "Manual"


def test_hourly_app_disabled_without_affecting_access(monkeypatch):
    monkeypatch.setenv("HOURLY_APP_ENABLED", "false")
    monkeypatch.setenv("HOURLY_ACCESS_ENABLED", "true")
    monkeypatch.setattr(worker, "local_now", lambda: datetime(
        2026, 11, 6, 23, 4, tzinfo=timezone(timedelta(hours=1))))
    sid = _create_server()
    assert worker.enqueue_hourly_app() == 0
    worker.enqueue_hourly_access()
    with Session() as db:
        jobs = db.query(Job).filter(Job.server_id == sid).all()
        assert any(job.kind == "access_check" for job in jobs)
        assert not any(job.kind == "app_check" for job in jobs)


def test_app_status_expires_after_90_minutes():
    sid = _create_server()
    with Session.begin() as db:
        job = Job(server_id=sid, kind="app_check", state="done",
                  context={"minutes": 1440}, updated_at=utcnow() - timedelta(minutes=85))
        db.add(job)
        db.flush()
        jid = job.id
        db.add(Analysis(job_id=jid, severity="warning", summary="Test exception v010",
                        diagnosis={}, ai_used=False))
    with Session() as db:
        status = domain_result(db, sid, "app", utcnow())
        assert status["status"] == "warning"
        assert status["outdated"] is False
    with Session.begin() as db:
        job = db.get(Job, jid)
        job.updated_at = utcnow() - timedelta(minutes=91)
    with Session() as db:
        status = domain_result(db, sid, "app", utcnow())
        assert status["status"] == "unknown"
        assert status["outdated"] is True


def test_home_has_badge_small_update_and_button_but_not_description():
    sid = _create_server()
    with Session.begin() as db:
        job = Job(server_id=sid, kind="app_check", state="done",
                  context={"minutes": 1440}, updated_at=utcnow())
        db.add(job)
        db.flush()
        db.add(Analysis(job_id=job.id, severity="critical",
                        summary="TEST-SUMMARY-MUST-BE-ONLY-IN-DETAILS",
                        diagnosis={}, ai_used=False))
    r = TestClient(app).get("/", auth=("admin", "test-dashboard-pass"))
    assert r.status_code == 200, r.text[:1000]
    overview = r.text.split("Stato per tipologia", 1)[1].split("Attività recente", 1)[0]
    assert "TEST-SUMMARY-MUST-BE-ONLY-IN-DETAILS" not in overview
    assert 'class="domain-updated"' in overview
    assert "Ultimo aggiornamento:" in overview
    assert "Analizza applicativi 24h" in overview
    assert "Analizza accessi 10m" in overview
    assert 'status-report-link' in overview
    assert "24h · auto ogni ora" in overview
