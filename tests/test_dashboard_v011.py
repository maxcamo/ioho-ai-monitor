"""v0.11 — rendering compatto e ordinamento criticita' in home."""
import os
import secrets

os.environ.setdefault("DATABASE_URL", f"sqlite:////tmp/ioho-v011-tests-{os.getpid()}.db")
os.environ.setdefault("DASHBOARD_USER", "admin")
os.environ.setdefault("DASHBOARD_PASSWORD", "test-dashboard-pass")
os.environ.setdefault("ZABBIX_WEBHOOK_TOKEN", "test-webhook-token")
os.environ.setdefault("OPENAI_API_KEY", "")

from fastapi.testclient import TestClient
from app.db import Session, Server, Job, Analysis, init_db, token_digest, utcnow
from app.main import app, display_servers


def setup_module(_):
    init_db()


def create_server(name, app_status=None, access_status=None):
    with Session.begin() as db:
        server = Server(name=name + "-" + secrets.token_hex(5),
                        zabbix_host="z-" + secrets.token_hex(6),
                        token_hash=token_digest(secrets.token_urlsafe(40)),
                        enabled=True, last_seen=utcnow())
        db.add(server)
        db.flush()
        sid = server.id
        for kind, minutes, severity in (
            ("app_check", 1440, app_status),
            ("access_check", 10, access_status),
        ):
            if severity is None:
                continue
            job = Job(server_id=sid, kind=kind, state="done",
                      context={"minutes": minutes}, updated_at=utcnow())
            db.add(job)
            db.flush()
            db.add(Analysis(job_id=job.id, severity=severity,
                            summary="DESCRIZIONE_INTERNA_NON_NELLA_LISTA",
                            diagnosis={}, ai_used=False))
    return sid, server.name


def test_sort_servers_by_worst_active_status():
    _, ok_name = create_server("zz-ok", "ok", "ok")
    _, warn_name = create_server("aa-warning", "warning", "ok")
    _, critical_name = create_server("zz-critical", "ok", "critical")
    _, unknown_name = create_server("aa-unknown", None, None)
    with Session() as db:
        rows = display_servers(db)
        names = [s["name"] for s in rows]
    assert names.index(critical_name) < names.index(warn_name)
    assert names.index(warn_name) < names.index(ok_name)
    assert names.index(ok_name) < names.index(unknown_name)


def test_compact_overview_badge_link_and_refresh_icon():
    sid, name = create_server("graphic", "warning", "ok")
    r = TestClient(app).get("/", auth=("admin", "test-dashboard-pass"))
    assert r.status_code == 200, r.text[:1000]
    overview = r.text.split("Stato per tipologia", 1)[1].split("Attività recente", 1)[0]
    assert "Zabbix:" not in overview
    assert "Ultimo aggiornamento:" not in overview
    assert "DESCRIZIONE_INTERNA_NON_NELLA_LISTA" not in overview
    assert "domain-updated" in overview
    assert "domain-recheck" in overview
    assert 'type="submit"' in overview
    assert 'status-report-link' in overview
    assert f'action="/server/{sid}/analyze/app"' in overview
    assert f'action="/server/{sid}/analyze/access"' in overview
    assert "Analizza applicativi 24h" in overview  # aria-label accessibile
    assert "Analizza accessi 10m" in overview
    # La CPU Zabbix in elenco e' esplicitamente rinviata alla prossima versione.
