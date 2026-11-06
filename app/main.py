import os
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from hmac import compare_digest
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_
from app.db import Session, Server, Job, Analysis, init_db, utcnow
from app.security import agent_auth, dashboard_auth, webhook_auth
from app.log_groups import build_error_groups
from app.traffic_view import make_traffic_report

@asynccontextmanager
async def lifespan(app: FastAPI):
    for key in ("DASHBOARD_PASSWORD", "ZABBIX_WEBHOOK_TOKEN"):
        if not os.getenv(key) or os.getenv(key, "").startswith("CAMBIA_"):
            raise RuntimeError(f"Configurare {key} in .env")
    init_db()
    yield


app = FastAPI(title="IOHO AI Monitor", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
views = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class ZabbixEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=150)
    name: str = Field(default="CPU alta", max_length=255)
    status: str = Field(default="PROBLEM", max_length=30)
    severity: str = Field(default="", max_length=40)
    clock: str = Field(default="", max_length=80)


@app.get("/health")
def health():
    return {"status": "running"}


@app.post("/api/zabbix/event", dependencies=[Depends(webhook_auth)])
def zabbix_event(data: ZabbixEvent):
    if data.status.upper() not in ("PROBLEM", "1"):
        return {"status": "ignored", "reason": "not problem"}
    with Session.begin() as db:
        server = db.scalar(select(Server).where(Server.zabbix_host == data.host, Server.enabled.is_(True)))
        if not server:
            raise HTTPException(status_code=404, detail="Host non registrato: usare l'Host name tecnico di Zabbix")
        prior = db.scalar(select(Job).where(Job.event_id == data.event_id))
        if prior:
            return {"status": "deduplicated", "job_id": prior.id}
        # Evitare decine di diagnosi per trigger CPU contemporanei dello stesso server.
        cutoff = utcnow() - timedelta(minutes=15)
        active = db.scalar(select(Job).where(Job.server_id == server.id, Job.kind == "incident", Job.created_at >= cutoff, Job.state.in_(["queued", "leased", "collected", "processing", "done"])).order_by(Job.id.desc()))
        if active:
            return {"status": "rate_limited", "job_id": active.id}
        job = Job(server_id=server.id, kind="incident", event_id=data.event_id,
                  incident_name=data.name, context=data.model_dump(), state="queued")
        db.add(job)
        db.flush()
        return {"status": "queued", "job_id": job.id}


@app.get("/api/agent/next")
def agent_next(server: Server = Depends(agent_auth)):
    with Session.begin() as db:
        s = db.get(Server, server.id)
        s.last_seen = utcnow()
        # Un collector con lease scaduto ritenta solo una volta per job.
        expired = db.scalars(select(Job).where(Job.server_id == s.id, Job.state == "leased", Job.leased_until < utcnow())).all()
        for job in expired:
            job.state = "queued" if job.attempts < 2 else "error"
            job.error = "Collector non ha risposto entro il lease previsto."
        job = db.scalar(select(Job).where(Job.server_id == s.id, Job.state == "queued").order_by(Job.id).with_for_update(skip_locked=True))
        if job:
            job.state = "leased"
            job.attempts += 1
            job.updated_at = utcnow()
            job.leased_until = utcnow() + timedelta(minutes=7)
            return {"job": {"id": job.id, "kind": job.kind, "minutes": int((job.context or {}).get("minutes", 20 if job.kind in ("incident", "traffic_check") else 1440)), "sections": (["access"] if job.kind == "access_check" else ["app"] if job.kind == "app_check" else None)}}
        return {"job": None}


@app.post("/api/agent/result")
async def agent_result(request: Request, server: Server = Depends(agent_auth)):
    body = await request.body()
    if len(body) > 900_000:
        raise HTTPException(status_code=413, detail="Payload too large")
    try:
        import json
        payload = json.loads(body)
        job_id = int(payload["job_id"])
        evidence = payload["data"]
        if not isinstance(evidence, dict):
            raise ValueError("data must be object")
    except (ValueError, KeyError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid payload")
    with Session.begin() as db:
        job = db.scalar(select(Job).where(Job.id == job_id, Job.server_id == server.id).with_for_update())
        if job is None or job.state not in ("leased", "collected"):
            raise HTTPException(status_code=409, detail="Job not active")
        job.payload = evidence
        job.state = "collected"
        job.updated_at = utcnow()
        return {"status": "accepted"}


# Accessi e applicativi mantengono due stati autonomi: uno storico misto
# (nightly / Zabbix) non puo' rappresentare l'esito di uno dei due controlli.
DOMAIN_KINDS = {"access": "access_check", "app": "app_check"}
# Controlli orari: 75m accessi, 90m applicativi (margine per la coda).
DOMAIN_FRESHNESS = {"access": timedelta(minutes=75), "app": timedelta(minutes=90)}
ACTIVE_STATES = ("queued", "leased", "collected", "processing")


def domain_result(db, server_id: int, scope: str, now: datetime) -> dict:
    kind = DOMAIN_KINDS[scope]
    # I vecchi app_check di 60 minuti non vanno presentati come
    # controlli di 24 ore. Conserviamo comunque quei job nello storico.
    def latest(state_filter):
        candidates = db.scalars(select(Job).where(
            Job.server_id == server_id, Job.kind == kind,
            state_filter
        ).order_by(Job.id.desc()).limit(50)).all()
        return next((job for job in candidates if scope != "app" or
                     int((job.context or {}).get("minutes", 0)) == 1440), None)

    last = latest(Job.state == "done")
    active = latest(Job.state.in_(ACTIVE_STATES))
    failed = latest(Job.state == "error")
    analysis = last.analysis if last else None
    timestamp = last.updated_at if last else None
    if timestamp is not None and timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    outdated = bool(timestamp and now - timestamp > DOMAIN_FRESHNESS[scope])
    severity = analysis.severity if analysis else "unknown"
    # Un errore o una raccolta in corso non cancellano l'ultimo report, ma
    # ne impediscono l'interpretazione come stato attuale se ormai scaduto.
    status = severity if analysis and not outdated else "unknown"
    return {
        "status": status,
        "last_severity": severity,
        "summary": analysis.summary if analysis else "Nessuna analisi specifica completata.",
        "report_id": last.id if last else None,
        "timestamp": timestamp,
        "outdated": outdated,
        "pending_id": active.id if active else None,
        "failed_id": failed.id if failed and (not last or failed.id > last.id) else None,
    }


def display_servers(db):
    servers = db.scalars(select(Server).order_by(Server.name)).all()
    now = utcnow()
    result = []
    for s in servers:
        last_seen = s.last_seen
        if last_seen is not None and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        stale = not last_seen or now - last_seen > timedelta(minutes=5)
        result.append({"id": s.id, "name": s.name, "zabbix_host": s.zabbix_host,
                       "stale": stale, "app": domain_result(db, s.id, "app", now),
                       "access": domain_result(db, s.id, "access", now)})
    # Ordina dal peggiore dei due esiti aggiornati: Critical, Warning, OK,
    # infine Non verificato/Da aggiornare. Parita' in ordine alfabetico.
    severity_order = {"critical": 0, "warning": 1, "ok": 2, "unknown": 3}
    result.sort(key=lambda row: (
        min(severity_order.get(row[scope]["status"], 3) for scope in ("app", "access")),
        row["name"].casefold()))
    return result


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, _: str = Depends(dashboard_auth)):
    with Session() as db:
        servers = display_servers(db)
        jobs = db.scalars(select(Job).order_by(Job.id.desc()).limit(25)).all()
        for job in jobs:
            job.server.name  # eagerly read before session closes
            if job.analysis:
                job.analysis.severity
        counters = {scope: {status: sum(1 for s in servers if s[scope]["status"] == status)
                            for status in ("ok", "warning", "critical", "unknown")}
                    for scope in ("app", "access")}
        return views.TemplateResponse(request=request, name="index.html", context={"servers": servers, "jobs": jobs, "counters": counters, "now": utcnow(), "ai_ready": bool(os.getenv("OPENAI_API_KEY", "").strip())})


@app.post("/server/{server_id}/analyze/{scope}")
def request_manual_analysis(server_id: int, scope: str, request: Request, _: str = Depends(dashboard_auth)):
    """Un click autenticato accoda una sola analisi per tipologia e server."""
    if scope not in ("access", "app"):
        raise HTTPException(status_code=404)
    # Non accettare form POST cross-origin con credenziali Basic del browser.
    origin = request.headers.get("origin") or request.headers.get("referer")
    host = request.headers.get("host", "").lower()
    if not origin or urlsplit(origin).netloc.lower() != host:
        raise HTTPException(status_code=403, detail="Origine richiesta non valida")
    kind = "access_check" if scope == "access" else "app_check"
    minutes = 10 if scope == "access" else 1440
    with Session.begin() as db:
        server = db.get(Server, server_id)
        if not server or not server.enabled:
            raise HTTPException(status_code=404, detail="Server non disponibile")
        # Un job ancora attivo o appena eseguito non va duplicato a ogni click.
        prior = db.scalar(select(Job).where(
            Job.server_id == server_id,
            Job.kind == kind,
            Job.created_at >= utcnow() - timedelta(minutes=2),
            Job.state.in_(["queued", "leased", "collected", "processing", "done"])
        ).order_by(Job.id.desc()))
        if prior:
            job_id = prior.id
        else:
            job = Job(server_id=server_id, kind=kind, state="queued",
                      incident_name=("Analisi access.log - ultimi 10 minuti" if scope == "access"
                                     else "Analisi log applicativi - ultime 24 ore"),
                      context={"manual": True, "minutes": minutes, "scope": scope})
            db.add(job)
            db.flush()
            job_id = job.id
    return RedirectResponse(url=f"/incident/{job_id}", status_code=303)


@app.get("/server/{server_id}", response_class=HTMLResponse)
def server_page(server_id: int, request: Request, _: str = Depends(dashboard_auth)):
    with Session() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise HTTPException(404)
        jobs = db.scalars(select(Job).where(Job.server_id == server_id).order_by(Job.id.desc()).limit(70)).all()
        for job in jobs:
            if job.analysis:
                job.analysis.summary
        status_app = domain_result(db, server_id, "app", utcnow())
        status_access = domain_result(db, server_id, "access", utcnow())
        return views.TemplateResponse(request=request, name="server.html", context={"server": server, "jobs": jobs, "status_app": status_app, "status_access": status_access, "ai_ready": bool(os.getenv("OPENAI_API_KEY", "").strip())})


@app.get("/incident/{job_id}", response_class=HTMLResponse)
def incident_page(job_id: int, request: Request, _: str = Depends(dashboard_auth)):
    with Session() as db:
        job = db.get(Job, job_id)
        if not job:
            raise HTTPException(404)
        server = job.server
        analysis = job.analysis
        groups, legacy = build_error_groups(job.payload or {})
        return views.TemplateResponse(request=request, name="incident.html", context={"job": job, "server": server, "analysis": analysis,
               "data": job.payload or {}, "diagnosis": analysis.diagnosis if analysis else {},
               "error_groups": groups, "legacy_logs": legacy,
               "traffic_report": make_traffic_report(job.payload or {})})
