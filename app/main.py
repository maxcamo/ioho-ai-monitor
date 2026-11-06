import os
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from hmac import compare_digest
from pathlib import Path
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_
from app.db import Session, Server, Job, Analysis, init_db, utcnow
from app.security import agent_auth, dashboard_auth, webhook_auth
from app.log_groups import build_error_groups

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
            return {"job": {"id": job.id, "kind": job.kind, "minutes": 20 if job.kind == "incident" else 1440}}
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


def display_servers(db):
    servers = db.scalars(select(Server).order_by(Server.name)).all()
    result = []
    for s in servers:
        stale = not s.last_seen or (utcnow() - s.last_seen.replace(tzinfo=timezone.utc) if s.last_seen.tzinfo is None else utcnow() - s.last_seen) > timedelta(minutes=5)
        status = "unknown" if stale else s.last_status
        pending = db.scalar(select(Job).where(Job.server_id == s.id, Job.kind == "incident", Job.state.in_(["queued", "leased", "collected", "processing"])).order_by(Job.id.desc()))
        if pending and not stale and status in ("unknown", "ok"):
            status = "warning"
        result.append({"id": s.id, "name": s.name, "zabbix_host": s.zabbix_host,
                       "status": status, "stale": stale, "last_seen": s.last_seen,
                       "last_analysis_at": s.last_analysis_at})
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
        counters = {x: sum(1 for s in servers if s["status"] == x) for x in ("ok", "warning", "critical", "unknown")}
        return views.TemplateResponse(request=request, name="index.html", context={"servers": servers, "jobs": jobs, "counters": counters, "now": utcnow()})


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
        return views.TemplateResponse(request=request, name="server.html", context={"server": server, "jobs": jobs})


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
               "error_groups": groups, "legacy_logs": legacy})
