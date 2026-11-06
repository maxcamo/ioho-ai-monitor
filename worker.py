"""Un solo worker per istanza. Esegue la diagnosi AI e pianifica gli audit notturni."""
import html
import os
import smtplib
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from zoneinfo import ZoneInfo
from sqlalchemy import delete, select
from app.db import Session, Server, Job, Analysis, DailyMarker, init_db, utcnow
from app.analysis import analyze, rule_based

TZ = ZoneInfo(os.getenv("TZ", "Europe/Rome"))


def local_now():
    return utcnow().astimezone(TZ)


def marker_exists(db, kind, day):
    return db.scalar(select(DailyMarker).where(DailyMarker.kind == kind, DailyMarker.day == day)) is not None


def enqueue_nightly():
    now = local_now()
    if (now.hour, now.minute) < (int(os.getenv("NIGHTLY_HOUR", "2")), int(os.getenv("NIGHTLY_MINUTE", "30"))):
        return
    # Non avviare in massa audit arretrati a mezzogiorno dopo un riavvio.
    if now.hour >= 5:
        return
    day = now.strftime("%Y-%m-%d")
    with Session.begin() as db:
        if marker_exists(db, "nightly", day):
            return
        db.add(DailyMarker(kind="nightly", day=day))
        for server in db.scalars(select(Server).where(Server.enabled.is_(True))):
            db.add(Job(server_id=server.id, kind="nightly", incident_name=f"Audit notturno {day}",
                       context={"day": day}, state="queued"))
    print(f"[scheduler] audit notturno {day} accodato", flush=True)


def send_mail(day, records):
    host = os.getenv("SMTP_HOST", "")
    receiver = os.getenv("REPORT_TO", "")
    sender = os.getenv("SMTP_FROM", "")
    if not (host and receiver and sender):
        return False
    counts = {"critical": 0, "warning": 0, "ok": 0, "unknown": 0, "pending": 0}
    lines = []
    for name, job in records:
        if not job or job.state != "done" or not job.analysis:
            counts["pending"] += 1
            state = "NON VERIFICATO"
            message = "Analisi non completata"
        else:
            state = job.analysis.severity.upper()
            counts[job.analysis.severity] = counts.get(job.analysis.severity, 0) + 1
            message = job.analysis.summary
        lines.append(f"<tr><td>{html.escape(name)}</td><td>{html.escape(state)}</td><td>{html.escape(message)}</td></tr>")
    doc = ("<html><body style='font-family:Arial,sans-serif'><h2>IOHO AI Monitor — Report " + html.escape(day) + "</h2>"
           f"<p>Critici {counts['critical']} · Warning {counts['warning']} · OK {counts['ok']} · Non verificati {counts['unknown'] + counts['pending']}</p>"
           "<table border='1' cellpadding='7' style='border-collapse:collapse'><tr><th>Server</th><th>Stato</th><th>Diagnosi</th></tr>"
           + "".join(lines) + "</table><p>La classificazione AI è un supporto diagnostico e va verificata prima di interventi in produzione.</p></body></html>")
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = receiver
    msg["Subject"] = f"IOHO AI Monitor | Report notturno {day} | {counts['critical']} critici"
    msg.set_content(f"Report IOHO del {day}: critici={counts['critical']}, warning={counts['warning']}, non verificati={counts['pending'] + counts['unknown']}. Aprire la console per i dettagli.")
    msg.add_alternative(doc, subtype="html")
    port = int(os.getenv("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=20) as smtp:
        if os.getenv("SMTP_STARTTLS", "true").lower() == "true":
            smtp.starttls()
        if os.getenv("SMTP_USER"):
            smtp.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD", ""))
        smtp.send_message(msg)
    return True


def maybe_mail():
    now = local_now()
    if (now.hour, now.minute) < (int(os.getenv("MAIL_HOUR", "6")), int(os.getenv("MAIL_MINUTE", "30"))):
        return
    day = now.strftime("%Y-%m-%d")
    if not (os.getenv("SMTP_HOST") and os.getenv("REPORT_TO") and os.getenv("SMTP_FROM")):
        return
    with Session() as db:
        if marker_exists(db, "mail", day) or not marker_exists(db, "nightly", day):
            return
        servers = db.scalars(select(Server).where(Server.enabled.is_(True)).order_by(Server.name)).all()
        records = []
        for s in servers:
            job = db.scalar(select(Job).where(Job.server_id == s.id, Job.kind == "nightly", Job.context["day"].as_string() == day).order_by(Job.id.desc()))
            if job and job.analysis:
                job.analysis.summary
            records.append((s.name, job))
        send_mail(day, records)
    with Session.begin() as db:
        if not marker_exists(db, "mail", day):
            db.add(DailyMarker(kind="mail", day=day))
    print(f"[email] report {day} inviato", flush=True)


def recover_stuck_processing():
    threshold = utcnow() - timedelta(minutes=10)
    with Session.begin() as db:
        jobs = db.scalars(select(Job).where(Job.state == "processing", Job.updated_at < threshold)).all()
        for job in jobs:
            job.state = "collected" if job.attempts < 4 else "error"
            job.error = "Analisi interrotta, ritentata automaticamente." if job.state == "collected" else "Analisi fallita ripetutamente."


def run_one():
    with Session.begin() as db:
        job = db.scalar(select(Job).where(Job.state == "collected").order_by(Job.id).with_for_update(skip_locked=True))
        if not job:
            return False
        job.state = "processing"
        job.attempts += 1
        job.updated_at = utcnow()
        job_id = job.id
        kind, context, payload = job.kind, job.context or {}, job.payload or {}
    try:
        diag, ai_used = analyze(payload, kind, context)
    except Exception as exc:
        print(f"[ai] job={job_id} fallito: {type(exc).__name__}: {exc}", flush=True)
        diag = rule_based(payload, kind)
        diag["limitations"].append("Analisi OpenAI fallita: diagnosi basata su regole. Verificare i log del worker.")
        ai_used = False
    with Session.begin() as db:
        job = db.get(Job, job_id)
        if not job:
            return True
        db.add(Analysis(job_id=job_id, severity=diag["severity"], summary=diag["summary"], diagnosis=diag, ai_used=ai_used))
        job.state = "done"
        job.error = None
        job.updated_at = utcnow()
        s = db.get(Server, job.server_id)
        if kind not in ("access_check", "app_check"):
            s.last_status = diag["severity"]
            s.last_analysis_at = utcnow()
    print(f"[analysis] job={job_id} {diag['severity']} AI={ai_used}", flush=True)
    return True


def cleanup():
    before = utcnow() - timedelta(days=int(os.getenv("DATA_RETENTION_DAYS", "30")))
    with Session.begin() as db:
        old_ids = db.scalars(select(Job.id).where(Job.created_at < before, Job.state.in_(["done", "error"]))).all()
        if old_ids:
            db.execute(delete(Analysis).where(Analysis.job_id.in_(old_ids)))
            db.execute(delete(Job).where(Job.id.in_(old_ids)))


if __name__ == "__main__":
    init_db()
    print("[worker] avviato", flush=True)
    tick = 0
    while True:
        try:
            enqueue_nightly()
            maybe_mail()
            recover_stuck_processing()
            completed = run_one()
            if tick % 120 == 0:
                cleanup()
            tick += 1
            time.sleep(1 if completed else 10)
        except Exception as exc:
            print("[worker] errore:", repr(exc), flush=True)
            traceback.print_exc()
            time.sleep(15)
