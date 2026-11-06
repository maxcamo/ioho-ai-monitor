"""Provisioning CLI: docker compose exec api python manage.py add-server ..."""
import argparse
import json
import secrets
from datetime import timedelta
from sqlalchemy import select
from app.db import Session, Server, Job, init_db, token_digest, utcnow


def main():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)
    add = subs.add_parser("add-server", help="Registra un nuovo server e genera il token del collector")
    add.add_argument("name")
    add.add_argument("zabbix_host", help="Nome host TECNICO Zabbix, non il nome visibile")
    run = subs.add_parser("run-audit", help="Accoda un audit manuale")
    run.add_argument("name")
    traffic = subs.add_parser("run-traffic", help="Fotografia immediata access.log: ultimi 5/10 minuti, senza simulare CPU alta")
    traffic.add_argument("name")
    subs.add_parser("list-servers")
    args = parser.parse_args()
    init_db()
    with Session.begin() as db:
        if args.command == "add-server":
            if db.scalar(select(Server).where((Server.name == args.name) | (Server.zabbix_host == args.zabbix_host))):
                parser.error("Server già registrato con nome o host Zabbix uguale")
            token = secrets.token_urlsafe(40)
            db.add(Server(name=args.name, zabbix_host=args.zabbix_host, token_hash=token_digest(token)))
            print(json.dumps({"server": args.name, "zabbix_host": args.zabbix_host, "agent_token": token}, indent=2))
            print("ATTENZIONE: salva ora il token in modo sicuro, non sarà mostrato di nuovo.")
        elif args.command in ("run-audit", "run-traffic"):
            server = db.scalar(select(Server).where(Server.name == args.name))
            if not server:
                parser.error("Server non registrato")
            if args.command == "run-traffic":
                recent = db.scalar(select(Job).where(
                    Job.server_id == server.id,
                    Job.kind == "traffic_check",
                    Job.created_at >= utcnow() - timedelta(minutes=3),
                    Job.state.in_(["queued", "leased", "collected", "processing", "done"])
                ).order_by(Job.id.desc()))
                if recent:
                    print(f"Analisi traffico recente gia presente: job #{recent.id} ({recent.state})")
                    return
                job = Job(server_id=server.id, kind="traffic_check",
                          incident_name="Analisi traffico HTTP 5/10 minuti",
                          context={"manual": True}, state="queued")
            else:
                job = Job(server_id=server.id, kind="nightly",
                          incident_name="Audit manuale", context={"manual": True}, state="queued")
            db.add(job)
            db.flush()
            print(f"Analisi accodata: {server.name} | job #{job.id} | tipo {job.kind}")
        elif args.command == "list-servers":
            servers = db.scalars(select(Server).order_by(Server.name)).all()
            for s in servers:
                print(f"{s.id:4d}  {s.name:30s}  Zabbix: {s.zabbix_host:30s}  {s.last_status}")


if __name__ == "__main__":
    main()
