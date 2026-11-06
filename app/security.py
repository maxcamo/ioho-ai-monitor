import os
import secrets
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import select
from app.db import Server, Session, token_digest

basic = HTTPBasic()


def dashboard_auth(credentials: HTTPBasicCredentials = Depends(basic)):
    user = os.getenv("DASHBOARD_USER", "")
    password = os.getenv("DASHBOARD_PASSWORD", "")
    if not user or not password or not (secrets.compare_digest(credentials.username, user) and secrets.compare_digest(credentials.password, password)):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic realm=IOHO-Monitor"})
    return credentials.username


def webhook_auth(x_webhook_token: str = Header(default="")):
    expected = os.getenv("ZABBIX_WEBHOOK_TOKEN", "")
    if not expected or not secrets.compare_digest(x_webhook_token, expected):
        raise HTTPException(status_code=401, detail="Invalid webhook token")


def agent_auth(x_agent_token: str = Header(default="")) -> Server:
    if len(x_agent_token) < 32:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    with Session() as db:
        server = db.scalar(select(Server).where(Server.token_hash == token_digest(x_agent_token), Server.enabled.is_(True)))
        if server is None:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        return server
