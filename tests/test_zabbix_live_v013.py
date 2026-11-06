"""v0.13: Widget live Zabbix CPU/load/processi e refresh automatico."""
import os
import secrets
import time
from datetime import datetime, timezone

os.environ.setdefault("DATABASE_URL", f"sqlite:////tmp/ioho-v013-tests-{os.getpid()}.db")
os.environ.setdefault("DASHBOARD_USER", "admin")
os.environ.setdefault("DASHBOARD_PASSWORD", "test-dashboard-pass")
os.environ.setdefault("ZABBIX_WEBHOOK_TOKEN", "test-webhook-token")
os.environ.setdefault("OPENAI_API_KEY", "")

from fastapi.testclient import TestClient
from app.db import init_db, Session, Server, token_digest, utcnow
from app.zabbix_live import get_live_metrics, _choose_cpu, _item_last
from app.main import app
import app.main as main


def setup_module(_):
    init_db()


def _item(hostid, key, value, stamp, name=None):
    return {"itemid": secrets.token_hex(3), "hostid": str(hostid), "key_": key,
            "name": name or key, "lastvalue": str(value), "lastclock": str(stamp),
            "status": "0", "state": "0", "value_type": "0"}


def test_batch_metrics_last_values_and_colored_levels(monkeypatch):
    monkeypatch.setenv("ZABBIX_API_URL", "https://zabbix.example.invalid/zabbix/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_API_TOKEN", "fake-readonly")
    monkeypatch.delenv("ZABBIX_CPU_ITEM_KEY", raising=False)
    now = int(time.time())
    calls = []
    data = {
        "server-yellow": [
            _item("1", "system.cpu.util", 63.97, now - 35, "CPU utilization"),
            _item("1", "system.cpu.load[all,avg1]", 3.26, now - 30),
            _item("1", "system.cpu.load[all,avg5]", 2.95, now - 30),
            _item("1", "system.cpu.load[all,avg15]", 2.70, now - 30),
            _item("1", "proc.num[]", 131, now - 30),
        ],
        "server-red": [
            _item("2", "system.cpu.util", 91.1, now - 20, "CPU utilization"),
            _item("2", "system.cpu.load[all,avg1]", 6.00, now - 20),
            _item("2", "proc.num[]", 300, now - 20),
        ],
        "server-green": [
            _item("3", "system.cpu.util", 34.3, now - 10, "CPU utilization"),
            _item("3", "proc.num[]", 210, now - 10),
        ]
    }
    def fake_rpc(url, token, method, params):
        assert token == "fake-readonly"
        calls.append(method)
        if method == "host.get":
            assert set(params["filter"]["host"]) == set(data)
            return [{"host": name, "hostid": str(index+1)}
                    for index, name in enumerate(data)]
        if method == "item.get":
            items = [row for values in data.values() for row in values]
            search = params["search"]["key_"]
            return [row for row in items if search in row["key_"]]
        raise AssertionError(method)
    result = get_live_metrics(data.keys(), rpc=fake_rpc)
    assert calls == ["host.get", "item.get", "item.get"]
    assert result["server-yellow"]["cpu_pct"] == 64.0
    assert result["server-yellow"]["level"] == "warning"
    assert result["server-yellow"]["load1"] == 3.26
    assert result["server-yellow"]["load5"] == 2.95
    assert result["server-yellow"]["load15"] == 2.7
    assert result["server-yellow"]["processes"] == 131
    assert result["server-red"]["level"] == "critical"
    assert result["server-green"]["level"] == "ok"


def test_stale_data_and_invalid_cpu_never_appear_live(monkeypatch):
    monkeypatch.setenv("ZABBIX_API_URL", "https://zabbix.example.invalid/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_API_TOKEN", "fake-token")
    now = int(time.time())
    def rpc(_url, _token, method, _params):
        if method == "host.get":
            return [{"host": "host1", "hostid": "99"}]
        if method == "item.get":
            if _params["search"]["key_"] == "proc.num":
                return [_item("99", "proc.num[]", "NaN", now - 15)]
            return [_item("99", "system.cpu.util", 87.3, now - 400, "CPU utilization"),
                    _item("99", "system.cpu.load[all,avg1]", 1.9, now - 400)]
        raise AssertionError(method)
    row = get_live_metrics(["host1"], rpc=rpc)["host1"]
    assert row["cpu_pct"] is None and row["level"] == "unknown"
    assert row["load1"] is None and row["processes"] is None


def test_cpu_idle_is_converted_and_user_cpu_ignored():
    now = int(time.time())
    items = [_item("1", "system.cpu.util", 90, now, "CPU user time"),
             _item("1", "system.cpu.util[,idle]", 21, now, "CPU idle time")]
    assert _choose_cpu(items, now)[0] == 79.0


def test_home_refresh_and_warning_row_highlight(monkeypatch):
    with Session.begin() as db:
        host = Server(name="widget-" + secrets.token_hex(5),
                      zabbix_host="z-widget-" + secrets.token_hex(6),
                      token_hash=token_digest(secrets.token_urlsafe(40)),
                      enabled=True, last_seen=utcnow())
        db.add(host)
        db.flush()
        zid = host.zabbix_host

    def fake_metrics(names):
        return {zid: {"cpu_pct": 63.97, "cpu_at": "15:20:00 UTC",
                      "level": "warning", "load1": 3.26,
                      "load5": 2.95, "load15": 2.7,
                      "processes": 131}}

    monkeypatch.setattr(main, "get_live_metrics", fake_metrics)
    response = TestClient(app).get("/", auth=("admin", "test-dashboard-pass"))
    assert response.status_code == 200, response.text[:1200]
    html = response.text
    overview = html.split("Stato per tipologia", 1)[1].split("Attività recente", 1)[0]
    assert '<meta http-equiv="refresh" content="30"/>' in html
    assert "Pagina aggiornata ogni 30 s" in overview
    assert "cpu-row-warning" in overview
    assert "63,9%" in overview or "64,0%" in overview
    assert "3.26" in overview and "2.95" in overview
    assert "Processi" in overview
    assert "131" in overview
    assert 'class="cpu-segments"' in overview
    assert "CPU Zabbix — nessun dato" not in overview
