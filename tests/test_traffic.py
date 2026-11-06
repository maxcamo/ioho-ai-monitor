"""Regressioni per diagnosi traffico incidente IOHO v0.4."""
from datetime import datetime, timedelta

from agent.collector import collect
from app.analysis import safe_ai_payload


def test_proxy_5_and_10_minute_windows(tmp_path):
    now = datetime.now().astimezone()
    d2 = (now - timedelta(minutes=2)).strftime("%d/%b/%Y:%H:%M:%S %z")
    d7 = (now - timedelta(minutes=7)).strftime("%d/%b/%Y:%H:%M:%S %z")
    d12 = (now - timedelta(minutes=12)).strftime("%d/%b/%Y:%H:%M:%S %z")

    def log(timestamp, ip, uri, status, ua):
        return (f'{ip}, 203.0.113.5 - - [{timestamp}] host="originalbrands.store" '
                f'"GET {uri} HTTP/1.1" {status} 16 "-" "{ua}"\n')

    p = tmp_path / "access.log"
    p.write_text(
        log(d2, "192.0.2.1", "/shopby/?price=12&cat=24&secret=hidden", "410", "Googlebot") * 4 +
        log(d7, "192.0.2.1", "/shopby/?price=19&cat=99&secret=hidden", "403", "Googlebot") * 3 +
        log(d2, "192.0.2.2", "/product", "200", "Mozilla") * 2 +
        log(d12, "192.0.2.3", "/old", "502", "Mozilla")
    )
    data = collect({"access_logs": [str(p)], "app_logs": [], "nginx_error_logs": [], "server_timezone": "Europe/Rome"}, 20)
    five = data["traffic"]["windows"]["5"]
    ten = data["traffic"]["windows"]["10"]
    assert five["total"] == 6
    assert ten["total"] == 9
    assert ten["top_clients"][0]["count"] == 7
    assert ten["top_ip_urls"][0]["count"] == 7
    assert ten["filtered_hits"] == 7
    assert ten["blocked_hits"] == 7
    assert data["coverage"]["access_unparsed_lines"] == 0
    assert "hidden" not in str(data["traffic"])
    assert "192.0.2.1" not in str(safe_ai_payload(data))


def test_access_sample_warning(tmp_path):
    now = datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
    p = tmp_path / "access.log"
    p.write_text((f'192.0.2.5 - - [{now}] "GET /catalog HTTP/1.1" 200 200 "-" "Mozilla"\n') * 120)
    data = collect({
        "access_logs": [str(p)], "app_logs": [], "nginx_error_logs": [],
        "server_timezone": "Europe/Rome",
        "max_bytes_per_file": 2048, "incident_access_bytes": 2048,
        "max_total_bytes": 4096, "incident_total_bytes": 4096
    }, 20)
    assert data["coverage"]["access_truncated"]
    assert data["traffic"]["windows"]["10"]["sampling_truncated"]
