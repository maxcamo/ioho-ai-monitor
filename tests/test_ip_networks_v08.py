"""v0.8: subnet /24 /64, dati completi e storico parziale, link IPinfo validati."""
from datetime import datetime, timezone
from agent.traffic_analysis import TrafficWindow, network_for_ip
from app.traffic_view import make_traffic_report


def test_ipv4_network_aggregates_all_requests_not_just_top_15():
    stamp = datetime.now(timezone.utc)
    window = TrafficWindow(10, stamp)
    for suffix in range(1, 21):
        for _ in range(suffix):
            window.add(stamp, f"66.249.66.{suffix}", "/shopby/?cat", "410", True, True)
    snapshot = window.snapshot(truncated=False)
    subnet = snapshot["top_networks"][0]
    assert subnet["network"] == "66.249.66.0/24"
    assert subnet["count"] == sum(range(1, 21))
    assert subnet["unique_ips_observed"] == 20
    assert subnet["filtered"] == subnet["count"]
    assert subnet["blocked"] == subnet["count"]
    assert len(snapshot["top_clients"]) == 15
    assert snapshot["network_counts_limited"] is False
    report = make_traffic_report({"traffic": {"windows": {"10": snapshot}}, "coverage": {}})
    net = report["windows"]["10"]["networks"][0]
    assert net["count"] == 210
    assert net["unique_ips"] == 20
    assert net["lookup_url"] == "https://ipinfo.io/ips/66.249.66.0/24"
    assert report["windows"]["10"]["networks_limited"] is False


def test_ipv6_and_invalid_clients():
    assert network_for_ip("2001:4860:4860::8888") == "2001:4860:4860::/64"
    assert network_for_ip("not-an-ip") is None
    stamp = datetime.now(timezone.utc)
    window = TrafficWindow(5, stamp)
    window.add(stamp, "2001:4860:4860::8888", "/", "200", False, False)
    window.add(stamp, "not-an-ip", "/", "200", False, False)
    data = window.snapshot(False)
    assert data["top_networks"][0]["network"] == "2001:4860:4860::/64"
    assert data["top_networks"][0]["count"] == 1
    assert data["total"] == 2


def test_legacy_network_is_explicitly_partial_and_private_ips_not_linked():
    old = {
        "total": 1000, "top_clients": [
            {"ip": "66.249.66.96", "count": 132, "filtered": 105, "blocked": 13},
            {"ip": "66.249.66.97", "count": 115, "filtered": 83, "blocked": 8},
            {"ip": "66.249.66.100", "count": 111, "filtered": 78, "blocked": 6},
            {"ip": "10.0.0.2", "count": 10, "filtered": 0, "blocked": 0},
        ]
    }
    report = make_traffic_report({"traffic": {"windows": {"10": old}}, "coverage": {}})
    t = report["windows"]["10"]
    assert t["networks_limited"] is True
    assert t["networks"][0]["network"] == "66.249.66.0/24"
    assert t["networks"][0]["count"] == 358
    assert t["networks"][0]["share"] == 35.8
    assert t["clients"][0]["lookup_url"] == "https://ipinfo.io/66.249.66.96"
    private = next(client for client in t["clients"] if client["ip"] == "10.0.0.2")
    assert private["lookup_url"] is None
    private_network = next(net for net in t["networks"] if net["network"] == "10.0.0.0/24")
    assert private_network["lookup_url"] is None
