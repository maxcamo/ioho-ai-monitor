"""View model del rapporto HTTP; aggregati locali, senza richieste esterne."""
from ipaddress import ip_address, ip_network


def _number(value):
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _percent(part, total):
    return round(100 * part / total, 1) if total else 0.0


def _network_from_client(value):
    try:
        ip = ip_address(str(value))
        return str(ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False))
    except (ValueError, TypeError):
        return None


def _ipinfo_ip(value):
    """Non creare link verso siti esterni per IP locali, non validi o non pubblici."""
    try:
        ip = ip_address(str(value))
        return f"https://ipinfo.io/{ip.compressed}" if ip.is_global else None
    except (ValueError, TypeError):
        return None


def _ipinfo_network(value):
    try:
        network = ip_network(str(value), strict=False)
        prefix = 24 if network.version == 4 else 64
        if network.prefixlen != prefix:
            return None
        return f"https://ipinfo.io/ips/{network}" if network.is_global else None
    except (ValueError, TypeError):
        return None


def make_traffic_report(payload):
    traffic = payload.get("traffic") or {}
    raw_windows = traffic.get("windows") or {}
    coverage = payload.get("coverage") or {}
    result = {"captured_at": traffic.get("captured_at"), "windows": {},
              "limited": bool(coverage.get("access_truncated")),
              "access_missing": bool(coverage.get("no_access_log")),
              "unparsed": _number(coverage.get("access_unparsed_lines")),
              "read_errors": coverage.get("errors") or []}
    for period in ("10", "5"):
        w = raw_windows.get(period)
        if not isinstance(w, dict):
            continue
        total = _number(w.get("total"))
        filters = _number(w.get("filtered_hits"))
        blocked = _number(w.get("blocked_hits"))
        errors = _number(w.get("http_5xx"))
        clients = []
        for ip in (w.get("top_clients") or [])[:15]:
            count = _number(ip.get("count"))
            clients.append({**ip, "count": count, "share": _percent(count,total),
                            "network": _network_from_client(ip.get("ip")),
                            "lookup_url": _ipinfo_ip(ip.get("ip")),
                            "blocked_percent": _percent(_number(ip.get("blocked")),count),
                            "filtered_percent": _percent(_number(ip.get("filtered")),count)})
        clients.sort(key=lambda x: -x["count"])
        # Nuovi audit: rete aggregata sul traffico completo letto dall'agente.
        # Audit storici: solo i 15 IP salvati, quindi somme MINIME e non globali.
        network_rows = []
        raw_networks = w.get("top_networks")
        network_from_collector = isinstance(raw_networks, list)
        if network_from_collector:
            for net in raw_networks[:20]:
                if not isinstance(net, dict):
                    continue
                cidr = net.get("network")
                lookup_url = _ipinfo_network(cidr)
                if not isinstance(cidr, str):
                    continue
                try:
                    parsed = ip_network(cidr, strict=False)
                except (ValueError, TypeError):
                    continue
                if parsed.prefixlen != (24 if parsed.version == 4 else 64):
                    continue
                count = _number(net.get("count"))
                network_rows.append({
                    "network": str(parsed), "count": count,
                    "share": _percent(count, total),
                    "unique_ips": _number(net.get("unique_ips_observed")),
                    "filtered": _number(net.get("filtered")),
                    "blocked": _number(net.get("blocked")),
                    "lookup_url": lookup_url,
                })
        else:
            grouped = {}
            for client in clients:
                cidr = client.get("network")
                if not cidr:
                    continue
                info = grouped.setdefault(cidr, {"network": cidr, "count": 0,
                    "unique_ips": 0, "filtered": 0, "blocked": 0,
                    "lookup_url": _ipinfo_network(cidr)})
                info["count"] += client["count"]
                info["unique_ips"] += 1
                info["filtered"] += _number(client.get("filtered"))
                info["blocked"] += _number(client.get("blocked"))
            network_rows = [{**item, "share": _percent(item["count"], total)}
                            for item in grouped.values()]
        network_rows.sort(key=lambda row: (-row["count"], row["network"]))
        networks_limited = (not network_from_collector) or bool(w.get("network_counts_limited"))
        filtered_urls = []
        for item in (w.get("top_filtered_urls") or [])[:15]:
            if isinstance(item,(list,tuple)) and len(item)>=2:
                filtered_urls.append({"url":item[0],"count":_number(item[1]),
                                      "share":_percent(_number(item[1]),total)})
        plain_urls = []
        all_urls=[]
        for u in w.get("top_urls") or []:
            count=_number(u.get("count"))
            filtered=min(count,_number(u.get("filtered")))
            plain=count-filtered
            all_urls.append({**u,"count":count,"plain":plain,"filtered":filtered,
                             "share":_percent(count,total)})
            if plain:
                plain_urls.append({"url":u.get("url", ""),"count":plain,
                                   "share":_percent(plain,total)})
        plain_urls.sort(key=lambda x:-x["count"])
        statuses=sorted(({"code":str(code),"count":_number(count),
                         "share":_percent(_number(count),total)}
                        for code,count in (w.get("statuses") or {}).items()),
                        key=lambda row:(-row["count"],row["code"]))
        per_minute=sorted(({"minute":row[0],"count":_number(row[1])}
                          for row in (w.get("per_minute") or []) if isinstance(row,(list,tuple)) and len(row)>=2),
                         key=lambda r:r["minute"])
        peak=max([r["count"] for r in per_minute] or [1])
        for row in per_minute:
            row["width"] = max(2, round(100 * row["count"] / peak)) if row["count"] else 0
        top_client_count=clients[0]["count"] if clients else 0
        findings=[]
        if network_rows and network_rows[0]["count"] >= 50 and network_rows[0]["share"] >= 25:
            top_net = network_rows[0]
            qualifier = "almeno " if not network_from_collector else ""
            findings.append(f"La rete {top_net['network']} rappresenta {qualifier}{top_net['count']} richieste "
                            f"({top_net['share']}% del campione): la rete condivisa NON implica un singolo bot.")
        if total == 0:
            findings.append("Nessuna richiesta riconosciuta nel campione di questa finestra: controllare log, rotazione e timestamp.")
        else:
            if errors:
                findings.append(f"{errors} risposte HTTP 5xx ({_percent(errors,total)}%): verificare quali pagine e servizi generano errori; i 5xx non dimostrano un attacco bot.")
            if top_client_count >= 50 and top_client_count / total >= .25:
                findings.append(f"L'IP più attivo genera {top_client_count} richieste ({_percent(top_client_count,total)}% del campione): controllare le sue URL e la provenienza reale.")
            if filters / total >= .3:
                findings.append(f"Le richieste con filtri riconosciuti sono {filters} ({_percent(filters,total)}%): esaminare categorie e parametri più ricorrenti.")
            if _number(w.get("peak_per_minute")) >= 120:
                findings.append(f"Picco osservato di {_number(w.get('peak_per_minute'))} richieste/minuto: confrontare l'orario con CPU e PHP-FPM su Zabbix.")
            if blocked:
                findings.append(f"{blocked} risposte 403/410/429/444; alcune possono essere respinte prima di Magento. Verificare le regole Nginx.")
            if not findings:
                findings.append("Nessuna concentrazione marcata secondo le soglie indicative. Questo non esclude bot distribuiti o richieste costose.")
        result["windows"][period] = {
            "minutes": period,"total":total,"rpm":w.get("rpm",0),"peak":_number(w.get("peak_per_minute")),
            "unique_ips": _number(w.get("unique_ips_observed")),"filters":filters,
            "filters_pct":_percent(filters,total),"plain":max(0,total-filters),
            "plain_pct":_percent(max(0,total-filters),total),"blocked":blocked,
            "blocked_pct":_percent(blocked,total),"errors":errors,"errors_pct":_percent(errors,total),
            "bot_ua":_number(w.get("bot_ua_hits")),"clients":clients,
            "networks":network_rows[:20], "networks_limited": networks_limited,
            "networks_from_collector": network_from_collector,
            "filtered_urls":filtered_urls,"plain_urls":plain_urls[:15],
            "plain_url_limited":True,"all_urls":all_urls,
            "top_ip_urls":(w.get("top_ip_urls") or [])[:15],
            "statuses":statuses,"timeline":per_minute,
            "observed_from":w.get("observed_from"),"observed_to":w.get("observed_to"),
            "capped":bool(w.get("aggregation_capped")),
            "partial":bool(w.get("sampling_truncated") or coverage.get("access_truncated")),
            "findings":findings,
        }
    return result
