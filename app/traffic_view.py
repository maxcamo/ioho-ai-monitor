"""View model del rapporto HTTP; solo aggregazioni già raccolte, senza rilettura log."""


def _number(value):
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _percent(part, total):
    return round(100 * part / total, 1) if total else 0.0


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
                            "blocked_percent": _percent(_number(ip.get("blocked")),count),
                            "filtered_percent": _percent(_number(ip.get("filtered")),count)})
        clients.sort(key=lambda x: -x["count"])
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
