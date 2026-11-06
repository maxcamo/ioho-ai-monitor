// Zabbix 7.x > Alerts > Media types > Webhook > Script
try {
    var p = JSON.parse(value),
        req = new HttpRequest(),
        resp;
    req.addHeader('Content-Type: application/json');
    req.addHeader('X-Webhook-Token: ' + p.token);
    resp = req.post(p.url, JSON.stringify({
        event_id: p.event_id,
        host: p.host,
        name: p.name,
        status: p.status,
        severity: p.severity,
        clock: p.clock
    }));
    if (req.getStatus() < 200 || req.getStatus() >= 300) {
        throw 'HTTP ' + req.getStatus() + ' ' + resp;
    }
    return 'OK ' + resp;
} catch (error) {
    Zabbix.log(3, '[IOHO AI Monitor] ' + error);
    throw 'IOHO AI Monitor: ' + error;
}
