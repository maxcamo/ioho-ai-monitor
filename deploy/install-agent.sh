#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${EUID}" -ne 0 ]]; then echo 'Eseguire con sudo'; exit 1; fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ ! -f /etc/ioho-ai-agent.json ]]; then
  echo 'ERRORE: creare prima /etc/ioho-ai-agent.json con token e percorsi dei log.'
  exit 1
fi
id ioho-monitor >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ioho-monitor
install -d -m 0755 /opt/ioho-agent
install -o root -g root -m 0644 "$ROOT/agent/collector.py" /opt/ioho-agent/collector.py
install -o root -g root -m 0644 "$ROOT/agent/traffic_analysis.py" /opt/ioho-agent/traffic_analysis.py
chown ioho-monitor:ioho-monitor /etc/ioho-ai-agent.json
chmod 0600 /etc/ioho-ai-agent.json
install -o root -g root -m 0644 "$ROOT/agent/ioho-ai-agent.service" /etc/systemd/system/ioho-ai-agent.service
systemctl daemon-reload
systemctl enable --now ioho-ai-agent
systemctl status --no-pager ioho-ai-agent || true
echo 'Installato. Verificare i permessi di lettura dei log e journalctl -u ioho-ai-agent.'
