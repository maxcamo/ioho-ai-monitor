#!/usr/bin/env bash
# Aggiorna solo l'agente senza toccare token, systemd o Magento.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Eseguire come root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ioho-agent
[[ -f "$DST/collector.py" && -f "$SRC/agent/traffic_analysis.py" && -f /etc/ioho-ai-agent.json ]] || { echo "Agente mancante"; exit 1; }
python3 -m py_compile "$SRC/agent/collector.py" "$SRC/agent/traffic_analysis.py"
BACKUP=/root/ioho-agent-pre-v05-$(date +%Y%m%d_%H%M%S)
install -d -m 700 "$BACKUP"
cp -a "$DST/collector.py" "$BACKUP/collector.py"
[[ ! -f "$DST/traffic_analysis.py" ]] || cp -a "$DST/traffic_analysis.py" "$BACKUP/traffic_analysis.py"
install -o root -g root -m 644 "$SRC/agent/collector.py" "$DST/collector.py"
install -o root -g root -m 644 "$SRC/agent/traffic_analysis.py" "$DST/traffic_analysis.py"
systemctl restart ioho-ai-agent
systemctl is-active --quiet ioho-ai-agent
echo "Agente v0.5 attivo; backup $BACKUP"
