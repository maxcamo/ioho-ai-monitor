#!/usr/bin/env bash
# Sola lettura: aggiorna collector v0.8 e aggregazioni per subnet, senza toccare Magento.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "ERRORE: eseguire come root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ioho-agent
[[ -f /etc/ioho-ai-agent.json && -f "$DST/collector.py" ]] || { echo "Agente non installato"; exit 1; }
[[ -f "$SRC/agent/collector.py" && -f "$SRC/agent/traffic_analysis.py" ]] || { echo "Sorgenti mancanti"; exit 1; }
systemctl cat ioho-ai-agent >/dev/null 2>&1 || { echo "Servizio agente mancante"; exit 1; }
python3 -m py_compile "$SRC/agent/collector.py" "$SRC/agent/traffic_analysis.py"
BACKUP=/root/ioho-agent-pre-v08-$(date +%Y%m%d_%H%M%S)
install -d -m 700 "$BACKUP"
cp -a "$DST/collector.py" "$BACKUP/collector.py"
[[ ! -f "$DST/traffic_analysis.py" ]] || cp -a "$DST/traffic_analysis.py" "$BACKUP/traffic_analysis.py"
install -o root -g root -m 644 "$SRC/agent/collector.py" "$DST/collector.py"
install -o root -g root -m 644 "$SRC/agent/traffic_analysis.py" "$DST/traffic_analysis.py"
python3 -m py_compile "$DST/collector.py" "$DST/traffic_analysis.py"
systemctl restart ioho-ai-agent
systemctl is-active --quiet ioho-ai-agent
echo "IOHO Agent v0.8 attivo; backup $BACKUP. Configurazione e token invariati."
