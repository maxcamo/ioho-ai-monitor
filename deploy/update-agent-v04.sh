#!/usr/bin/env bash
# Aggiorna solo il collector IOHO su un server Magento. Mantiene token, certificato e systemd.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "ERRORE: eseguire come root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="/opt/ioho-agent"
UNIT="ioho-ai-agent"
[[ -f "$SRC/agent/collector.py" && -f "$SRC/agent/traffic_analysis.py" ]] || { echo "ERRORE: repository incompleto"; exit 1; }
[[ -f "$TARGET/collector.py" && -f /etc/ioho-ai-agent.json ]] || { echo "ERRORE: collector precedente non installato"; exit 1; }
systemctl cat "$UNIT" >/dev/null 2>&1 || { echo "ERRORE: servizio systemd non trovato"; exit 1; }
python3 -m py_compile "$SRC/agent/collector.py" "$SRC/agent/traffic_analysis.py"

echo "=== BACKUP COLLECTOR ==="
BACKUP="/root/ioho-ai-agent-pre-v04-$(date +%Y%m%d_%H%M%S)"
install -d -m 700 "$BACKUP"
cp -a "$TARGET/collector.py" "$BACKUP/collector.py"
if [[ -f "$TARGET/traffic_analysis.py" ]]; then cp -a "$TARGET/traffic_analysis.py" "$BACKUP/traffic_analysis.py"; fi
echo "Backup: $BACKUP"

echo "=== AGGIORNAMENTO CODICE, NESSUNA MODIFICA A TOKEN O LOG ==="
install -o root -g root -m 644 "$SRC/agent/traffic_analysis.py" "$TARGET/traffic_analysis.py"
install -o root -g root -m 644 "$SRC/agent/collector.py" "$TARGET/collector.py"
python3 -m py_compile "$TARGET/traffic_analysis.py" "$TARGET/collector.py"

echo "=== RIAVVIO SOLO IOHO AGENT ==="
systemctl restart "$UNIT"
systemctl is-active --quiet "$UNIT"
systemctl --no-pager --full status "$UNIT" | head -16 || true
echo "=== COLLECTOR V0.4 ATTIVO; MAGENTO E NGINX INVARIATI ==="
