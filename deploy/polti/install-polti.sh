#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "ERRORE: installazione interrotta alla riga %s (exit %s)\n" "$LINENO" "$?" >&2' ERR
[[ $EUID -eq 0 ]] || { echo 'ERRORE: eseguire come root su Polti'; exit 1; }
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG=/etc/ioho-ai-agent.json
CERT=/etc/ioho-ai-console.crt
AGENT=/opt/ioho-agent/collector.py
SERVICE=/etc/systemd/system/ioho-ai-agent.service
USER=polticom
for f in "$SRC/config.json" "$SRC/collector.py"; do
    [[ -s "$f" ]] || { echo "ERRORE: manca $f"; exit 1; }
done
id "$USER" >/dev/null || { echo "ERRORE: utente $USER non presente"; exit 1; }
GROUP=$(id -gn "$USER")
python3 -m py_compile "$SRC/collector.py"
python3 - "$SRC/config.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x.get('agent_token') and len(x['agent_token'])>=32
assert x.get('console_url') == 'https://2.31.176.212'
print('OK: configurazione agente valida (token nascosto)')
PY
command -v curl >/dev/null || { echo 'ERRORE: curl non installato'; exit 1; }
TLS_LINE=''
echo '=== VERIFICA HTTPS CONSOLE ==='
if curl -fsS --connect-timeout 6 --max-time 12 'https://2.31.176.212/health' >/dev/null 2>&1; then
    echo 'OK: certificato pubblico verificato'
elif [[ -s "$SRC/console.crt" ]] && curl --cacert "$SRC/console.crt" -fsS --connect-timeout 6 --max-time 12 'https://2.31.176.212/health' >/dev/null; then
    install -m 644 "$SRC/console.crt" "$CERT"
    TLS_LINE="Environment=SSL_CERT_FILE=$CERT"
    echo 'OK: certificato privato verificato'
else
    echo 'ERRORE: certificato HTTPS non verificabile. Installazione fermata.'
    exit 1
fi
BASE=/var/www/www.polti.com
[[ -d "$BASE/htdocs/var/log" ]] || { echo "ERRORE: Magento non trovato: $BASE/htdocs/var/log"; exit 1; }
echo '=== VERIFICA LOG DI POLTI ==='
find "$BASE/logs" -maxdepth 1 -type f \( -name 'access.log' -o -name 'reverse_access.log' -o -name 'error.log' \) -printf '%p %s byte\n' 2>/dev/null || true
[[ -r "$BASE/htdocs/var/log/system.log" || -r "$BASE/htdocs/var/log/exception.log" ]] || { echo 'ERRORE: non riesco a leggere i log Magento principali'; exit 1; }
for f in "$BASE/logs/access.log" "$BASE/logs/reverse_access.log" "$BASE/htdocs/var/log/system.log" "$BASE/htdocs/var/log/exception.log"; do
    if [[ -e "$f" ]] && ! runuser -u "$USER" -- test -r "$f"; then
        echo "ATTENZIONE: $USER non riesce a leggere $f"
    fi
done
[[ ! -e "$CONFIG" ]] || { echo "ERRORE: $CONFIG esiste già. Non sovrascrivo un collector esistente."; exit 1; }
[[ ! -e "$SERVICE" ]] || { echo "ERRORE: $SERVICE esiste già. Non sovrascrivo il servizio esistente."; exit 1; }
echo '=== INSTALLAZIONE SENZA MODIFICARE MAGENTO ==='
install -d -m 755 /opt/ioho-agent
install -m 644 "$SRC/collector.py" "$AGENT"
install -o root -g "$GROUP" -m 640 "$SRC/config.json" "$CONFIG"
cat > "$SERVICE" <<EOF
[Unit]
Description=IOHO AI Monitor - Polti
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$USER
Group=$GROUP
$TLS_LINE
ExecStart=/usr/bin/python3 $AGENT $CONFIG
Restart=always
RestartSec=20
CPUQuota=35%
MemoryMax=256M
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$SERVICE"
echo '=== TEST LOCALE (SOLO LETTURA) ==='
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
runuser -u "$USER" -- env ${TLS_LINE#Environment=} python3 "$AGENT" "$CONFIG" --once > "$TMP"
python3 - "$TMP" <<'PY'
import json,sys
from pathlib import Path
x=json.loads(Path(sys.argv[1]).read_text())
print('Richieste HTTP riconosciute:', x.get('access',{}).get('total'))
print('Log esaminati:', x.get('coverage',{}).get('matched'))
print('Analisi parziale:', x.get('coverage',{}).get('truncated'))
print('Righe access non riconosciute:',x.get('coverage',{}).get('access_unparsed_lines'))
print('Problemi copertura:', x.get('coverage',{}).get('errors',[]))
PY
rm -f "$TMP"
trap - EXIT
echo '=== ATTIVAZIONE COLLECTOR ==='
systemctl daemon-reload
systemctl enable --now ioho-ai-agent
systemctl is-active --quiet ioho-ai-agent
systemctl status --no-pager --full ioho-ai-agent | head -16 || true
echo '=== INSTALLAZIONE POLTI COMPLETATA ==='
echo 'Le richieste di audit arriveranno tramite HTTPS in uscita; non serve SSH da Polti ad ai-control.'
