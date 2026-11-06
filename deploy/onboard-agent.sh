#!/usr/bin/env bash
# Install only IOHO AI Monitor collector. Console remains on ai-control.
set -Eeuo pipefail
[[ $EUID -eq 0 && $# -eq 2 ]] || { echo "Uso: bash deploy/onboard-agent.sh /var/www/site utente"; exit 1; }
BASE="$1"
USR="$2"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CENTRAL="2.31.176.212"
CFG="/etc/ioho-ai-agent.json"
CRT="/etc/ioho-ai-console.crt"
UNIT="/etc/systemd/system/ioho-ai-agent.service"
[[ "$BASE" == /* && -d "$BASE/htdocs/var/log" && -d "$BASE/logs" ]] || { echo "Root Magento/log non valida"; exit 1; }
id "$USR" >/dev/null 2>&1 || { echo "Utente inesistente"; exit 1; }
[[ ! -e "$CFG" && ! -e "$UNIT" ]] || { echo "Collector gia' configurato: non sovrascrivo"; exit 1; }
GRP="$(id -gn "$USR")"
python3 -m py_compile "$ROOT/agent/collector.py"
for f in "$BASE/logs/access.log.1" "$BASE/htdocs/var/log/system.log" "$BASE/htdocs/var/log/exception.log"; do
  if [[ -s "$f" ]]; then
    runuser -u "$USR" -- test -r "$f" || { echo "Accesso negato a $USR: $f"; exit 1; }
  fi
done
if [[ -s "$BASE/logs/access.log.1" ]]; then
  MAGIC="$(od -An -tx1 -N2 "$BASE/logs/access.log.1" | tr -d ' \n')"
  [[ "$MAGIC" != "1f8b" ]] || { echo "access.log.1 e' gzip senza suffisso .gz: adattare parser"; exit 1; }
fi
TMP="$(mktemp -d /tmp/ioho-onboard.XXXXXXXX)"
trap 'rm -rf "$TMP"; unset IOHO_AGENT_TOKEN || true' EXIT
echo "=== TLS: copia dal terminale ai-control la fingerprint SHA256 (64 caratteri) ==="
read -r -p "SHA256: " EXPECTED
EXPECTED="$(echo "$EXPECTED" | tr '[:upper:]' '[:lower:]')"
[[ "$EXPECTED" =~ ^[0-9a-f]{64}$ ]] || { echo "Fingerprint non valida"; exit 1; }
timeout 15 openssl s_client -connect "$CENTRAL:443" -servername "$CENTRAL" -showcerts </dev/null 2>/dev/null | openssl x509 -out "$TMP/console.crt"
ACTUAL="$(openssl x509 -in "$TMP/console.crt" -outform DER | sha256sum | awk '{print $1}')"
[[ "$ACTUAL" == "$EXPECTED" ]] || { echo "Fingerprint TLS diversa da ai-control: STOP"; exit 1; }
curl -fsS --cacert "$TMP/console.crt" --connect-timeout 6 --max-time 12 "https://$CENTRAL/health" >/dev/null || { echo "Certificato verificato ma HTTPS non valido"; exit 1; }
openssl x509 -in "$TMP/console.crt" -noout -enddate
echo "=== TOKEN: copia il valore agent_token generato su ai-control ==="
read -r -s -p "Agent token (non visibile): " IOHO_AGENT_TOKEN
echo
[[ "$IOHO_AGENT_TOKEN" =~ ^[A-Za-z0-9_-]{32,}$ ]] || { echo "Token non valido"; exit 1; }
export IOHO_AGENT_TOKEN
export IOHO_BASE="$BASE"
python3 - "$TMP/config.json" <<'PY'
import json, os, sys
b=os.environ['IOHO_BASE']
out={
 'console_url':'https://2.31.176.212',
 'agent_token':os.environ['IOHO_AGENT_TOKEN'],
 'server_timezone':'Europe/Rome',
 'poll_seconds':20,
 'max_bytes_per_file':4000000,
 'max_total_bytes':25000000,
 'max_files':25,
 'access_logs':[b+'/logs/access.log',b+'/logs/access.log.1'],
 'nginx_error_logs':[b+'/logs/error.log',b+'/logs/error.log.1',b+'/logs/reverse_error.log',b+'/logs/reverse_error.log.1','/var/log/nginx/nginx.log'],
 'app_logs':[b+'/htdocs/var/log/system.log',b+'/htdocs/var/log/exception.log',b+'/htdocs/var/log/*.log',b+'/htdocs/var/log/wp/error.log']
}
with open(sys.argv[1],'w') as f: json.dump(out,f,indent=2)
PY
unset IOHO_AGENT_TOKEN
install -d -m 755 /opt/ioho-agent
install -o root -g root -m 644 "$ROOT/agent/collector.py" /opt/ioho-agent/collector.py
install -o root -g "$GRP" -m 640 "$TMP/config.json" "$CFG"
install -o root -g root -m 644 "$TMP/console.crt" "$CRT"
cat > "$UNIT" <<EOF
[Unit]
Description=IOHO AI Monitor - Magento collector
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$USR
Group=$GRP
Environment=SSL_CERT_FILE=$CRT
ExecStart=/usr/bin/python3 /opt/ioho-agent/collector.py $CFG
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
chmod 644 "$UNIT"
echo "=== TEST LOCALE (non inviato alla console) ==="
runuser -u "$USR" -- env SSL_CERT_FILE="$CRT" python3 /opt/ioho-agent/collector.py "$CFG" --once > "$TMP/test.json"
python3 - "$TMP/test.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
c=d['coverage']
print('Richieste HTTP riconosciute:',d['access']['total'])
print('File esaminati:',c['matched'])
print('Righe non riconosciute:',c['access_unparsed_lines'])
print('Campionamento:',c['truncated'])
print('Errori di copertura:',c['errors'])
PY
systemctl daemon-reload
systemctl enable --now ioho-ai-agent
systemctl is-active --quiet ioho-ai-agent
echo "=== COLLECTOR ATTIVO - console centrale invariata ==="
systemctl status --no-pager --full ioho-ai-agent | head -12 || true
