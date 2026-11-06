#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'ERRORE: eseguire come root su ai-control'; exit 1; }
CENTRAL_ROOT=/opt/ioho-ai-monitor
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME=polti.com
BUNDLE=/root/ioho-polti-onboarding.tar.gz
[[ -f "$CENTRAL_ROOT/agent/collector.py" ]] || { echo 'ERRORE: collector mancante su ai-control'; exit 1; }
[[ -f "$SCRIPT_DIR/install-polti.sh" ]] || { echo 'ERRORE: script installazione mancante'; exit 1; }
grep -q 'count_15m' "$CENTRAL_ROOT/agent/collector.py" || { echo 'ERRORE: il collector centrale non sembra aggiornato alla v0.3'; exit 1; }
[[ ! -e "$BUNDLE" ]] || { echo "ERRORE: $BUNDLE esiste già. Non lo sovrascrivo (potrebbe contenere un token valido)."; exit 1; }
ZHOST=${1:-}
if [[ -z "$ZHOST" ]]; then
    read -r -p 'Inserisci Hostname TECNICO Zabbix di Polti (esatto): ' ZHOST
fi
[[ -n "$ZHOST" ]] || { echo 'ERRORE: Hostname Zabbix vuoto'; exit 1; }
[[ "$ZHOST" =~ ^[A-Za-z0-9_.:-]+$ ]] || { echo 'ERRORE: caratteri hostname non ammessi'; exit 1; }
cd "$CENTRAL_ROOT"
echo '=== STATO CENTRALE ==='
docker compose ps
echo '=== REGISTRAZIONE POLTI ==='
umask 077
TEMP=$(mktemp -d /root/ioho-polti-prep.XXXXXXXX)
trap 'rm -rf -- "$TEMP"' EXIT
# add-server restituisce il token una sola volta: mantenerlo fuori da stdout.
docker compose exec -T api python manage.py add-server "$NAME" "$ZHOST" > "$TEMP/provision.json" </dev/null
python3 - "$TEMP/provision.json" "$TEMP/config.json" <<'PY'
import json, sys
from pathlib import Path
raw = Path(sys.argv[1]).read_text()
start = raw.find('{')
if start < 0:
    raise SystemExit('ERRORE: registrazione non ha restituito JSON')
data, _ = json.JSONDecoder().raw_decode(raw[start:])
token = data.get('agent_token', '')
if len(token) < 32:
    raise SystemExit('ERRORE: token agente non valido')
base = '/var/www/www.polti.com'
config = {
  'console_url': 'https://2.31.176.212',
  'agent_token': token,
  'server_timezone': 'Europe/Rome',
  'poll_seconds': 20,
  'max_bytes_per_file': 4_000_000,
  'max_total_bytes': 25_000_000,
  'max_files': 30,
  'access_logs': [
    f'{base}/logs/access.log', f'{base}/logs/access.log.1', f'{base}/logs/access.log.1.gz',
    f'{base}/logs/reverse_access.log', f'{base}/logs/reverse_access.log.1', f'{base}/logs/reverse_access.log.1.gz',
    '/var/log/nginx/access.log', '/var/log/nginx/access.log.1',
  ],
  'nginx_error_logs': [
    f'{base}/logs/error.log', f'{base}/logs/error.log.1',
    f'{base}/logs/reverse_error.log', f'{base}/logs/reverse_error.log.1',
    '/var/log/nginx/error.log',
  ],
  'app_logs': [
    f'{base}/htdocs/var/log/system.log',
    f'{base}/htdocs/var/log/exception.log',
    f'{base}/htdocs/var/log/debug.log',
    f'{base}/htdocs/var/log/magento.cron.log',
    f'{base}/htdocs/var/log/*stripe*.log',
    f'{base}/htdocs/var/log/*.log',
  ],
}
Path(sys.argv[2]).write_text(json.dumps(config, indent=2) + '\n')
PY
install -m 644 "$CENTRAL_ROOT/agent/collector.py" "$TEMP/collector.py"
install -m 755 "$SCRIPT_DIR/install-polti.sh" "$TEMP/install-polti.sh"
if [[ -s /etc/nginx/ssl/ioho.crt ]]; then
    install -m 644 /etc/nginx/ssl/ioho.crt "$TEMP/console.crt"
fi
tar -czf "$BUNDLE" -C "$TEMP" config.json collector.py install-polti.sh $([[ -f "$TEMP/console.crt" ]] && printf console.crt)
chmod 600 "$BUNDLE"
echo '=== PACCHETTO PRONTO ==='
ls -lh "$BUNDLE"
sha256sum "$BUNDLE"
echo "Server registrato: $NAME | Hostname Zabbix: $ZHOST"
echo 'Il pacchetto contiene un token privato. Trasferirlo SOLO via SSH e conservarlo sotto /root.'
echo 'Dopo il trasferimento, installare su Polti ed eliminare il bundle da entrambi i server.'
