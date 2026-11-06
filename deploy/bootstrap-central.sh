#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo 'ERRORE: Docker non installato'; exit 1; }
docker compose version >/dev/null || { echo 'ERRORE: Docker Compose plugin non installato'; exit 1; }
command -v openssl >/dev/null || { echo 'ERRORE: openssl non disponibile'; exit 1; }
if [[ ! -f .env ]]; then
  umask 077
  cp .env.example .env
  DB_PASS="$(openssl rand -hex 24)"
  UI_PASS="$(openssl rand -hex 24)"
  HOOK_PASS="$(openssl rand -hex 32)"
  sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${DB_PASS}/" .env
  sed -i "s/^DASHBOARD_PASSWORD=.*/DASHBOARD_PASSWORD=${UI_PASS}/" .env
  sed -i "s/^ZABBIX_WEBHOOK_TOKEN=.*/ZABBIX_WEBHOOK_TOKEN=${HOOK_PASS}/" .env
  chmod 600 .env
  echo 'Credenziali generate in .env (chmod 600). Non copiarle nei ticket o nei log.'
else
  echo 'File .env esistente: non sovrascritto.'
fi
echo 'Avvio PostgreSQL, API e worker...'
docker compose up -d --build
sleep 4
curl --fail --silent http://127.0.0.1:8088/health || true
echo
echo 'API in ascolto SOLO su 127.0.0.1:8088. Configurare Nginx e HTTPS prima dei collector remoti.'
echo 'Aprire .env e impostare OPENAI_API_KEY e SMTP, poi: docker compose up -d --force-recreate'
