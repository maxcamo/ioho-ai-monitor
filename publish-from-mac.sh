#!/usr/bin/env bash
set -Eeuo pipefail
clear
ZIP="${1:-$HOME/Downloads/IOHO_AI_Monitor_GitHub_0_3.zip}"
REPO='maxcamo/ioho-ai-monitor'
[[ -s "$ZIP" ]] || { echo "ZIP non trovato o vuoto: $ZIP"; exit 1; }
command -v gh >/dev/null || { echo 'Installare GitHub CLI: brew install gh'; exit 1; }
command -v git >/dev/null || { echo 'git non installato'; exit 1; }
command -v unzip >/dev/null || { echo 'unzip non installato'; exit 1; }
gh auth status >/dev/null 2>&1 || { echo 'Eseguire gh auth login per accedere a GitHub'; exit 1; }
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
unzip -q "$ZIP" -d "$TMP/unpack"
SRC="$TMP/unpack/ioho-ai-monitor"
[[ -f "$SRC/agent/collector.py" && -f "$SRC/app/main.py" && -f "$SRC/.gitignore" ]] || { echo 'Archivio non valido'; exit 1; }
if find "$SRC" -type f \( -name '.env' -o -name '*.key' -o -name '*.pem' -o -name '*.crt' -o -name '*token*' -o -name '*.log' \) | grep .; then
  echo 'ERRORE: archivio contiene file potenzialmente sensibili; verifica manuale obbligatoria.'
  exit 1
fi
gh repo clone "$REPO" "$TMP/repo" -- --depth 1
(cd "$SRC" && find . -type f \( -name '*.py' -o -name '*.sh' -o -name '*.js' -o -name '*.html' -o -name '*.yaml' -o -name '*.conf' -o -name '*.json' -o -name '*.txt' -o -name '*.md' -o -name 'Dockerfile' -o -name 'VERSION' -o -name 'requirements.txt' -o -name '.gitignore' -o -name '.env.example' \) -print0) | (cd "$SRC" && tar --null -T - -cf -) | (cd "$TMP/repo" && tar xf -)
cd "$TMP/repo"
git status --short
git add --all
if git diff --cached --quiet; then echo 'Repository già aggiornato'; exit 0; fi
git commit -m 'feat: publish IOHO AI Monitor v0.3 source and Polti onboarding'
git push origin HEAD:main
echo "OK: pubblicazione completata: https://github.com/$REPO"
