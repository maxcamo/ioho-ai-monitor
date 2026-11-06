## Dashboard: analisi su richiesta (v0.5)

Nella **Panoramica** e nella pagina di ogni server sono presenti due azioni:

- **Accessi 10m** (`access_check`): raccoglie SOLO access.log, aggrega ultimi 5/10 minuti per IP, URL, filtri, status e ritmo/minuto, quindi avvia diagnosi AI (se OPENAI_API_KEY configurata).
- **Applicativi 60m** (`app_check`): raccoglie SOLO log applicativi Magento negli ultimi 60 minuti e raggruppa firme di errore, frequenza e picchi, quindi avvia diagnosi AI.

I pulsanti sono protetti da HTTP Basic e verifica same-origin, usano POST, accodano un job per server e categoria con limite anti-duplicazione di 2 minuti. Sono operazioni di **sola lettura**; non provocano stress artificiale e non modificano Nginx/Magento. Ogni report è distinto dall'audit generale e non sovrascrive il suo stato di salute. I log vengono campionati entro i budget configurati; la diagnosi segnala le limitazioni. L'AI legge solo aggregati depurati, non IP sorgente o righe grezze.

Aggiornamento su ai-control: `bash deploy/update-central-v05.sh` dal clone GitHub. Aggiornamento sui collector già installati: `bash deploy/update-agent-v05.sh`; aggiornare prima la console e poi gli agenti.

**Per abilitare l'AI:** configurare `OPENAI_API_KEY` nell'`.env` della console centrale e ricreare solo il worker con Docker Compose. Senza chiave i pulsanti generano report con diagnosi per regole e la dashboard lo dichiara esplicitamente. Non mettere la chiave su GitHub o sui server Magento.

---

> **Nota GitHub:** questo repository contiene solo codice e template, mai token di collector, `.env`, certificati o log dei clienti. Dopo il clone conservare la configurazione runtime sul server e aggiornarla separatamente. Per Polti usare `deploy/polti/README.txt`, che genera localmente un bundle contenente un token privato: non caricare il bundle su GitHub.

# IOHO AI Monitor — sorgenti consolidati v0.3 (pilota controllato)

Console indipendente da Zabbix per ~40 server Linux/Magento. Due workflow:

- **Trigger CPU Zabbix** → webhook → analisi del server mirato → incidente in console.
- **Audit notturno alle 02:30** (Europe/Rome) → analisi log 24 h con budget di lettura → dashboard → un riepilogo email alle 06:30 (solo se SMTP configurato).

> **Stato**: sorgenti consolidati dalla MVP e dalla patch 0.3; testare prima di distribuire a nuovi server. Non esegue azioni correttive. Non pretende di leggere integralmente log enormi: limita le letture e segnala espressamente l'incompletezza.

## Struttura

```
app/       FastAPI + dashboard HTML + API webhooks/collector + analisi AI
agent/     collector Python stdlib, sola lettura, connessioni HTTPS in uscita
worker.py  job processor, scheduler, email, retention
manage.py  provisioning server e audit manuale
zabbix/    JavaScript per Media type Webhook Zabbix 7.x
deploy/    bootstrap centrale, service systemd e proxy Nginx
```

## Prerequisiti e sicurezza

- Console: server Linux con Docker Engine, `docker compose` plugin, Nginx con **HTTPS TLS valido**, DNS dedicato, firewall. La dashboard usa HTTP Basic: **non esporre mai in HTTP**. Aggiungere preferibilmente VPN, allowlist IP o un sistema SSO prima di esporla su Internet.
- Collector: Python 3.10+ e Linux con `systemd`; utente dedicato non privilegiato, permessi di **sola lettura** su access.log, error.log e log Magento; traffico HTTPS **in uscita**. Nessuna apertura SSH dal pannello, nessuna esecuzione remota.
- Zabbix: accesso admin per aggiungere un media type webhook e un'azione/operazione senza toccare la notifica email esistente.
- API OpenAI: chiave API separata dall'abbonamento ChatGPT; addebito a consumo. Senza chiave la diagnosi è **rule-based**, esplicitamente segnalata, non AI.
- Postgres solo su rete interna Docker. Porta API esposta esclusivamente su loopback `127.0.0.1:8088`, da mettere dietro TLS.
- Conservazione analisi/job: 30 giorni di default. Backup database e custodia token a carico dell'operatore.

## A — Installazione sul server della console

Dal server dedicato (non necessariamente quello di Zabbix), copiare/scaricare questa cartella e:

```bash
clear
cd /opt/ioho-ai-monitor
bash deploy/bootstrap-central.sh
```

La prima esecuzione genera `.env` con password differenti per PostgreSQL, pannello e webhook. Poi:

```bash
clear
cd /opt/ioho-ai-monitor
nano .env
# OPENAI_API_KEY=sk-...   (non condividere la chiave)
# SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, REPORT_TO
# Esempio REPORT_TO=ops@propriodominio.tld

docker compose up -d --force-recreate

docker compose ps
docker compose logs --tail=80 api worker
curl -fsS http://127.0.0.1:8088/health
```

**Nginx:** creare un server `https://monitor.<dominio-di-proprieta>` con certificato valido e utilizzare `deploy/nginx-example.conf` **all'interno del blocco `server` TLS** (non copiarlo come intero `nginx.conf`). Aprire 443 solo da reti autorizzate ove possibile. Testare TLS e autenticazione browser prima di installare agent remoti.

La UI è `https://monitor.<dominio-di-proprieta>/`, autenticazione con `DASHBOARD_USER` e `DASHBOARD_PASSWORD` presenti in `.env`.

## B — Registrazione del primo server Magento (esempio Polti)

Il secondo parametro deve essere **Host name tecnico** in Zabbix, non il nome visibile. Prima verificarlo dalla UI di Zabbix:

```bash
clear
cd /opt/ioho-ai-monitor
docker compose exec api python manage.py add-server polti.it NOME_HOST_TECNICO_ZABBIX
```

L'output contiene un **agent_token** generato una sola volta. Copiarlo in un password manager. Quindi sul server Magento, copiare la cartella `agent/` e `deploy/install-agent.sh` e configurare:

```bash
clear
sudo cp agent/config.example.json /etc/ioho-ai-agent.json
sudo nano /etc/ioho-ai-agent.json
# console_url: https://monitor.<dominio-proprio>
# agent_token: token appena generato
# access_logs e nginx_error_logs: percorsi reali, eventualmente rotated *.1 e *.gz
# app_logs: glob Magento var/log/*.log* e moduli personalizzati

sudo chmod 600 /etc/ioho-ai-agent.json
python3 agent/collector.py /etc/ioho-ai-agent.json --once
```

L'ultimo comando fa un'ispezione locale *non inviata* alla console e mostra in JSON i file trovati, quanti eventi vengono letti e le limitazioni. Attenzione: se lo esegui come root legge log che l'utente del servizio potrebbe non poter leggere. Meglio provarlo anche come `ioho-monitor` dopo installazione.

Concedere **solo** gli ACL strettamente necessari, per esempio (adattare percorsi):

```bash
clear
sudo apt-get install -y acl
sudo setfacl -m u:ioho-monitor:rx /var/www/www.example.com/logs
sudo setfacl -m u:ioho-monitor:r /var/www/www.example.com/logs/access.log
sudo setfacl -m u:ioho-monitor:r /var/www/www.example.com/logs/error.log
# Per file ruotati e nuovi log applicativi impostare ACL sui file già presenti
# e ACL default appropriate sulle directory; verificare prima la struttura reale.
```

Per Magento, concedere accesso in lettura a `htdocs/var/log` e ai file, più permesso di attraversamento sulle directory genitrici (`x`). Se i file vengono ricreati da logrotate o Magento, configurare ACL di default o gruppi appropriati; non rendere i log `chmod 777`. In caso di percorsi con contenuti sensibili limitare l'accesso ai soli log approvati.

Avviare systemd:

```bash
clear
sudo bash deploy/install-agent.sh
sudo journalctl -u ioho-ai-agent -n 50 --no-pager
```

Il collector interroga `/api/agent/next` ogni 20 secondi, mantiene l'heartbeat e si attiva **solo se è in coda un job**, senza costose scansioni continue.

## C — Zabbix: media type e action CPU (senza toccare le mail esistenti)

1. **Alerts → Media types → Create media type**. Nome: `IOHO AI Monitor`. Tipo: **Webhook**.
2. Copiare il JavaScript contenuto in `zabbix/ioho-ai-webhook.js` nel campo **Script**.
3. Impostare questi parametri *esattamente*:

| Parametro | Valore |
| --- | --- |
| `url` | `https://monitor.<dominio-proprio>/api/zabbix/event` |
| `token` | valore `ZABBIX_WEBHOOK_TOKEN` di `.env` |
| `event_id` | `{EVENT.ID}` |
| `host` | `{HOST.HOST}` |
| `name` | `{EVENT.NAME}` |
| `status` | `{EVENT.VALUE}` |
| `severity` | `{EVENT.SEVERITY}` |
| `clock` | `{EVENT.DATE} {EVENT.TIME}` |

4. Abilitare il media type. Creare o usare un utente tecnico Zabbix dedicato, aggiungendo il **media IOHO AI Monitor**. Se Zabbix richiede **Send to**, inserire `ioho-monitor` (il parametro non è utilizzato dal nostro script).
5. **Alerts → Actions → Trigger actions**: nuova azione `IOHO - CPU alto -> AI`. Filtrare sui trigger CPU già esistenti (trigger name/tag coerenti con i vostri template); nell'operazione di invio selezionare l'utente tecnico e **solo** il media type `IOHO AI Monitor`. Lasciare le azioni email preesistenti invariate. Definire un solo invio iniziale, non ripetizioni ad ogni step.
6. Testare con la funzione **Test** del media type, compilando un event ID di prova, host registrato e `status=1`, oppure con l'evento reale. Controllare che il job compaia nel pannello. Non provocare artificialmente saturazione CPU in produzione.

Il codice lato server deduplica lo stesso `event_id` e limita a un'analisi incidente ogni 15 minuti per server. Una risposta HTTP 404 all'evento indica che l'host Zabbix non corrisponde a quello registrato in console.

**Nota:** per ora si inoltrano solo gli eventi **PROBLEM**. La chiusura automatica alla recovery Zabbix è uno sviluppo successivo: in questa versione la gravità rappresenta **l'ultima diagnosi**, non necessariamente lo stato corrente del trigger.

## D — Test incidente e controllo manuale

Dopo la registrazione, puoi accodare un audit a richiesta senza produrre stress CPU:

```bash
clear
cd /opt/ioho-ai-monitor
docker compose exec api python manage.py run-audit polti.it
docker compose logs -f --tail=50 worker
```

Oppure simulare un **evento Zabbix** dalla funzione Test del media type, verificando che arrivi, venga acquisito dal collector e compaia `done` con diagnosi nella console. I tre passaggi che ci aspettiamo sono:

1. **queued** (arrivato da Zabbix) → **leased** (assegnato al collector) → **collected** (evidenze ricevute)
2. **processing** (analisi AI) → **done** (diagnosi in console)
3. **critical / warning / ok / unknown**; `unknown` indica evidenze non affidabili, non server sano.

## E — Notturno

- Alle **02:30 Europe/Rome**, il worker genera un job `nightly` per ciascun server attivo (quando il servizio è online nella finestra 02:30–04:59).
- Il collector esamina l'ultima finestra di **1.440 minuti**. Limiti per sicurezza: fino a 12 MB per file, 90 MB complessivi per server e 40 file per categoria (modificabili in config); include `*.1` e `*.gz` dove presenti, ma una rotazione molto voluminosa può essere **campionata**, non letta integralmente.
- Alle **06:30 Europe/Rome**, se SMTP è configurato, un'email raggruppa gli stati dei server. I non analizzati vengono segnalati, mai marcati come OK.
- L'analisi AI usa l'API OpenAI **solo per aggregati/metadata**: non trasmette IP sorgente né righe di log complete. La console autenticata conserva temporaneamente IP e piccoli esempi depurati per consentire l'investigazione.
- La prima notte può risultare incompleta sui server con log grandi: la versione 0.2 potrà introdurre cursori incrementali di lettura per statistiche giornaliere complete, anomaly detection su baseline settimanale e stream di errori.

## F — Operatività, backup e limiti della MVP

- **Cosa non fa:** modificare firewall/Nginx, bloccare bot, riavviare servizi, eseguire shell da remoto, controllare promettendo diagnosi certa. Non monitora metriche CPU autonomamente: queste arrivano da Zabbix.
- **Cosa fa:** analizza su richiesta del trigger Zabbix, mostra top URL normalizzate, IP più attivi, status HTTP, errori di app e Nginx, processi con consumo medio `ps`, limita invii duplicati, schedula audit e email.
- **Privacy/GDPR:** IP e righe di log restano nel DB centrale protetto (retention 30 giorni), mentre l'API AI riceve soltanto statistiche e URL normalizzate. Anche le URL possono contenere identificativi: adattare la normalizzazione alle vostre applicazioni e definire policy di conservazione/informativa e trasferimento dati prima dell'uso su tutti i clienti.
- **Limiti diagnostici:** `ps %CPU` è una media, non equivalente al valore Zabbix al momento del picco; log custom che non adottano timestamp riconosciuti non vengono conteggiati e richiedono parser dedicati. Per log enormi il campionamento potrebbe mancare il momento dell'evento. La durata di analisi dipende dalla coda e dai tempi API; non esiste SLA nella versione pilota.
- **Scalabilità:** un worker sequenziale va bene per il pilota; con 40 server e analisi notturne contemporanee va dimensionata la concorrenza, i limiti API, I/O e retention. Nella fase successiva predisporre più worker con coda robusta e metriche di salute del monitor stesso.
- **Email incidenti:** non invia ancora email ad ogni incidente, perché Zabbix continua a farlo; il pannello mostra la diagnosi e l'email giornaliera riepiloga la notte.
- **Stato recuperato:** come sopra, manca ancora la sincronizzazione PROBLEM/RESOLVED.

Backup logico DB (esempio; conservare i dump fuori dal server):

```bash
clear
cd /opt/ioho-ai-monitor
docker compose exec -T db pg_dump -U ioho -d ioho_monitor > "ioho_monitor_$(date +%F).sql"
```

Test locali su codice senza bisogno di server:

```bash
clear
python3 -m pytest -q tests
```

## Note sviluppo (da integrare dopo il pilota)

- Parser personalizzati per access log JSON, errori Magento multilinea e rotazioni con file giganti.
- Baseline traffico 7/30 giorni e stato evento legato alla recovery Zabbix.
- Grafici storico per server, riconoscimento ricorrenze, snapshot processi più frequenti.
- Accesso console con utenti e audit trail/SSO, confidenze calibrate su esempi reali.
- Sistema d'avviso push in UI/email distinto dai trigger, limiti di costo AI per server/tenant.


## v0.4 - Analisi traffico incidente (5/10 minuti)

Per un **evento incidente Zabbix**, il collector calcola istantanee separate degli ultimi 5 e 10 minuti del solo access log: top URL normalizzate, top IP, IP x URL, query filtrate, risposte 403/410/429/444, picco/minuto e trend minuto per minuto. L'interfaccia segnala quando l'access log e' troncato; non sostituisce il confronto con CPU, PHP-FPM e WAF.

Per gli incidenti il budget predefinito viene elevato fino a 16 MB per access log e 40 MB per raccolta complessiva (configurabili con `incident_access_bytes` e `incident_total_bytes`, tetti hard di 24/60 MB); gli audit notturni mantengono i limiti esistenti. Serve aggiornare **sia console che collector**, installando `collector.py` e `traffic_analysis.py` nella stessa directory. Gli audit storici non acquisiscono retroattivamente questi dati.


## v0.6 - Doppio stato e finestre indipendenti

La panoramica mostra **Problemi applicativi (24h)** e **Traffico / crawler (10m)** in colonne e riepiloghi separati. Ogni colonna usa esclusivamente il proprio `app_check` o `access_check` completato: i vecchi audit misti e i trigger Zabbix non vengono attribuiti arbitrariamente ad un dominio. Il monitor non indica mai che un controllo sia corrente dopo la scadenza: accessi aggiornabili dopo 20 minuti, applicativi dopo 30 ore. L'ultimo esito storico e il collegamento rimangono visibili.

Il pulsante Applicativi ora accoda `app_check` con `minutes=1440` e `sections=["app"]`; Accessi mantiene `minutes=10` e `sections=["access"]`. Sono utilizzabili con collector v0.5; i collector precedenti vanno aggiornati per rispettare la selezione delle sezioni. Il monitor resta read-only.

La chiave `OPENAI_API_KEY` e' opzionale, senza di essa la diagnosi usa regole locali. Un campionamento parziale di un log molto grande limita la confidenza; non equivale a copertura completa delle 24 ore.

Per aggiornare solo la console, senza reinstallare i collector v0.5:

```bash
clear
cd /tmp/ioho-ai-monitor
git pull --ff-only origin main
bash deploy/update-central-v06.sh
```


## v0.7 — rapporto operativo access.log

La pagina di analisi Accessi mostra prima le richieste, la classifica dei top IP,
le URL con filtri e quelle senza filtri, le coppie IP×URL, il ritmo minuto e lo stato HTTP.
L'analisi 5 minuti è secondaria e le tabelle ridondanti sono rimosse dal report manuale HTTP.
La versione 0.7 è compatibile con i collector v0.5 e con i vecchi payload già salvati:
la classifica URL senza filtri dei report preesistenti è ricavata solo dalle top URL
che erano state archiviate, ed è segnalata come **parziale**. Non equivale
alla lettura integrale dell'access.log.
Per aggiornare la console: `bash deploy/update-central-v07.sh`.
Nessun upgrade agente è richiesto per questa modifica di visualizzazione.


## v0.8 — Classifica delle reti IP e geolocalizzazione su richiesta

Nel report di access.log sono visualizzate anche le reti IPv4 **/24** e IPv6 **/64**: richieste totali osservate, numero di IP distinti, richieste filtrate, risposte 403/410/429/444 e percentuale del campione. Con il collector aggiornato i conteggi per rete sono calcolati su tutte le richieste lette nel campione, non soltanto sui primi 15 IP. Per i job storici della v0.7 il raggruppamento e' invece derivato esclusivamente dai primi IP memorizzati: la UI segnala esplicitamente che i conteggi sono **parziali**, come accade anche se e' raggiunto il limite di aggregazione. Il campionamento del file puo' comunque essere incompleto.

Accanto a ogni IP pubblico e alle reti pubbliche appare un link IPinfo; il monitor non consulta automaticamente servizi di geolocalizzazione. La visita al sito terzo e' deliberata, con `target=_blank`, `rel=noopener noreferrer` e `referrerpolicy=no-referrer`. Indirizzi privati e non validi non sono linkati. L'attribuzione di una rete/ASN o la posizione geoIP non prova che il client sia un crawler legittimo; verificare reverse+forward DNS per bot dichiarati, proxy fidati, CPU e URL.

Aggiornamento centrale: `bash deploy/update-central-v08.sh` dopo `git pull`; aggiornamento dei collector gia' configurati: `bash deploy/update-agent-v08.sh`, su ciascun server interessato. Le analisi 10m nuove mostreranno gli aggregati completi del campione; per i report precedenti nessuna ricostruzione artificiale dei dati mancanti.

 
## v0.9 — Grafico CPU Zabbix, crawler ogni ora e badge cliccabili

**Dashboard:** stato applicativo (24h) e traffico/crawler (10m) separati. Il badge
`OK / WARNING / CRITICAL / DA AGGIORNARE` è cliccabile e apre il relativo
rapporto; il testo diagnostico non è più un link. Eliminato il paragrafo
ridondante sopra la tabella.

**Audit automatici:** il worker crea ogni ora, fra il minuto 02 e il minuto 10
(ora `TZ`, predefinita Europe/Rome), un `access_check` per ogni server abilitato
e senza audit accessi già attivo/recentissimo. Il controllo legge soltanto
`access.log` degli ultimi 10 minuti con le protezioni e i limiti del collector.
Il database `daily_markers` impedisce duplicati dopo il riavvio del worker.
Gli esiti restano validi fino a 75 minuti (non 20); il report indica l'orario
della fotografia, non descrive un monitoraggio in streaming.
`HOURLY_ACCESS_ENABLED=false` in `.env` disabilita le analisi automatiche.
Nessun carico artificiale sul sito; si applica ai server già registrati.

**CPU Zabbix (opzionale, API in sola lettura):** su `ai-control` modificare
`/opt/ioho-ai-monitor/.env` aggiungendo:

```ini
ZABBIX_API_URL=https://ZABBIX_FQDN/zabbix/api_jsonrpc.php
ZABBIX_API_TOKEN=TOKEN_DEDICATO_SOLO_LETTURA
# ZABBIX_CPU_ITEM_KEY=system.cpu.util
HOURLY_ACCESS_ENABLED=true
```

L'URL deve usare HTTPS con certificato attendibile per il container. Il token
NON è `ZABBIX_WEBHOOK_TOKEN`, ma un API token Zabbix dedicato, con permessi
limitati agli host e ai metodi `host.get`, `item.get` e `history.get`.
Dopo aver modificato `.env`, riavviare il worker con
`docker compose up -d --no-deps --force-recreate worker`. Non stampare
il token nei log o nelle chat.

Il worker usa il nome host tecnico `Server.zabbix_host` per trovare l'host
Zabbix, seleziona preferibilmente l'item dipendente `system.cpu.util`
(CPU utilization) oppure `system.cpu.util[,idle]` (convertito in 100-idle).
`ZABBIX_CPU_ITEM_KEY` è opzionale se il template differisce.
**NON** utilizza l'item `system.cpu.util` grezzo come percentuale
di utilizzo complessivo se non ha il nome `CPU utilization`: come key
dell'agente può indicare solo la CPU `user`.

Per ogni nuovo audit accessi/trigger CPU il worker interroga lo storico nei
10 minuti precedenti l'istante **effettivo di raccolta** del collector,
salva la sintesi `zabbix_cpu` nello stesso job e disegna CPU e richieste
sincronizzate per minuto nella pagina incidente. Il report storico non
cambia aprendo la pagina in seguito. Gli audit antecedenti alla v0.9 non
hanno i campioni CPU; serve un nuovo controllo. Se Zabbix non è configurato,
non risponde o non ha lo storico, l'analisi HTTP continua senza CPU.
Le API Zabbix non sono mai chiamate dal browser; il token resta nel worker.

**Deploy:** soltanto su `ai-control`:
`git -C /tmp/ioho-ai-monitor pull --ff-only origin main`,
`bash /tmp/ioho-ai-monitor/deploy/update-central-v09.sh`.
Il deploy aggiorna API e worker mantenendo il database, i token e gli agenti
invariati. Verificare l'API e testare i cinque host in sola lettura, senza
provocare un picco CPU artificiale.


## v0.10 — Home compatta e controlli automatici ogni ora su entrambe le colonne

**Panoramica:** nella tabella "Stato per tipologia" ciascuna cella mostra
solo il badge di stato cliccabile (apre il report), l'ultimo aggiornamento
con carattere piccolo e il pulsante di analisi manuale. Le frasi lunghe
con il riassunto diagnostico non appaiono più nella home; rimangono nel
report di dettaglio e nella tabella "Attività recente".

**Scheduler ogni ora, per ciascun server abilitato:**
- `access_check`: ultimi **10 minuti** del solo log accessi;
- `app_check`: ultimi **1.440 minuti (24 ore)** dei log applicativi.

I due scheduler sono indipendenti, vengono controllati dal worker fra
il minuto 02 e il minuto 10 di ogni ora locale (`TZ`, di default
`Europe/Rome`), e saltano un controllo quando esiste già un job della
stessa tipologia in corso oppure completato negli ultimi 10 minuti.
Usano marcatori DB distinti per ora e tipologia, evitando il reinvio al
riavvio. Non fanno recupero dei giri saltati durante un downtime.
Non leggono senza limiti: restano validi budget, campionamento e
`CPUQuota/MemoryMax` degli agenti. Se la coda è lenta, le verifiche
possono completarsi dopo l'inizio dell'ora.

I badge passano a `DA AGGIORNARE` dopo **75 minuti** per gli accessi e
dopo **90 minuti** per gli applicativi. Una fotografia non è monitoraggio
in tempo reale; data e ora visibili indicano l'ultimo completamento.

La configurazione `.env` sul server centrale supporta:

```ini
HOURLY_ACCESS_ENABLED=true
HOURLY_APP_ENABLED=true
```

Entrambe le impostazioni sono `true` per default anche se mancanti
dal file `.env`. Per disabilitare i controlli applicativi impostare
`HOURLY_APP_ENABLED=false` e ricreare il solo worker.

**Deploy centrale (ai-control, root):**

```bash
clear
git -C /tmp/ioho-ai-monitor pull --ff-only origin main
test "$(cat /tmp/ioho-ai-monitor/VERSION)" = "0.10"
bash /tmp/ioho-ai-monitor/deploy/update-central-v010.sh
```

Il deploy fa backup dei file aggiornati, ricostruisce `api` e `worker`,
verifica il loro avvio e non modifica il DB, i secret, la rete o gli agenti
Magento. I nuovi job automatici appariranno alla prossima finestra oraria
(minuti 02-10). La raccolta può essere eseguita anche manualmente dal
pulsante, senza produrre traffico di test sul sito.

**Verifica:** `docker compose logs --tail=50 worker` per leggere le
righe `[scheduler] access` e `[scheduler] app`, e la sezione
"Attività recente" nella dashboard. I cinque server esistenti
continuano a essere gestiti dalle registrazioni già presenti nel DB.


## v0.11 — Ritocchi grafici alla tabella "Stato per tipologia"

Nella **panoramica** il nome tecnico Zabbix viene nascosto (resta
disponibile nella pagina del singolo server). Il badge di stato
`CRITICAL / WARNING / OK / NON VERIFICATO` resta cliccabile e porta al
rapporto. Accanto compare un pulsante **solo icona di aggiornamento**
con tooltip e nome accessibile per rilanciare il controllo manuale
corrispondente. Il testo "Ultimo aggiornamento:" sparisce: viene mostrata
solo la data con ora UTC, in piccolo. Non viene cambiato il dettaglio
del report o il comportamento dei job.

L'elenco server viene **ordinato automaticamente per lo stato peggiore
delle due tipologie**: Critical, Warning, OK, quindi Non verificato /
Da aggiornare. A parita' di gravita' si usa l'ordine alfabetico del nome.
Gli altri dati e gli stati sono calcolati come nelle versioni precedenti.

Il valore della CPU Zabbix **in questa tabella** non e' ancora implementato:
rimane nel rapporto Accessi e verra' aggiunto in una versione successiva,
come concordato.

**Installazione centrale (solo API, non tocca il worker):**

```bash
clear
git -C /tmp/ioho-ai-monitor pull --ff-only origin main
test "$(cat /tmp/ioho-ai-monitor/VERSION)" = "0.11"
bash /tmp/ioho-ai-monitor/deploy/update-central-v011.sh
```

Lo script crea un backup del codice toccato, ricostruisce e riavvia solo
il servizio `api`, poi verifica `/health`. Database, token,
integrazione HTTPS Zabbix, scheduler e agenti sono invariati.
