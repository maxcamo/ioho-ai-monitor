# Distribuzione da GitHub — IOHO AI Monitor 0.3

Questa directory contiene **sorgenti**, non credenziali o configurazioni installate.

## Clonare da GitHub

Da una macchina con accesso al repository (per un repository privato configurare una deploy key o una credenziale con sola lettura):

```bash
clear
git clone https://github.com/maxcamo/ioho-ai-monitor.git
cd ioho-ai-monitor
```

Non usare `curl | bash` su server di produzione. Ispezionare prima gli script.

## Console centrale già installata

Su `ai-control` non sostituire l'intera directory con una copia pulita: preservare `.env`, database e `compose.yaml` del deploy attivo. Prima di aggiornare fare un backup e testare in staging. Usare il repository come sorgente versionato e confrontare i file (`git diff`) rispetto a `/opt/ioho-ai-monitor`.

## Nuovo server Magento: Polti

Il codice sorgente del collector è in `agent/collector.py`, gli script specifici in `deploy/polti/`.

1. Installare/verificare la versione 0.3 sulla console centrale.
2. Su ai-control utilizzare `deploy/polti/prepare-central.sh` per registrare `polti.com` e creare il bundle privato `/root/ioho-polti-onboarding.tar.gz` con token e certificato.
3. Trasferire il bundle **direttamente al server Polti via SCP**, senza inserirlo in GitHub, ed eseguire `install-polti.sh` come root.
4. Verificare che il collector risulti attivo e che la console riceva un nuovo audit.

La versione del pacchetto per Polti presuppone l'utente Linux `polticom`, la root Magento `/var/www/www.polti.com/htdocs`, e il server centrale `https://2.31.176.212`. Verificare i valori sul server prima di eseguire gli script.

## Riservatezza e sicurezza

Non pubblicare mai `.env`, `config.json` generato, token, API key, `.crt` di bundle privati, password, access log o report clienti. Preferire un repository privato. L'accesso via GitHub non sostituisce un certificato HTTPS verificato sulla console.