IOHO AI Monitor - Onboarding Polti
==================================
1) Verificare su Polti il nome tecnico dell'host Zabbix:
   grep -h '^Hostname=' /etc/zabbix/zabbix_agentd.conf /etc/zabbix/zabbix_agent2.conf 2>/dev/null || hostname -f
2) Caricare questo ZIP su ai-control sotto /tmp ed estrarlo:
   unzip -oq /tmp/IOHO_Polti_Onboarding.zip -d /tmp/
   bash /tmp/ioho_polti_onboarding/prepare-central.sh
   Inserire il nome tecnico esatto Zabbix, usando l'output del punto 1.
3) Trasferire /root/ioho-polti-onboarding.tar.gz da ai-control a Polti usando SCP/SFTP, senza rendere pubblici file o token.
4) Su Polti, come root:
   install -d -m 700 /root/ioho-polti-onboarding
   tar -xzf /root/ioho-polti-onboarding.tar.gz -C /root/ioho-polti-onboarding
   bash /root/ioho-polti-onboarding/install-polti.sh
5) Su ai-control:
   cd /opt/ioho-ai-monitor
   docker compose exec -T api python manage.py run-audit polti.com </dev/null
   docker compose ps
   docker compose logs --tail=15 worker
6) Dopo verifica rimuovere in modo protetto bundle contenente token su entrambi i server. Non incollare JSON config o token in chat.
