# K8s SOC — Purple Team Detection & Response Pipeline

A SOC/SIEM pipeline for detecting and responding to attacks across a hybrid
Active Directory + Kubernetes + web-app lab, built during a PFA internship
at CHU Hassan II, Fès.

## Stack
- **Wazuh** — detection rules (Kerberoasting, AD compromise, K8s runtime
  compromise via Falco, web SQLi)
- **TheHive + Cortex** — case management and automated response
- **Custom responders**: `K8sIsolate` (isolates a compromised pod via
  NetworkPolicy), `IPBlock` (blocks an IP via iptables)
- **Telegram** — real-time alert notifications

## Requirements
- Docker + Docker Compose
- A Kubernetes cluster (K3s recommended) with `kubectl` access
- Falco running as a DaemonSet on your cluster

## Deploy
```bash
# 1. Wazuh (generate SSL certs first — see Wazuh's own docs)
cd wazuh && docker compose up -d

# 2. TheHive + Cortex
cp .env.example .env   # fill in your values
docker compose up -d

# 3. Copy the integration scripts and Wazuh config into the manager
docker cp integrations/. wazuh.manager:/var/ossec/integrations/
docker cp wazuh/ossec.conf.example wazuh.manager:/var/ossec/etc/ossec.conf
docker cp wazuh/local_rules.xml wazuh.manager:/var/ossec/etc/rules/local_rules.xml
docker exec wazuh.manager chown root:wazuh /var/ossec/integrations/custom-w2thive /var/ossec/integrations/custom-telegram /var/ossec/etc/ossec.conf
docker exec wazuh.manager /var/ossec/bin/wazuh-control restart

# 4. Bridge the two Docker networks so Wazuh can reach TheHive/Cortex
docker network connect <wazuh-network> thehive
docker network connect <wazuh-network> cortex
```
Then deploy `responders/K8sIsolate` and `responders/IPBlock` into your
Cortex instance and enable them from the UI.

Fill in the placeholder values (`REPLACE_WITH_...`) in `ossec.conf.example`,
`application.conf.example`, and `.env` with your own credentials first.

## Known limitation
The fully automated responder-trigger chain (Wazuh → Cortex, hands-off) has
a documented dataType mismatch and doesn't fire end-to-end yet. Responders
work fine when invoked directly against the Cortex API.

## Credentials
All secrets here are placeholders — real ones used during development have
been rotated.

## License
MIT
