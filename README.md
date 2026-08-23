# K8s SOC — Purple Team Detection & Response Pipeline

A SOC/SIEM pipeline for detecting and automatically responding to attacks
across a hybrid Active Directory + Kubernetes + web-app environment. Built as
a two-month PFA internship project (CHU Hassan II, Fès).

## Stack
- **Wazuh** (SIEM/HIDS) — detection rules for Kerberoasting, AD compromise
  chains, Kubernetes runtime compromise (via Falco), and web SQLi (DVWA)
- **TheHive + Cortex** — case management, automated enrichment, and
  automated response
- **Custom Cortex responders**: `K8sIsolate` (NetworkPolicy-based pod
  isolation) and `IPBlock` (iptables DROP rule)
- **Telegram** — real-time alert notifications

## Requirements
- Docker + Docker Compose
- A Kubernetes cluster (K3s recommended) with `kubectl` access, for the
  `K8sIsolate` responder and Falco-based detection
- Falco deployed as a DaemonSet on your Kubernetes nodes
- (Optional) A Windows Server with Active Directory, for the AD-side
  detection rules

## Deploy

**1. Wazuh:**
```bash
cd wazuh
docker compose up -d
```
This is the official Wazuh single-node stack. Before starting it, generate
the required SSL certs per
[Wazuh's own instructions](https://github.com/wazuh/wazuh-docker/tree/main/single-node) —
this repo does not include them, since they're generated per-deployment.

Then copy this repo's `wazuh/ossec.conf.example` and `wazuh/local_rules.xml`
into the running `wazuh.manager` container (`docker cp`), filling in the
placeholder values in `ossec.conf` first (Telegram token, TheHive API key,
cluster key).

**2. TheHive + Cortex:**
```bash
# from the repo root
cp .env.example .env   # fill in real values
docker compose up -d
```
Note: the `cortex` service in `docker-compose.yml` expects a locally-built
image (`thehive-cortex-cortex`). If you don't have one, swap it for the
official `thehiveproject/cortex` image, or build your own from the
[Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers) repo.

Also copy `cortex/application.conf.example` to `cortex/application.conf`
(fill in a random secret key) — it's mounted into the Cortex container.

**3. Deploy the integrations** (Wazuh → TheHive, Wazuh → Telegram):
```bash
docker cp integrations/custom-w2thive.py wazuh.manager:/var/ossec/integrations/
docker cp integrations/custom-w2thive    wazuh.manager:/var/ossec/integrations/
docker cp integrations/custom-telegram.py wazuh.manager:/var/ossec/integrations/
docker cp integrations/custom-telegram    wazuh.manager:/var/ossec/integrations/
docker exec wazuh.manager chown root:wazuh /var/ossec/integrations/custom-w2thive /var/ossec/integrations/custom-telegram
docker exec wazuh.manager chmod 750 /var/ossec/integrations/custom-w2thive /var/ossec/integrations/custom-telegram
docker exec wazuh.manager /var/ossec/bin/wazuh-control restart
```

**4. Bridge the Wazuh and TheHive/Cortex Docker networks** so the manager
can reach TheHive/Cortex by hostname:
```bash
docker network connect <wazuh-network> thehive
docker network connect <wazuh-network> cortex
```

**5. Deploy the Cortex responders** (`responders/K8sIsolate/`,
`responders/IPBlock/`) into your Cortex instance's `Cortex-Analyzers/responders/`
folder, then enable them for your organization from the Cortex UI.

## Known limitations
See the codebase's inline comments and `.env.example`. Notably: the
automated responder-trigger chain (Wazuh → Cortex responder, fully hands-off)
has a documented dataType mismatch that prevents full automation — responders
work when invoked directly against the Cortex API, just not yet via either
UI's auto-trigger path.

## Credentials
All secrets in this repo are placeholders. Every real credential used during
development has been rotated or is no longer valid.

## License
MIT
