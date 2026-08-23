# SOC/SIEM PFA — CHU Hassan II (Detection & Automated Response Purple Team Lab)

A two-month internship (PFA) project building a SOC/SIEM detection-and-response
pipeline across a hybrid Active Directory + Kubernetes + web-app lab environment,
simulating a hospital IT environment (CHU Hassan II, Fès).

Full write-up, including architecture, week-by-week progress, and a full penetration
test against the environment, is in [`report/raport_de_stage.pdf`](report/raport_de_stage.pdf).

## What this repo contains
- Custom Wazuh detection rules (Kerberoasting, AD compromise chain, container
  runtime compromise via Falco, web-app SQLi)
- Wazuh → TheHive alert integration (`integrations/custom-w2thive.py`)
- Wazuh → Telegram real-time notification integration (`integrations/custom-telegram.py`)
- Two custom Cortex responders: `K8sIsolate` (NetworkPolicy-based pod isolation)
  and `IPBlock`

## What this repo does NOT include
This was a lab environment spanning 3 VMs (K3s cluster), a Windows AD server, and
several Docker Compose stacks (Wazuh, TheHive/Cortex). There is no one-command
deploy script — reproducing this requires your own similarly-shaped lab. See the
report's Chapter 2 (Architecture) for the full topology.

## Known limitations (see report, Chapter 6, for full detail)
- **Responder auto-trigger does not currently work end-to-end** — a dataType
  mismatch between Cortex's responder typing (`thehive:case_artifact`) and the
  Wazuh integration script's query (`dataType=ip`) means the automated trigger
  path never returns a match. Documented as an architectural limitation, not
  fixed in this version.
- **Manual responder trigger in the TheHive UI is also broken** — an internal
  bug in this TheHive version's Cortex connector (`GetByNameUnsupportedError`).
  Responders work when invoked directly against the Cortex API (verified — see
  report §3.4.3), just not from either UI path.
- Case-resolved Telegram notifications were never implemented.
- No analyzer coverage for the `other` Cortex dataType (used for pod/container
  name observables).

## Requirements to reproduce
- A K3s (or similar) Kubernetes cluster, 3 nodes recommended
- A Windows Server with Active Directory
- Docker + Docker Compose for Wazuh (4.12.0) and TheHive 5 / Cortex
- Falco deployed as a DaemonSet on your Kubernetes nodes

## Setup
1. Copy `.env.example` to `.env` and fill in your own values (Telegram bot
   token, Cortex API key, TheHive API key, chat ID).
2. Copy `wazuh/ossec.conf.example`, fill in the placeholder values, and deploy
   it to your Wazuh manager along with `wazuh/local_rules.xml`.
3. Deploy the wrapper + `.py` integration scripts to your Wazuh manager's
   `/var/ossec/integrations/` directory (`chown root:wazuh`, `chmod 750` on
   the wrapper; `chmod 750` on the `.py` file).
4. Deploy the `responders/` scripts into your Cortex instance following
   [Cortex's custom responder docs](https://github.com/TheHive-Project/Cortex-Analyzers).

## Credentials
All secrets in this repo are placeholders. Every credential used during
development (Telegram bot token, Cortex API key, TheHive API key, and the k3s
cluster admin kubeconfig) has been rotated and is no longer valid.

## License
[choose one — MIT is a common default for a project like this]
