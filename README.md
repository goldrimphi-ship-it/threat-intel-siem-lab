# Threat Intel SIEM Lab

Home SOC lab covering 8 cybersecurity domains.

## Stack
- **Vostro 3350** (192.168.3.10) — sensor node
  - Cowrie SSH honeypot (port 2222)
  - Suricata IDS (wlp9s0) — 51,976 rules
  - Filebeat — log shipping
  - theHarvester, Spiderfoot, Subfinder — OSINT recon

- **ELK VM** (192.168.3.147)
  - Elasticsearch + Kibana — 26,732 logs ingested

- **MISP VM** (10.0.2.15)
  - 160,098 IOCs stored
  - Automated Cowrie → MISP IOC pipeline (cron daily 2am)

## Domains Covered
1. Security Operations
2. Threat Intelligence
3. Security Assessment & Testing
4. Cryptography (in progress)
5. Incident Response (in progress)
6. Identity & Access Management (in progress)
7. Network Security (planned)
8. Cloud Security (planned)
