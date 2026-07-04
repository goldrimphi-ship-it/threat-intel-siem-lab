# Threat Intelligence SIEM Lab

A home lab SIEM built with Elastic Stack and MISP threat intelligence, demonstrating end-to-end blue team capabilities from IOC ingestion to real-time alert generation.

## Architecture

```
MISP Threat Feeds (CIRCL, Abuse.ch, Botvrij.eu)
         ↓
  Python Ingestion Script (misp_to_elastic.py)
         ↓
  Elasticsearch (misp-iocs index, 160,000+ IOCs)
         ↓
  Kibana Detection Rules (Indicator Match)
         ↓
  Security Alerts Dashboard
```

## Stack

| Component | Role |
|-----------|------|
| MISP | Threat intelligence platform — aggregates IOC feeds |
| Elasticsearch 8.x | SIEM backend — stores logs and threat intel |
| Kibana | SIEM frontend — detection rules and alert dashboard |
| Filebeat | Log ingestion — system, auth, and network logs |
| Python 3 | Custom ETL script — MISP → Elasticsearch pipeline |
| VirtualBox | VM hosting on Windows host (16GB RAM) |

## Features

- **160,000+ IOCs** ingested from MISP feeds including CIRCL, Abuse.ch URLhaus, Feodo Tracker, and Botvrij.eu
- **ECS-compliant** threat indicator mapping (`threat.indicator.*` fields)
- **Automated hourly ingestion** via cron job
- **Indicator Match detection rule** correlating live logs against known malicious IPs
- **Real-time alerting** with severity scoring and risk scores in Kibana Security
- **State tracking** to avoid duplicate indexing across runs

## Detection Rules

| Rule | Type | Severity |
|------|------|----------|
| MISP Threat Intel - Malicious IP Match | Indicator Match | High |

## IOC Types Supported

- IP addresses (source/destination)
- Domains and hostnames
- URLs
- File hashes (MD5, SHA1, SHA256)
- Email addresses
- Filenames

## Project Structure

## Key Skills Demonstrated

- SIEM architecture and deployment
- Threat intelligence platform integration (MISP)
- Elastic Common Schema (ECS) field mapping
- Custom ETL pipeline development (Python)
- Detection engineering (Indicator Match rules)
- SOC alert triage workflow

## Environment

- **Host:** Windows, VirtualBox
- **MISP VM:** Ubuntu, Apache, MySQL
- **SIEM VM:** Ubuntu 24, Elasticsearch 8.x, Kibana, Filebeat
- **RAM:** 8GB per VM, Elasticsearch JVM heap capped at 1GB
