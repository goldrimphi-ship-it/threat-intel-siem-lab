#!/usr/bin/env python3
"""
misp_to_elastic.py
------------------
Pulls IOCs from MISP via REST API and indexes them into Elasticsearch
under the 'misp-iocs' index using ECS threat.indicator fields.

Tracks last run via timestamp file to avoid re-indexing.
Designed for lab use — handles self-signed SSL on both MISP and ES.

Usage:
    python3 misp_to_elastic.py

Cron (every 60 min):
    0 * * * * python3 /opt/misp_to_elastic.py >> /var/log/misp_ingest.log 2>&1
"""

import urllib.request
import urllib.error
import json
import ssl
import os
import datetime
import sys

# ── CONFIG ───────────────────────────────────────────────────────────────────

MISP_API_KEY  = "YOUR_MISP_API_KEY_HERE"
ES_PASS       = "YOUR_ELASTIC_PASSWORD_HERE"

ES_URL        = "https://localhost:9200"
ES_USER       = "elastic"
ES_PASS       = "Ty@EA888"
ES_INDEX      = "misp-iocs"

STATE_FILE    = "/var/lib/misp-ingest/last_run.txt"
BATCH_SIZE    = 100   # events per MISP page
MAX_EVENTS    = 5000  # safety cap per run

# ── SSL CONTEXTS ─────────────────────────────────────────────────────────────

_no_verify = ssl.create_default_context()
_no_verify.check_hostname = False
_no_verify.verify_mode = ssl.CERT_NONE


# ── HELPERS ──────────────────────────────────────────────────────────────────

def log(msg):
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] {msg}", flush=True)


def es_request(method, path, body=None):
    import base64
    url = ES_URL + path
    token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
    }
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=_no_verify, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()[:500]
        log(f"ES {method} {path} -> HTTP {e.code}: {body_text}")
        raise
    except Exception as e:
        log(f"ES {method} {path} -> {e}")
        raise


def misp_request(path, body=None):
    url = MISP_URL + path
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=_no_verify, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()[:500]
        log(f"MISP {path} -> HTTP {e.code}: {body_text}")
        raise
    except Exception as e:
        log(f"MISP {path} -> {e}")
        raise


# ── STATE ─────────────────────────────────────────────────────────────────────

def load_last_run():
    try:
        with open(STATE_FILE) as f:
            val = f.read().strip()
            return val if val else None
    except FileNotFoundError:
        return None


def save_last_run(ts_str):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        f.write(ts_str)


# ── ECS MAPPING ───────────────────────────────────────────────────────────────

MISP_TO_ECS = {
    "ip-src":        ("ip",           "threat.indicator.ip"),
    "ip-dst":        ("ip",           "threat.indicator.ip"),
    "domain":        ("domain-name",  "threat.indicator.domain"),
    "hostname":      ("domain-name",  "threat.indicator.domain"),
    "url":           ("url",          "threat.indicator.url.full"),
    "uri":           ("url",          "threat.indicator.url.full"),
    "md5":           ("hash",         "threat.indicator.file.hash.md5"),
    "sha1":          ("hash",         "threat.indicator.file.hash.sha1"),
    "sha256":        ("hash",         "threat.indicator.file.hash.sha256"),
    "email-src":     ("email",        "threat.indicator.email.address"),
    "email-dst":     ("email",        "threat.indicator.email.address"),
    "email-subject": ("email",        "threat.indicator.email.subject"),
    "filename":      ("file",         "threat.indicator.file.name"),
    "mutex":         ("mutex",        "threat.indicator.registry.key"),
    "regkey":        ("windows-registry-key", "threat.indicator.registry.key"),
    "AS":            ("autonomous-system",    "threat.indicator.as.number"),
    "vulnerability": ("vulnerability",        "threat.indicator.cve"),
}


def _set_nested(d, dotted_key, value):
    keys = dotted_key.split(".")
    for key in keys[:-1]:
        d = d.setdefault(key, {})
    d[keys[-1]] = value


def _epoch_to_iso(epoch_str):
    if not epoch_str:
        return None
    try:
        return datetime.datetime.utcfromtimestamp(int(epoch_str)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _map_threat_level(level_id):
    return {"1": "High", "2": "Medium", "3": "Low"}.get(str(level_id), "Unknown")


def _map_tlp(distribution):
    return {"0": "RED", "1": "AMBER", "2": "GREEN", "3": "GREEN", "5": "WHITE"}.get(str(distribution), "WHITE")


def _extract_tags(event):
    return [tag.get("name", "") for tag in event.get("Tag", [])]


def attr_to_doc(attr, event):
    atype = attr.get("type", "")
    mapping = MISP_TO_ECS.get(atype)
    if not mapping:
        return None

    indicator_type, ecs_field = mapping

    doc = {
        "@timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": {
            "kind":     "enrichment",
            "category": ["threat"],
            "type":     ["indicator"],
            "module":   "misp",
            "dataset":  "misp.threat_intel",
        },
        "threat": {
            "feed": {"name": "MISP"},
            "indicator": {
                "type":        indicator_type,
                "confidence":  _map_threat_level(event.get("threat_level_id", "4")),
                "description": attr.get("comment", "") or event.get("info", ""),
                "modified":    _epoch_to_iso(attr.get("timestamp")),
                "provider":    "MISP",
                "tlp":         _map_tlp(event.get("distribution", "0")),
            },
        },
        "misp": {
            "event_id":        event.get("id"),
            "event_info":      event.get("info", ""),
            "attribute_id":    attr.get("id"),
            "attribute_type":  atype,
            "attribute_value": attr.get("value", ""),
            "category":        attr.get("category", ""),
            "to_ids":          attr.get("to_ids", False),
            "threat_level_id": event.get("threat_level_id"),
            "tags":            _extract_tags(event),
        },
    }

    _set_nested(doc, ecs_field, attr.get("value", ""))
    return doc


# ── ES INDEX SETUP ────────────────────────────────────────────────────────────

def ensure_index():
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp":                        {"type": "date"},
                "threat.indicator.ip":               {"type": "ip"},
                "threat.indicator.domain":           {"type": "keyword"},
                "threat.indicator.url.full":         {"type": "keyword"},
                "threat.indicator.file.hash.md5":    {"type": "keyword"},
                "threat.indicator.file.hash.sha1":   {"type": "keyword"},
                "threat.indicator.file.hash.sha256": {"type": "keyword"},
                "threat.indicator.email.address":    {"type": "keyword"},
                "misp.attribute_value":              {"type": "keyword"},
                "misp.event_info":                   {"type": "text"},
                "misp.tags":                         {"type": "keyword"},
            }
        }
    }
    try:
        es_request("GET", f"/{ES_INDEX}")
        log(f"Index '{ES_INDEX}' already exists.")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            es_request("PUT", f"/{ES_INDEX}", mapping)
            log(f"Created index '{ES_INDEX}'.")
        else:
            raise


# ── BULK INDEX ────────────────────────────────────────────────────────────────

def bulk_index(docs):
    if not docs:
        return 0

    import base64
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": ES_INDEX}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"

    token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/x-ndjson",
    }
    req = urllib.request.Request(
        ES_URL + "/_bulk",
        data=body.encode(),
        headers=headers,
        method="POST"
    )
    with urllib.request.urlopen(req, context=_no_verify, timeout=60) as r:
        result = json.loads(r.read())

    errors = [i for i in result.get("items", []) if "error" in i.get("index", {})]
    indexed = len(result.get("items", [])) - len(errors)
    if errors:
        log(f"  Bulk: {indexed} indexed, {len(errors)} errors. First: {errors[0]}")
    return indexed


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    log("=== MISP -> Elasticsearch IOC ingest starting ===")

    ensure_index()

    last_run = load_last_run()
    if last_run:
        log(f"Last run: {last_run} — fetching events newer than this.")
    else:
        log("First run — fetching all published events.")

    page          = 1
    total_indexed = 0
    total_events  = 0
    run_ts        = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    while total_events < MAX_EVENTS:
        payload = {
            "returnFormat":     "json",
            "limit":            BATCH_SIZE,
            "page":             page,
            "published":        True,
            "includeEventTags": True,
        }
        if last_run:
            epoch = int(datetime.datetime.fromisoformat(last_run.replace("Z", "")).timestamp())
            payload["timestamp"] = epoch

        log(f"Fetching MISP page {page} (limit={BATCH_SIZE})...")
        try:
            resp = misp_request("/events/restSearch", payload)
        except Exception:
            log("Failed to fetch from MISP — aborting.")
            sys.exit(1)

        events = resp.get("response", [])
        if not events:
            log("No more events from MISP.")
            break

        docs = []
        for wrapper in events:
            event = wrapper.get("Event", wrapper)
            total_events += 1
            for attr in event.get("Attribute", []):
                doc = attr_to_doc(attr, event)
                if doc:
                    docs.append(doc)

        log(f"  Page {page}: {len(events)} events -> {len(docs)} mappable attributes.")

        if docs:
            indexed = bulk_index(docs)
            total_indexed += indexed
            log(f"  Indexed {indexed} documents.")

        if len(events) < BATCH_SIZE:
            break
        page += 1

    save_last_run(run_ts)
    log(f"=== Done. {total_events} events processed, {total_indexed} IOCs indexed. ===")


if __name__ == "__main__":
    main()
