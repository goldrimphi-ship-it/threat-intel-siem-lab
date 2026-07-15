import json
import glob
from pymisp import PyMISP, MISPEvent, MISPAttribute

MISP_URL = "https://127.0.0.1:8443"
MISP_KEY = "eoySNb2WwT7lAiy57E439usHIKaJn5disFfF4fpn"
MISP_VERIFY_SSL = False

misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_SSL)

log_files = glob.glob('/home/cowrie/cowrie/var/log/cowrie/cowrie.json*')

ips = set()
for log_file in log_files:
    with open(log_file, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if 'src_ip' in event:
                    ips.add(event['src_ip'])
            except:
                pass

print(f"Found {len(ips)} unique attacker IPs")

misp_event = MISPEvent()
misp_event.info = "Cowrie Honeypot IOCs"
misp_event.distribution = 0
misp_event.threat_level_id = 2
misp_event.analysis = 1

for ip in ips:
    misp_event.add_attribute('ip-src', ip)

result = misp.add_event(misp_event)
print(f"Event created: {result['Event']['id']}")
