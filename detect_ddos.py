#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
import pandas as pd
from elasticsearch import Elasticsearch
from pymisp import PyMISP, MISPEvent
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== Load ENV =====
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

ES_URL   = os.getenv("ES_URL")
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
ES_INDEX = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "2"))
VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
EVENT_TITLE_DDOS = os.getenv("EVENT_TITLE_DDOS", "Potential DDoS Activity (SYN Flood)")

missing = []
for k,v in {"ES_URL":ES_URL,"MISP_URL":MISP_URL,"MISP_KEY":MISP_KEY}.items():
    if not v: missing.append(k)
if missing:
    sys.stderr.write(f"[CONFIG ERROR] Missing required env: {', '.join(missing)}\n")
    sys.exit(1)

LOG_FILE = os.getenv("LOG_FILE", "ddos_detect.log")
logger = logging.getLogger("ddos-detect")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=1048576, backupCount=3, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)


def fetch_connections_from_es():
    """Truy vấn ES để lấy (src_ip, dst_port)"""
    es = Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=HOURS_LOOKBACK)).isoformat()

    body = {
        "_source": ["@timestamp","source.ip","src_ip","destination.port","dest_port"],
        "query": {"range": {"@timestamp": {"gte": start}}},
        "size": 5000,
        "sort": [{"@timestamp":{"order":"desc"}}]
    }

    resp = es.search(index=ES_INDEX, body=body)
    rows = []
    for h in resp.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        src_ip = s.get("source.ip") or s.get("src_ip")
        if src_ip:
            rows.append(str(src_ip))
    return rows


def detect_ddos(conns, threshold=100):
    """Xác định IP có số lượng kết nối tăng đột biến (>=threshold)"""
    if not conns: return []
    df = pd.DataFrame(conns, columns=["ip"])
    grouped = df.groupby("ip").size()
    return [ip for ip,cnt in grouped.items() if cnt >= threshold]


def create_event(misp: PyMISP, title: str):
    ev = MISPEvent()
    ev.info = title
    ev.distribution = 0
    ev.analysis = 0
    ev.threat_level_id = 2
    res = misp.add_event(ev)
    return str(res["Event"]["id"])


def main():
    conns = fetch_connections_from_es()
    suspects = detect_ddos(conns, threshold=100)  # ngưỡng tùy chỉnh
    if not suspects:
        print("[!] Không phát hiện DDoS trong log.")
        return

    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)
    event_id = create_event(misp, EVENT_TITLE_DDOS)
    print(f"[+] Created Event {event_id} - {EVENT_TITLE_DDOS}")

    for ip in suspects:
        attr = {
            "type": "ip-src",
            "category": "Network activity",
            "value": ip,
            "to_ids": True,
            "comment": "Detected by SYN Flood heuristic"
        }
        misp.add_attribute(event_id, attr, pythonify=True)
        logger.info(f"ADD ip-src {ip} to event {event_id}")

    print(f"[+] Done. Added {len(suspects)} attacker IP(s).")


if __name__ == "__main__":
    main()
