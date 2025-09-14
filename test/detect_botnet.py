#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta

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

# ===== ENV (giống form Nmap) =====
ES_URL   = os.getenv("ES_URL")
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
ES_INDEX = os.getenv("ES_INDEX", "logstash-*")

HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "12"))
VERIFY_SSL     = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
EVENT_TITLE_BOTNET = os.getenv("EVENT_TITLE_BOTNET", "Botnet Infection Attempt (Cowrie)")

SAFE_IPS = [ip.strip() for ip in os.getenv("SAFE_IPS", "").split(",") if ip.strip()]

# Kiểm tra ENV bắt buộc (y như Nmap)
missing = []
for k, v in {"ES_URL": ES_URL, "MISP_URL": MISP_URL, "MISP_KEY": MISP_KEY}.items():
    if not v:
        missing.append(k)
if missing:
    sys.stderr.write(f"[CONFIG ERROR] Missing required env: {', '.join(missing)}\n")
    sys.exit(1)

# ===== Logger (đặt tên và file theo “botnet”) =====
LOG_FILE = os.getenv("LOG_FILE", "botnet_infection_detect.log")
logger = logging.getLogger("botnet-scan-detect")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=1048576, backupCount=3, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)

# ===== Elasticsearch helpers (đơn giản, giống style Nmap) =====
def fetch_sessions_from_es():
    """Truy vấn ES để lấy danh sách src_ip có đăng nhập thành công vào Cowrie trong khoảng lookback."""
    es = Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=HOURS_LOOKBACK)).isoformat()

    body = {
        "_source": ["@timestamp", "src_ip", "source.ip", "eventid", "type", "path"],
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": start}}}],
                "should": [
                    {"term": {"eventid.keyword": "cowrie.login.success"}},
                    {"term": {"type.keyword": "Cowrie"}},
                    {"wildcard": {"path.keyword": "*cowrie*"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "size": 10000,
        "sort": [{"@timestamp": {"order": "desc"}}],
    }

    resp = es.search(index=ES_INDEX, body=body)
    ips = []
    for h in resp.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        ev = (s.get("eventid") or "").lower()
        if ev != "cowrie.login.success":
            # Cho phép lọc rộng bằng should, nhưng chỉ tính login thành công
            continue
        ip = s.get("source.ip") or s.get("src_ip")
        if ip:
            ips.append(str(ip))
    return ips

def detect_bot_sources(ips):
    """Lọc danh sách IP tấn công (duy nhất)."""
    return sorted(set(ips))

# ===== MISP (y hệt Nmap) =====
def create_event(misp: PyMISP, title: str):
    ev = MISPEvent()
    ev.info = title
    ev.distribution = 0
    ev.analysis = 0
    ev.threat_level_id = 2
    res = misp.add_event(ev)
    return str(res["Event"]["id"])

# ===== Main =====
def main():
    ips = fetch_sessions_from_es()
    suspects = [ip for ip in detect_bot_sources(ips) if ip not in SAFE_IPS]

    if not suspects:
        print("[!] Không phát hiện botnet login thành công trong log.")
        return

    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)
    event_id = create_event(misp, EVENT_TITLE_BOTNET)
    print(f"[+] Created Event {event_id} - {EVENT_TITLE_BOTNET}")

    for ip in suspects:
        attr = {
            "type": "ip-src",
            "category": "Network activity",
            "value": ip,
            "to_ids": True,
            "comment": "Detected by Botnet (Cowrie login success) heuristic",
        }
        misp.add_attribute(event_id, attr, pythonify=True)
        logger.info(f"ADD ip-src {ip} to event {event_id}")

    print(f"[+] Done. Added {len(suspects)} attacker IP(s).")

if __name__ == "__main__":
    main()
