#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smoke test cho MISP:
- Kết nối MISP bằng PyMISP
- Tạo 1 Event test (có tag)
- Thêm vài Attribute mẫu (ip-src, domain, url, hash, text)
- (Optional) Xoá event test nếu không muốn giữ
"""

import os
from datetime import datetime
from pymisp import PyMISP, MISPEvent

# ===== Load .env nếu có =====
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ===== ENV =====
MISP_URL  = os.getenv("MISP_URL")            # ví dụ: https://<ip-or-host>/
MISP_KEY  = os.getenv("MISP_KEY")            # API key từ My Profile → Authkeys
VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"

EVENT_TITLE_PREFIX = os.getenv("EVENT_TITLE_PREFIX", "T-Pot IoC Collection")
KEEP_TEST_EVENT = os.getenv("KEEP_TEST_EVENT", "false").lower() == "true"
MISP_TAGS = [t.strip() for t in os.getenv("MISP_TAGS", "source:t-pot,tlp:amber").split(",") if t.strip()]

assert MISP_URL and MISP_KEY, "Thiếu MISP_URL hoặc MISP_KEY trong ENV"

def main():
    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)

    # 1) Tạo Event test
    ev = MISPEvent()
    ev.info = f"[TEST] {EVENT_TITLE_PREFIX} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    ev.distribution = int(os.getenv("MISP_DISTRIBUTION", "0"))  # Your org only (lab)
    ev.analysis = int(os.getenv("MISP_ANALYSIS", "0"))          # Initial
    ev.threat_level_id = int(os.getenv("MISP_THREAT_LEVEL_ID", "2"))  # Medium

    created = misp.add_event(ev, pythonify=True)
    event_id = str(created.id)
    print(f"[+] Created test event: {event_id} | {created.info}")

    # 1.1) Gắn tag cho event
    for t in MISP_TAGS:
        try:
            misp.tag(created.uuid, t)
            print(f"[+] Tagged event with: {t}")
        except Exception as e:
            print(f"[!] Tag failed: {t} -> {e}")

    # 2) Thêm vài Attribute mẫu
    samples = [
        {"type": "ip-src", "category": "Network activity", "to_ids": True,  "value": "45.77.88.12", "comment": "src_ip=45.77.88.12; ts=test"},
        {"type": "domain", "category": "Network activity", "to_ids": True,  "value": "example.com", "comment": "from test script"},
        {"type": "url",    "category": "Network activity", "to_ids": True,  "value": "http://bad.example.com/login", "comment": "from test script"},
        {"type": "md5",    "category": "Payload delivery", "to_ids": True,  "value": "d41d8cd98f00b204e9800998ecf8427e", "comment": "empty md5 test"},
        {"type": "text",   "category": "Other",            "to_ids": False, "value": "admin:123456", "comment": "credential sample"},
    ]
    for attr in samples:
        a = misp.add_attribute(event_id, attr, pythonify=True)
        print(f"[+] Added attribute: {a.type} | {a.value}")

    print("[✓] Smoke test OK!")

    # 3) (Tuỳ chọn) Xoá Event test để không xả rác
    if not KEEP_TEST_EVENT:
        misp.delete_event(event_id)
        print(f"[+] Deleted test event: {event_id}")
    else:
        print(f"[i] KEEP_TEST_EVENT=true -> giữ lại event {event_id}")

if __name__ == "__main__":
    main()
