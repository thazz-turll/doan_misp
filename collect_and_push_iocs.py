#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from dateutil import parser

import pandas as pd
from elasticsearch import Elasticsearch
from pymisp import PyMISP, MISPEvent
import time, random
from requests.exceptions import RequestException
from elasticsearch import TransportError, ConnectionError as ESConnectionError
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from utils import (
    with_retry, first, many, classify_hash, is_non_routable_ip,
    normalize_domain, normalize_url, _fmt_local_ts_for_comment
)

from es_collect import fetch_iocs_from_es, fetch_conn_tuples_from_es

from misp_core import (
    tag_event, get_event_id, push_iocs_to_misp,
    create_nmap_event_and_push, create_ddos_event_and_push
)

from config import (
    # Kết nối
    ES_URL, ES_INDEX, HOURS_LOOKBACK,
    MISP_URL, MISP_KEY, VERIFY_SSL,

    # Thông số event
    EVENT_TITLE_PREFIX, EVENT_TITLE_FORMAT,
    EVENT_DISTRIBUTION, EVENT_ANALYSIS, THREAT_LEVEL_ID, MISP_TAGS,
    EVENT_MODE, MISP_EVENT_ID,                    # ✅ thêm

    # Xử lý IP private
    DISABLE_IDS_FOR_PRIVATE, TAG_PRIVATE_IP_ATTR, PRIVATE_IP_TAG,

    # Detection
    DETECT_NMAP, DETECT_DDOS, NMAP_THRESHOLD, DDOS_THRESHOLD,
    EVENT_TITLE_NMAP, EVENT_TITLE_DDOS,          # ✅ thêm
    SAFE_IPS,

    # Retry cho with_retry
    RETRY_BASE, RETRY_CAP, RETRY_MAX,            # ✅ thêm

    # Logger dùng chung
    logger
)
# ===== Regex/hash/url =====
# Regex nhận diện hash/URL/domain trong log
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA512_RE = re.compile(r"^[a-fA-F0-9]{128}$")


def detect_nmap_scanners(conns, threshold: int):
    """Trả về list IP có số cổng duy nhất >= threshold."""
    if not conns:
        return []
    df = pd.DataFrame(conns, columns=["ip", "port"])
    grouped = df.groupby("ip")["port"].nunique()
    suspects = [ip for ip, cnt in grouped.items() if cnt >= threshold]
    return [ip for ip in suspects if ip not in SAFE_IPS]

def detect_ddos_sources(conns, threshold: int):
    """Trả về list IP có tổng số record >= threshold (dấu hiệu flood)."""
    if not conns:
        return []
    df = pd.DataFrame([c[0] for c in conns], columns=["ip"])
    grouped = df.groupby("ip").size()
    suspects = [ip for ip, cnt in grouped.items() if cnt >= threshold]
    return [ip for ip in suspects if ip not in SAFE_IPS]


# ===== MISP mapping / push =====

def create_single_event_and_push_ips(misp: PyMISP, title: str, ip_list: list[str], comment: str = "") -> str:
    """Tạo event mới với 'title' và add các ip-src; trả về event_id."""
    ev = MISPEvent()
    ev.info            = title
    ev.distribution    = EVENT_DISTRIBUTION
    ev.analysis        = EVENT_ANALYSIS
    ev.threat_level_id = THREAT_LEVEL_ID
    res = with_retry(lambda: misp.add_event(ev), who="misp.add_event_detection")

    event_id = None
    try:
        event_id = res["Event"]["id"]
    except Exception:
        event_id = getattr(res, "id", None)

    event_id = str(event_id)
    for ip in ip_list:
        attr = {
            "type": "ip-src",
            "category": "Network activity",
            "value": ip,
            "to_ids": True,
            "comment": comment or "Detected by heuristic",
        }
        with_retry(lambda: misp.add_attribute(event_id, attr, pythonify=True), who="misp.add_attr_detection")
        logger.info(f"[detect] {title}: ADD ip-src {ip} -> event {event_id}")
    return event_id


def create_daily_event_title():
    """Tạo tiêu đề event theo prefix + EVENT_TITLE_FORMAT (theo giờ local)."""
    ts = datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)
    return f"{EVENT_TITLE_PREFIX} - {ts}"

def _get_ts_suffix_from_daily() -> str:
    return create_daily_event_title().split(" - ", 1)[-1]

# ===== main =====

def main():
    if not VERIFY_SSL:
        logger.warning("MISP SSL verification DISABLED (lab only)")

    # Freeze suffix ngày cho toàn bộ run (đảm bảo Nmap/DDOS trùng ngày với event chính)
    ts_suffix = datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)

    # Override helper để mọi nơi dùng cùng 1 suffix
    def _fixed_suffix() -> str:
        return ts_suffix
    global _get_ts_suffix_from_daily
    _get_ts_suffix_from_daily = _fixed_suffix

    

    # 1) Lấy IoC từ ES
    df = fetch_iocs_from_es()
    total = 0 if df is None or df.empty else len(df)
    logger.info(f"IoC fetched: {total}")
    if df is None or df.empty:
        print("[!] Không có IoC nào trong khoảng thời gian yêu cầu.")

    # 2) Kết nối MISP (dùng chung cho push IoC và detection)
    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)

    # 3) Nếu có IoC thì lấy/tạo event chính + gắn tag + push attribute
    if df is not None and not df.empty:
        event_id = get_event_id(misp, ts_suffix=ts_suffix)
        logger.info(f"Using Event ID: {event_id}")
        print(f"[+] Using Event ID: {event_id}")
        if MISP_TAGS:
            tag_event(misp, event_id, MISP_TAGS)
        added, skipped = push_iocs_to_misp(misp, event_id, df)
        logger.info(f"Done. Added={added} Skipped={skipped} TotalInput={len(df)}")
        print(f"[+] Done. Added: {added}, Skipped: {skipped}, Total input: {len(df)}")

    # 4) Phát hiện Nmap/DDoS → tạo event RIÊNG (đuôi thời gian giống event chính)
    try:
        conns = fetch_conn_tuples_from_es() if (DETECT_NMAP or DETECT_DDOS) else None

        if DETECT_NMAP and conns:
            suspects_nmap = detect_nmap_scanners(misp, suspects_nmap, ts_suffix)
            if suspects_nmap:
                ev_nmap = create_nmap_event_and_push(misp, suspects_nmap)
                print(f"[+] Created Nmap event: {ev_nmap} ({len(suspects_nmap)} IP)")

        if DETECT_DDOS and conns:
            suspects_ddos = detect_ddos_sources(conns, DDOS_THRESHOLD)
            if suspects_ddos:
                ev_ddos = create_ddos_event_and_push(misp, suspects_ddos, ts_suffix)
                print(f"[+] Created DDoS event: {ev_ddos} ({len(suspects_ddos)} IP)")
    except Exception as e:
        logger.error(f"Specialized detections failed: {e}")




if __name__ == "__main__":
    main()
