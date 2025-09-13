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


# Map base (non-hash)
MAPPING_BASE = {
    "ip":        ("ip-src", "Network activity", True),   # to_ids có thể bị override nếu là private
    "domain":    ("domain", "Network activity", True),
    "hostname":  ("hostname", "Network activity", True),
    "url":       ("url",    "Network activity", True),
    "credential":("text",   "Other",            False),  # không đẩy sang IDS
}


# ===== Helpers =====
def tag_event(misp: PyMISP, event_id: str, tags: list[str]):
    """Gắn danh sách tag vào event (best-effort, có retry)."""
    try:
        ev = with_retry(lambda: misp.get_event(event_id, pythonify=True), who="misp.get_event_for_tag")
        event_uuid = getattr(ev, "uuid", None)
        if not event_uuid:
            logger.warning(f"Không lấy được UUID cho event {event_id}, thử gắn theo ID.")
            event_uuid = event_id  # fallback
        for t in tags:
            try:
                with_retry(lambda: misp.tag(event_uuid, t), who="misp.tag_event")
                logger.info(f"TAG event {event_uuid} with '{t}'")
            except Exception as e:
                logger.error(f"Gắn tag '{t}' vào event {event_uuid} thất bại: {e}")
    except Exception as e:
        logger.error(f"get_event({event_id}) để gắn tag thất bại: {e}")



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

def map_row_to_misp(row):
    """Map 1 dòng IoC → tuple attribute cho MISP (type, category, to_ids, value, comment, is_private)."""
    ioc_type = str(row.get("ioc_type", "")).strip().lower()
    value    = str(row.get("value", "")).strip()
    if not value:
        return None

    ts_str = str(row.get("timestamp", "")).strip()
    ts_local_str = ts_str
    if ts_str:
        try:
            dt = parser.isoparse(ts_str)
            # Chỉ gán UTC nếu thiếu thông tin timezone
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            # Đổi sang giờ local của server
            ts_local_str = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        except Exception:
            pass

    src = str(row.get("src_ip", "")).strip()
    comment_parts = []
    if src:
        comment_parts.append(f"src_ip={src}")
    if ts_local_str:
        comment_parts.append(f"ts={ts_local_str}")
    comment = "; ".join(comment_parts)

    # Hash
    if ioc_type == "hash":
        htype = classify_hash(value)
        if not htype:
            return None
        return (htype, "Payload delivery", True, value, comment, False)

    # IP
    elif ioc_type == "ip":
        is_private = is_non_routable_ip(value)
        to_ids = not (DISABLE_IDS_FOR_PRIVATE and is_private)
        if is_private:
            comment = (comment + "; non-routable") if comment else "non-routable"
        return ("ip-src", "Network activity", to_ids, value, comment, is_private)

    # Domain / URL / Hostname
    elif ioc_type in ("domain", "url", "hostname"):
        misp_type, category, to_ids = MAPPING_BASE[ioc_type]
        return (misp_type, category, to_ids, value, comment, False)

    # Credential
    elif ioc_type == "credential":
        misp_type, category, to_ids = MAPPING_BASE[ioc_type]
        return (misp_type, category, to_ids, value, comment, False)

    else:
        return None

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

def _create_event_with_title(misp: PyMISP, title: str) -> str:
    ev = MISPEvent()
    ev.info = title
    ev.distribution = EVENT_DISTRIBUTION
    ev.analysis = EVENT_ANALYSIS
    ev.threat_level_id = THREAT_LEVEL_ID
    res = with_retry(lambda: misp.add_event(ev), who="misp.add_event_detection")
    try:
        ev_id = res["Event"]["id"]
    except Exception:
        ev_id = getattr(res, "id", None)
    ev_id = str(ev_id)
    if MISP_TAGS:
        tag_event(misp, ev_id, MISP_TAGS)
    return ev_id

def create_nmap_event_and_push(misp: PyMISP, ip_list: list[str]) -> str:
    title = f"{EVENT_TITLE_NMAP} - {_get_ts_suffix_from_daily()}"
    ev_id = _create_event_with_title(misp, title)
    ts_local = _fmt_local_ts_for_comment()
    for ip in ip_list:
        comment = f"src_ip={ip}; ts={ts_local}; detection=NmapScan"
        attr = {"type":"ip-src","category":"Network activity","value":ip,"to_ids":True,"comment":comment}
        with_retry(lambda: misp.add_attribute(ev_id, attr, pythonify=True), who="misp.add_attr_detection")
        logger.info(f"[detect] {title}: ADD ip-src {ip} -> event {ev_id} (comment='{comment}')")
    return ev_id


def create_ddos_event_and_push(misp: PyMISP, ip_list: list[str]) -> str:
    title = f"{EVENT_TITLE_DDOS} - {_get_ts_suffix_from_daily()}"
    ev_id = _create_event_with_title(misp, title)
    ts_local = _fmt_local_ts_for_comment()
    for ip in ip_list:
        comment = f"src_ip={ip}; ts={ts_local}; detection=DDOSFlood"
        attr = {"type":"ip-src","category":"Network activity","value":ip,"to_ids":True,"comment":comment}
        with_retry(lambda: misp.add_attribute(ev_id, attr, pythonify=True), who="misp.add_attr_detection")
        logger.info(f"[detect] {title}: ADD ip-src {ip} -> event {ev_id} (comment='{comment}')")
    return ev_id



def create_event(misp: PyMISP, title: str) -> str:
    """Tạo MISP Event mới và trả về event_id."""
    ev = MISPEvent()
    ev.info            = title
    ev.distribution    = EVENT_DISTRIBUTION
    ev.analysis        = EVENT_ANALYSIS
    ev.threat_level_id = THREAT_LEVEL_ID

    res = with_retry(lambda: misp.add_event(ev), who="misp.add_event")

    # Lấy event_id đúng cách
    event_id = None
    try:
        event_id = res["Event"]["id"]
    except Exception:
        event_id = getattr(res, "id", None) or getattr(getattr(res, "Event", None), "id", None)

    if not event_id:
        raise RuntimeError(f"Cannot create MISP event, unexpected response: {type(res)} {res}")

    return str(event_id)



def get_event_id(misp: PyMISP, ts_suffix: str | None = None):
    suffix = ts_suffix or datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)
    today_title = f"{EVENT_TITLE_PREFIX} - {suffix}"

    if EVENT_MODE == "APPEND":
        if not MISP_EVENT_ID:
            raise ValueError("EVENT_MODE=APPEND nhưng thiếu MISP_EVENT_ID")
        ev = with_retry(lambda: misp.get_event(MISP_EVENT_ID), who="misp.get_event")
        if not ev or ("Event" not in ev and not getattr(ev, "id", None)):
            raise ValueError(f"MISP_EVENT_ID={MISP_EVENT_ID} không tồn tại/không truy cập được")
        return MISP_EVENT_ID

    if EVENT_MODE == "DAILY":
        try:
            # ✅ Tìm theo tiêu đề Event (eventinfo), metadata nhanh hơn
            # Cách 1: dùng search_index (nhanh)
            idx = with_retry(
                lambda: misp.search_index(eventinfo=today_title), 
                who="misp.search_index_event"
            )
            # idx là list dict; lọc đúng tiêu đề
            for it in idx or []:
                if it.get('info') == today_title:
                    return str(it.get('id'))

            # Cách 2 (fallback): search controller='events' + eventinfo, pythonify=True
            search_result = with_retry(
                lambda: misp.search(controller='events', eventinfo=today_title, metadata=True, pythonify=True),
                who="misp.search_event_by_eventinfo"
            )
            if search_result:
                # Lọc đúng info (tránh match mơ hồ)
                for ev in search_result:
                    if getattr(ev, "info", "") == today_title:
                        return str(ev.id)
        except Exception as e:
            logger.warning(f"Tìm event DAILY bị lỗi: {e}")

        # Không tìm thấy → tạo mới
        return create_event(misp, today_title)

    raise ValueError(f"EVENT_MODE={EVENT_MODE} không hợp lệ")



def push_iocs_to_misp(misp: PyMISP, event_id: str, df: pd.DataFrame):
    """Đẩy các IoC trong DataFrame vào MISP Event (check trùng, tag IP private nếu cấu hình)."""
    existing = set()
    try:
        ev = with_retry(lambda: misp.get_event(event_id, pythonify=True), who="misp.get_event_for_attrs")
        for a in getattr(ev, "attributes", []) or []:
            existing.add((a.type, a.value))
    except Exception as e:
        logger.warning(f"get_event attributes failed: {e}")

    added, skipped = 0, 0
    for _, row in df.iterrows():
        mapped = map_row_to_misp(row)
        if not mapped:
            skipped += 1
            continue
        misp_type, category, to_ids, value, comment, is_private = mapped
        key = (misp_type, value)
        if key in existing:
            skipped += 1
            continue

        attr = {"type": misp_type, "category": category, "value": value, "to_ids": to_ids, "comment": comment}
        
        try:
            def _add():
                return misp.add_attribute(event_id, attr, pythonify=True)

            aobj = with_retry(_add, who="misp.add_attribute")
            added += 1
            existing.add(key)
            logger.info(f"ADD {misp_type} value={value} to_ids={to_ids} comment='{comment}'")
            if TAG_PRIVATE_IP_ATTR and is_private and getattr(aobj, "uuid", None):
                try:
                    with_retry(lambda: misp.tag(aobj.uuid, PRIVATE_IP_TAG), who="misp.tag_attr")
                    logger.info(f"TAG attribute {aobj.uuid} with {PRIVATE_IP_TAG}")
                except Exception:
                    pass
                    
        except Exception as e:
               msg = str(e).lower()
               if "already exists" in msg or "409" in msg:
                  skipped += 1
                  existing.add(key)
                  logger.info(f"SKIP duplicate (server said exists): {key}")
               else:
                   skipped += 1
                   logger.error(f"add_attribute failed: type={misp_type} value={value} err={e}")

    return added, skipped


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
            suspects_nmap = detect_nmap_scanners(conns, NMAP_THRESHOLD)
            if suspects_nmap:
                ev_nmap = create_nmap_event_and_push(misp, suspects_nmap)
                print(f"[+] Created Nmap event: {ev_nmap} ({len(suspects_nmap)} IP)")

        if DETECT_DDOS and conns:
            suspects_ddos = detect_ddos_sources(conns, DDOS_THRESHOLD)
            if suspects_ddos:
                ev_ddos = create_ddos_event_and_push(misp, suspects_ddos)
                print(f"[+] Created DDoS event: {ev_ddos} ({len(suspects_ddos)} IP)")
    except Exception as e:
        logger.error(f"Specialized detections failed: {e}")




if __name__ == "__main__":
    main()
