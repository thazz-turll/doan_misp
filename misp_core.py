# misp_core.py
from __future__ import annotations
from typing import List, Tuple, Optional
import pandas as pd
from pymisp import PyMISP, MISPEvent
from dateutil import parser
from datetime import datetime, timezone

from config import (
    EVENT_DISTRIBUTION, EVENT_ANALYSIS, THREAT_LEVEL_ID, MISP_TAGS,
    EVENT_MODE, MISP_EVENT_ID, EVENT_TITLE_PREFIX, EVENT_TITLE_FORMAT,
    DISABLE_IDS_FOR_PRIVATE, TAG_PRIVATE_IP_ATTR, PRIVATE_IP_TAG,
    EVENT_TITLE_NMAP, EVENT_TITLE_DDOS, logger
)
from utils import with_retry, classify_hash, is_non_routable_ip, fmt_local_ts_for_comment

# Map base (non-hash)
MAPPING_BASE = {
    "ip":        ("ip-src", "Network activity", True),   # to_ids có thể override nếu là private
    "domain":    ("domain", "Network activity", True),
    "hostname":  ("hostname", "Network activity", True),
    "url":       ("url",    "Network activity", True),
    "credential":("text",   "Other",            False),  # không đẩy sang IDS
}

# ---------- Helpers về tiêu đề ----------
def _today_suffix() -> str:
    return datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)

def build_daily_title(suffix: Optional[str] = None) -> str:
    """Tạo tiêu đề event chính dạng '<prefix> - <YYYY-mm-dd>'."""
    return f"{EVENT_TITLE_PREFIX} - {(suffix or _today_suffix())}"

# ---------- Tag event ----------
def tag_event(misp: PyMISP, event_id: str, tags: List[str]):
    try:
        ev = with_retry(lambda: misp.get_event(event_id, pythonify=True), who="misp.get_event_for_tag")
        event_uuid = getattr(ev, "uuid", None) or event_id
        for t in tags:
            with_retry(lambda: misp.tag(event_uuid, t), who="misp.tag_event")
            logger.info(f"TAG event {event_uuid} with '{t}'")
    except Exception as e:
        logger.error(f"tag_event failed: {e}")

# ---------- Create / get event ----------
def create_event(misp: PyMISP, title: str) -> str:
    ev = MISPEvent()
    ev.info = title
    ev.distribution = EVENT_DISTRIBUTION
    ev.analysis = EVENT_ANALYSIS
    ev.threat_level_id = THREAT_LEVEL_ID
    res = with_retry(lambda: misp.add_event(ev), who="misp.add_event")
    try:
        ev_id = res["Event"]["id"]
    except Exception:
        ev_id = getattr(res, "id", None)
    if not ev_id:
        raise RuntimeError(f"Cannot create MISP event, resp={res}")
    ev_id = str(ev_id)
    if MISP_TAGS:
        tag_event(misp, ev_id, MISP_TAGS)
    return ev_id

def get_event_id(misp: PyMISP, ts_suffix: Optional[str] = None) -> str:
    """Lấy/tạo event 'chính' theo EVENT_MODE (DAILY/APPEND)."""
    if EVENT_MODE == "APPEND":
        if not MISP_EVENT_ID:
            raise ValueError("EVENT_MODE=APPEND nhưng thiếu MISP_EVENT_ID")
        ev = with_retry(lambda: misp.get_event(MISP_EVENT_ID), who="misp.get_event")
        if not ev or ("Event" not in ev and not getattr(ev, "id", None)):
            raise ValueError(f"MISP_EVENT_ID={MISP_EVENT_ID} không tồn tại/không truy cập được")
        return MISP_EVENT_ID

    # DAILY
    title = build_daily_title(ts_suffix)
    try:
        idx = with_retry(lambda: misp.search_index(eventinfo=title), who="misp.search_index_event")
        for it in idx or []:
            if it.get("info") == title:
                return str(it.get("id"))
        res = with_retry(lambda: misp.search(controller="events", eventinfo=title, metadata=True, pythonify=True),
                         who="misp.search_event_by_eventinfo")
        if res:
            for ev in res:
                if getattr(ev, "info", "") == title:
                    return str(ev.id)
    except Exception as e:
        logger.warning(f"Tìm event DAILY bị lỗi: {e}")

    return create_event(misp, title)

# ---------- Map 1 IoC row -> attribute ----------
def map_row_to_misp(row):
    """Trả về (type, category, to_ids, value, comment, is_private) hoặc None."""
    ioc_type = str(row.get("ioc_type", "")).strip().lower()
    value    = str(row.get("value", "")).strip()
    if not value:
        return None

    ts_str = str(row.get("timestamp", "")).strip()
    ts_local_str = ts_str
    if ts_str:
        try:
            dt = parser.isoparse(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
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
    if ioc_type == "ip":
        is_private = is_non_routable_ip(value)
        to_ids = not (DISABLE_IDS_FOR_PRIVATE and is_private)
        if is_private:
            comment = (comment + "; non-routable") if comment else "non-routable"
        return ("ip-src", "Network activity", to_ids, value, comment, is_private)

    # Domain / URL / Hostname
    if ioc_type in ("domain", "url", "hostname"):
        misp_type, category, to_ids = MAPPING_BASE[ioc_type]
        return (misp_type, category, to_ids, value, comment, False)

    # Credential
    if ioc_type == "credential":
        misp_type, category, to_ids = MAPPING_BASE[ioc_type]
        return (misp_type, category, to_ids, value, comment, False)

    return None

# ---------- Push IoC dataframe ----------
def push_iocs_to_misp(misp: PyMISP, event_id: str, df: pd.DataFrame):
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
            aobj = with_retry(lambda: misp.add_attribute(event_id, attr, pythonify=True), who="misp.add_attribute")
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

# ---------- Event phát hiện (Nmap/DDoS) ----------
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

def create_nmap_event_and_push(misp: PyMISP, ip_list: List[str], ts_suffix: Optional[str] = None) -> str:
    """Tạo event Nmap có hậu tố ngày; nếu không truyền ts_suffix sẽ dùng ngày hiện tại."""
    if not ip_list:
        return ""
    title = f"{EVENT_TITLE_NMAP} - {(ts_suffix or _today_suffix())}"
    ev_id = _create_event_with_title(misp, title)
    ts_local = fmt_local_ts_for_comment()
    for ip in ip_list:
        comment = f"src_ip={ip}; ts={ts_local}; detection=NmapScan"
        attr = {"type": "ip-src", "category": "Network activity", "value": ip, "to_ids": True, "comment": comment}
        with_retry(lambda: misp.add_attribute(ev_id, attr, pythonify=True), who="misp.add_attr_detection_nmap")
        logger.info(f"[detect] {title}: ADD ip-src {ip} -> event {ev_id}")
    return ev_id

def create_ddos_event_and_push(misp: PyMISP, ip_list: List[str], ts_suffix: Optional[str] = None) -> str:
    """Tạo event DDoS có hậu tố ngày; nếu không truyền ts_suffix sẽ dùng ngày hiện tại."""
    if not ip_list:
        return ""
    title = f"{EVENT_TITLE_DDOS} - {(ts_suffix or _today_suffix())}"
    ev_id = _create_event_with_title(misp, title)
    ts_local = fmt_local_ts_for_comment()
    for ip in ip_list:
        comment = f"src_ip={ip}; ts={ts_local}; detection=DDOSFlood"
        attr = {"type": "ip-src", "category": "Network activity", "value": ip, "to_ids": True, "comment": comment}
        with_retry(lambda: misp.add_attribute(ev_id, attr, pythonify=True), who="misp.add_attr_detection_ddos")
        logger.info(f"[detect] {title}: ADD ip-src {ip} -> event {ev_id}")
    return ev_id
