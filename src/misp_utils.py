#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
misp_utils.py
-------------
Các hàm hỗ trợ tương tác với MISP: tạo event, thêm attribute,
retry an toàn, gắn tag, push IoC.
"""

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

)
from logger import get_logger

logger = get_logger("misp-utils")


def _is_retryable_exc(e):
    """Xác định lỗi tạm thời (nên retry)."""
    # ES errors
    if isinstance(e, (ESConnectionError, TransportError)):
        try:
            status = getattr(e, "status_code", None) or getattr(e, "status", None)
        except Exception:
            status = None
        # retry cho lỗi mạng, 5xx, 429
        if status in (429, 500, 502, 503, 504) or status is None:
            return True
        return False
    # Requests / PyMISP
    if isinstance(e, RequestException):
        # đa phần lỗi mạng tạm thời trong nhóm này → retry
        return True

    # Các Exception khác: cho retry một cách thận trọng
    return False

# Chạy hàm với retry + backoff khi gặp lỗi tạm thời.
def with_retry(func, *, max_attempts=RETRY_MAX, base=RETRY_BASE, cap=RETRY_CAP, who="op"):
    """Chạy func() với exponential backoff/retry cho lỗi tạm thời."""
    attempt = 0
    while True:
        try:
            return func()
        except Exception as e:
            attempt += 1
            if not _is_retryable_exc(e) or attempt >= max_attempts:
                logger.error(f"[{who}] FAILED after {attempt} attempts: {e}")
                raise
            delay = min(cap, base * (2 ** (attempt - 1))) + random.uniform(0, base)
            logger.warning(f"[{who}] attempt {attempt} failed: {e} → retry in {delay:.2f}s")
            time.sleep(delay)


# Thêm attribute vào event MISP với retry an toàn.
def add_attr_safe(misp: PyMISP, event_id: str, a_type: str, value: str,
                  category: str = "Other", comment: str = "", to_ids: bool = False):
    attr = {"type": a_type, "category": category, "value": value,
            "to_ids": to_ids, "comment": comment}
    return with_retry(lambda: misp.add_attribute(event_id, attr, pythonify=True),
                      who="misp.add_attribute_botnet")
                      
# Gắn danh sách tag vào event MISP.
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


# Tạo event mới trên MISP với tiêu đề cho trước.
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

# Tạo event MISP chung, trả về event_id.
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


# Lấy hoặc tạo event chính (theo DAILY hoặc APPEND mode).
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

 # Đẩy IoC từ DataFrame vào event MISP (check trùng, gắn tag).
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


# Tạo event đơn lẻ và đẩy danh sách IP.
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

 # Sinh tiêu đề event theo prefix + ngày.
def create_daily_event_title():
    """Tạo tiêu đề event theo prefix + EVENT_TITLE_FORMAT (theo giờ local)."""
    ts = datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)
    return f"{EVENT_TITLE_PREFIX} - {ts}"

# Lấy hậu tố thời gian (ngày) cho event.
def _get_ts_suffix_from_daily() -> str:
    return create_daily_event_title().split(" - ", 1)[-1]
