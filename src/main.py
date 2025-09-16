#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===============================================================
#  T-Pot → Elasticsearch → MISP: Thu thập IoC + phát hiện Nmap/DDoS/Cowrie
#  Phiên bản: "reorganized-with-notes"
#  Lưu ý quan trọng:
#   - Chỉ sắp xếp lại vị trí các phần/hàm và bổ sung chú thích.
#   - Không thay đổi logic hay nội dung lệnh trong thân hàm.
#   - Các comment (# ...) được thêm để giải thích vai trò từng phần.
# ===============================================================

# -----------------------------
# 1) IMPORTS & THƯ VIỆN
# -----------------------------
import os
import re
import sys
import socket
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

from config import (
    # bắt buộc
    ES_URL, MISP_URL, MISP_KEY,
    # tùy chọn
    ES_INDEX, HOURS_LOOKBACK,
    VERIFY_SSL, EVENT_MODE, MISP_EVENT_ID,
    EVENT_TITLE_PREFIX, EVENT_TITLE_FORMAT,
    EVENT_DISTRIBUTION, EVENT_ANALYSIS, THREAT_LEVEL_ID,
    MISP_TAGS,
    DISABLE_IDS_FOR_PRIVATE, TAG_PRIVATE_IP_ATTR, PRIVATE_IP_TAG,
    # logging
    LOG_FILE, LOG_MAX_BYTES, LOG_BACKUPS,
    # retry
    RETRY_BASE, RETRY_CAP, RETRY_MAX,
    # detection flags
    ALLOW_SAMPLE_FETCH, SAMPLE_MAX_BYTES,
    DETECT_NMAP, DETECT_DDOS, DETECT_BOTNET,
    NMAP_THRESHOLD, DDOS_THRESHOLD,
    EVENT_TITLE_NMAP, EVENT_TITLE_DDOS, EVENT_TITLE_BOTNET,
    SAFE_IPS,
    # ES fields
    ES_SOURCE_FIELDS,
    # regex
    MD5_RE, SHA1_RE, SHA256_RE, SHA512_RE,
    URL_RGX, LOGIN_SUCC_RGX, IP_HOST_RGX,
    LABELED_HASH_RE, BARE_HASH_RE, URL_RE,
    DOMAIN_RE,
    # mapping
    MAPPING_BASE
)
logger = logging.getLogger("ioc-es-misp-v3")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)


from ioc_utils import (
    first, many, classify_hash, is_non_routable_ip,
    normalize_domain, normalize_url, fmt_comment, map_row_to_misp
)


from es_utils import (
    es_client, time_range_clause,
    fetch_iocs_from_es, fetch_conn_tuples_from_es, fetch_cowrie_events
)

from misp_utils import (
    with_retry, add_attr_safe, tag_event,
    create_event, get_event_id, push_iocs_to_misp,
    create_single_event_and_push_ips, create_daily_event_title, _get_ts_suffix_from_daily
)

from nmap import (
     detect_nmap_scanners, create_nmap_event_and_push
)
from ddos import (
     detect_ddos_sources, create_ddos_event_and_push
)
from botnet import (
     correlate_cowrie_sessions,
     create_botnet_event_and_push
)
 # Hàm chính: lấy IoC từ ES, tạo event MISP, chạy detection (Nmap/DDoS/Botnet).

def main():
    if not VERIFY_SSL:
        logger.warning("MISP SSL verification DISABLED (lab only)")

    # 0) Cố định hậu tố thời gian cho toàn bộ run
    ts_suffix = datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)

    # Cho toàn bộ helper dùng CÙNG một suffix (Nmap/DDoS/Botnet)
    def _fixed_suffix() -> str:
        return ts_suffix
    _get_ts_suffix_from_daily = _fixed_suffix

    # 1) Lấy IoC từ ES (dùng để push vào event chính)
    df = fetch_iocs_from_es()
    total = 0 if df is None or df.empty else len(df)
    logger.info(f"IoC fetched: {total}")
    if df is None or df.empty:
        print("[!] Không có IoC nào trong khoảng thời gian yêu cầu.")
    

    # 2) Kết nối MISP (dùng chung cho push IoC và các detection)
    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)

    # 3) Nếu có IoC thì lấy/tạo event chính + gắn tag + push attribute
    if df is not None and not df.empty:
        event_id = get_event_id(misp, ts_suffix=ts_suffix)
        logger.info(f"Using Event ID: {event_id}")
        print(f"[+] Using Event ID: {event_id}")
        if MISP_TAGS:
            try:
                tag_event(misp, event_id, MISP_TAGS)
            except Exception as e:
                logger.warning(f"Tag event failed: {e}")
        try:
            added, skipped = push_iocs_to_misp(misp, event_id, df)
            logger.info(f"Done. Added={added} Skipped={skipped} TotalInput={len(df)}")
            print(f"[+] Done. Added: {added}, Skipped: {skipped}, Total input: {len(df)}")
        except Exception as e:
            logger.error(f"Push IoC failed: {e}")

    # 4) Các phát hiện chuyên biệt → tạo event RIÊNG (Nmap/DDoS/Botnet)
    try:
        # 4.1) Nmap & DDoS dựa trên kết nối (nếu bật)
        conns = fetch_conn_tuples_from_es() if (DETECT_NMAP or DETECT_DDOS) else None

        # Trước khi tạo các event Nmap/DDoS, cố gắng lấy sessions từ Cowrie để map IP->session
        sessions = {}
        ip2sess = {}
        if DETECT_BOTNET:
            try:
                cowrie_events = fetch_cowrie_events()
                if cowrie_events:
                    sessions = correlate_cowrie_sessions(cowrie_events)
                else:
                    logger.info("[Botnet] Không lấy được cowrie events (rỗng).")
            except Exception as e:
                logger.warning(f"[Botnet] Lấy sessions từ Cowrie thất bại: {e}")

        # NMAP
        if DETECT_NMAP and conns:
            try:
                suspects_nmap = detect_nmap_scanners(conns, NMAP_THRESHOLD)
                if suspects_nmap:
                    # truyền ip2sess để comment có session nếu có
                    ev_nmap = create_nmap_event_and_push(misp, suspects_nmap)
                    print(f"[+] Created Nmap event: {ev_nmap} ({len(suspects_nmap)} IP)")
            except Exception as e:
                logger.error(f"Nmap detection failed: {e}")

        # DDOS
        if DETECT_DDOS and conns:
            try:
                suspects_ddos = detect_ddos_sources(conns, DDOS_THRESHOLD)
                if suspects_ddos:
                    ev_ddos = create_ddos_event_and_push(misp, suspects_ddos)
                    print(f"[+] Created DDoS event: {ev_ddos} ({len(suspects_ddos)} IP)")
            except Exception as e:
                logger.error(f"DDoS detection failed: {e}")

        # 4.2) Botnet/Cowrie (login thành công + có URL/file download)
        if DETECT_BOTNET:
            try:
                # nếu chưa có sessions từ trên, lấy bây giờ
                if not sessions:
                    cowrie_events = fetch_cowrie_events()
                    sessions = correlate_cowrie_sessions(cowrie_events) if cowrie_events else {}

                # Lọc nghi vấn: có IP nguồn (không nằm SAFE_IPS), có creds, và có URL/download
                suspicious = {}
                for sid, info in sessions.items():
                    ip = info.get("src_ip")
                    if not ip or ip in SAFE_IPS:
                        continue
                    if not (info.get("username") or info.get("password")):
                        continue
                    if not (info.get("urls") or info.get("downloads")):
                        continue
                    suspicious[sid] = info

                if suspicious:
                    ev_bot = create_botnet_event_and_push(misp, suspicious)
                    print(f"[+] Created Botnet event: {ev_bot} ({len(suspicious)} session)")
                else:
                    print("[Botnet] Không có session login thành công kèm URL/download.")
            except Exception as e:
                logger.error(f"Botnet detection failed: {e}")

    except Exception as e:
        logger.error(f"Specialized detections failed: {e}")


if __name__ == "__main__":
    main()
