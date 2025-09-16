#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
main.py
-------
Orchestrator chính:
- Lấy IoC từ Elasticsearch
- Tạo / lấy Event chính trên MISP và push IoC
- Chạy các kịch bản detection (Nmap, DDoS, Botnet) tùy cấu hình
"""

from datetime import datetime
from pymisp import PyMISP

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
from logger import get_logger

# utils modules (khung bạn đã tạo)
import es_utils
import ioc_utils
import misp_utils

# detection modules (khung)
import nmap
import ddos
import botnet

logger = get_logger("main")


def _override_detection_suffix(suffix: str):
    """
    Gán một _get_ts_suffix_from_daily cố định cho các module detection
    (nếu module có định nghĩa _get_ts_suffix_from_daily).
    """
    def fixed():
        return suffix

    for mod in (nmap, ddos, botnet):
        if hasattr(mod, "_get_ts_suffix_from_daily"):
            try:
                setattr(mod, "_get_ts_suffix_from_daily", fixed)
                logger.debug(f"Overrode _get_ts_suffix_from_daily for module {mod.__name__}")
            except Exception as e:
                logger.warning(f"Cannot override suffix for {mod.__name__}: {e}")


def main():
    logger.info("=== Starting ioc-collector run ===")

    # 0) chuẩn bị suffix thời gian cố định cho cả run
    ts_suffix = datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)
    _override_detection_suffix(ts_suffix)

    # 1) Lấy IoC từ Elasticsearch
    try:
        df = es_utils.fetch_iocs_from_es()
        total = 0 if df is None or df.empty else len(df)
        logger.info(f"IoC fetched: {total}")
        if df is None or df.empty:
            print("[!] Không có IoC nào trong khoảng thời gian yêu cầu.")
    except Exception as e:
        logger.error(f"Failed fetching IoC from ES: {e}", exc_info=True)
        df = None

    # 2) Kết nối tới MISP
    try:
        misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)
    except Exception as e:
        logger.error(f"Failed to initialize PyMISP: {e}", exc_info=True)
        raise

    # 3) Nếu có IoC -> get/create event chính + push IoCs
    if df is not None and not df.empty:
        try:
            event_id = misp_utils.get_event_id(misp, ts_suffix=ts_suffix)
            logger.info(f"Using Event ID: {event_id}")
            print(f"[+] Using Event ID: {event_id}")
            if hasattr(misp_utils, "tag_event") and getattr(misp_utils, "MISP_TAGS", None) is None:
                # tag_event expects (misp, event_id, tags) — if you keep tags in config it will be called inside get/create
                pass
            added, skipped = misp_utils.push_iocs_to_misp(misp, event_id, df)
            logger.info(f"Done pushing IoCs. Added={added} Skipped={skipped} TotalInput={len(df)}")
            print(f"[+] Done. Added: {added}, Skipped: {skipped}, Total input: {len(df)}")
        except Exception as e:
            logger.error(f"Push IoC failed: {e}", exc_info=True)

    # 4) Các detection chuyên biệt → tạo event RIÊNG (Nmap/DDoS/Botnet)
    try:
        # 4.1) Nmap & DDoS dựa trên kết nối (nếu bật)
        conns = es_utils.fetch_conn_tuples_from_es() if (DETECT_NMAP or DETECT_DDOS) else None

        # Trước khi tạo các event Nmap/DDoS, cố gắng lấy sessions từ Cowrie để map IP->session
        sessions = {}
        if DETECT_BOTNET:
            try:
                cowrie_events = es_utils.fetch_cowrie_events()
                if cowrie_events:
                    sessions = botnet.correlate_cowrie_sessions(cowrie_events)
                else:
                    logger.info("[Botnet] No cowrie events returned.")
            except Exception as e:
                logger.warning(f"[Botnet] Fetching/correlating cowrie events failed: {e}", exc_info=True)

        # NMAP detection
        if DETECT_NMAP and conns:
            try:
                suspects_nmap = nmap.detect_nmap_scanners(conns, threshold=None)  # replace None with config threshold inside nmap.detect or pass from config
                if suspects_nmap:
                    ev_nmap = nmap.create_nmap_event_and_push(misp, suspects_nmap)
                    print(f"[+] Created Nmap event: {ev_nmap} ({len(suspects_nmap)} IP)")
            except Exception as e:
                logger.error(f"Nmap detection failed: {e}", exc_info=True)

        # DDOS detection
        if DETECT_DDOS and conns:
            try:
                suspects_ddos = ddos.detect_ddos_sources(conns, threshold=None)  # same note about threshold
                if suspects_ddos:
                    ev_ddos = ddos.create_ddos_event_and_push(misp, suspects_ddos)
                    print(f"[+] Created DDoS event: {ev_ddos} ({len(suspects_ddos)} IP)")
            except Exception as e:
                logger.error(f"DDoS detection failed: {e}", exc_info=True)

        # BOTNET / COWRIE detection
        if DETECT_BOTNET:
            try:
                # if sessions empty, re-fetch
                if not sessions:
                    cowrie_events = es_utils.fetch_cowrie_events()
                    sessions = botnet.correlate_cowrie_sessions(cowrie_events) if cowrie_events else {}

                # Lọc nghi vấn: có IP nguồn, có creds và có URL/download
                suspicious = {}
                for sid, info in sessions.items():
                    ip = info.get("src_ip")
                    if not ip:
                        continue
                    # bạn có SAFE_IPS logic ở config; here we rely on botnet.create to filter
                    if not (info.get("username") or info.get("password")):
                        continue
                    if not (info.get("urls") or info.get("downloads")):
                        continue
                    suspicious[sid] = info

                if suspicious:
                    ev_bot = botnet.create_botnet_event_and_push(misp, suspicious)
                    print(f"[+] Created Botnet event: {ev_bot} ({len(suspicious)} session)")
                else:
                    print("[Botnet] No suspicious cowrie sessions (login + URL/download).")
            except Exception as e:
                logger.error(f"Botnet detection failed: {e}", exc_info=True)

    except Exception as e:
        logger.error(f"Specialized detections failed overall: {e}", exc_info=True)

    logger.info("=== Run finished ===")


if __name__ == "__main__":
    main()
