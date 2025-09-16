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

from logger import get_logger
logger = get_logger("ioc-es-misp-v3")


from ioc_utils import (
    first, many, classify_hash, is_non_routable_ip,
    normalize_domain, normalize_url, fmt_comment, map_row_to_misp
)


from es_utils import (
    es_client, time_range_clause,
    fetch_iocs_from_es, fetch_conn_tuples_from_es, fetch_cowrie_events
)


import misp_utils as MU  # để override _get_ts_suffix_from_daily
from misp_utils import (
    with_retry, add_attr_safe, tag_event,
    create_event, get_event_id, push_iocs_to_misp,
    create_single_event_and_push_ips, create_daily_event_title
)

ts_suffix = datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)

def _fixed_suffix() -> str:
    return ts_suffix

MU._get_ts_suffix_from_daily = _fixed_suffix



# Lấy timestamp local để chèn vào comment MISP.
def _fmt_local_ts_for_comment() -> str:
    """Trả về timestamp local kiểu 'YYYY-MM-DD HH:MM:SS +07'."""
    d = datetime.now().astimezone()
    tz_raw = d.strftime("%z")  # ví dụ +0700
    tz_short = tz_raw[:3] if tz_raw else ""
    return d.strftime("%Y-%m-%d %H:%M:%S") + (f" {tz_short}" if tz_short else "")
    
# Kiểm tra exception có nên retry không.
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


# Thêm attribute vào event MISP với retry an toàn.

                      
# Gắn danh sách tag vào event MISP.


# ========================
# 3. Fetch dữ liệu từ ES
# ========================



# Lấy (src_ip, dest_port) từ ES để phục vụ Nmap/DDoS.


# ========================
# 4. Kịch bản Nmap & DDoS
# ========================

# Phát hiện IP quét nhiều cổng (nghi vấn Nmap).
def detect_nmap_scanners(conns, threshold: int):
    """Trả về list IP có số cổng duy nhất >= threshold."""
    if not conns:
        return []
    df = pd.DataFrame(conns, columns=["ip", "port"])
    grouped = df.groupby("ip")["port"].nunique()
    suspects = [ip for ip, cnt in grouped.items() if cnt >= threshold]
    return [ip for ip in suspects if ip not in SAFE_IPS]

# Phát hiện IP gửi nhiều kết nối (nghi vấn DDoS).
def detect_ddos_sources(conns, threshold: int):
    """Trả về list IP có tổng số record >= threshold (dấu hiệu flood)."""
    if not conns:
        return []
    df = pd.DataFrame([c[0] for c in conns], columns=["ip"])
    grouped = df.groupby("ip").size()
    suspects = [ip for ip, cnt in grouped.items() if cnt >= threshold]
    return [ip for ip in suspects if ip not in SAFE_IPS]

# Tạo event MISP cho Nmap scan và đẩy IP nguồn.
def create_nmap_event_and_push(misp, ip_list):
    """Tạo event Nmap và push IP (không ghi session vào comment)."""
    title = f"{EVENT_TITLE_NMAP} - {_get_ts_suffix_from_daily()}"
    ev_id = _create_event_with_title(misp, title)
    ts_local = _fmt_local_ts_for_comment()
    for ip in ip_list:
        if ip in SAFE_IPS:
            continue
        # comment chỉ gồm src_ip + ts
        cmt = fmt_comment(ip, None, ts_local)
        add_attr_safe(misp, ev_id, "ip-src", ip, "Network activity", cmt, True)
    return ev_id

# Tạo event MISP cho DDoS và đẩy IP nguồn.
def create_ddos_event_and_push(misp, ip_list):
    """Tạo event DDoS và push IP (không ghi session vào comment)."""
    title = f"{EVENT_TITLE_DDOS} - {_get_ts_suffix_from_daily()}"
    ev_id = _create_event_with_title(misp, title)
    ts_local = _fmt_local_ts_for_comment()
    for ip in ip_list:
        if ip in SAFE_IPS:
            continue
        # comment chỉ gồm src_ip + ts
        cmt = fmt_comment(ip, None, ts_local)
        add_attr_safe(misp, ev_id, "ip-src", ip, "Network activity", cmt, True)
    return ev_id

# ========================
# 5. Kịch bản Botnet / Cowrie
# ========================

# Lấy log Cowrie từ ES (login, command, file download).


# Trích URL từ command input/args của Cowrie.
def extract_urls_from_command(msg, args):
    texts = []
    if isinstance(msg, str): texts.append(msg)
    if isinstance(args, list): texts.extend([str(a) for a in args])
    elif isinstance(args, str): texts.append(args)
    urls = set()
    for t in texts:
        for m in URL_RGX.finditer(t):
            urls.add(m.group("url").strip(";\"' )("))
    return list(urls)

# Chuyển hostname thành IP.
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

# Tải file (giới hạn dung lượng) và tính sha256.
def safe_fetch_sha256(url):
    import requests, hashlib
    try:
        with requests.get(url, timeout=8, stream=True, verify=VERIFY_SSL) as r:
            r.raise_for_status()
            h = hashlib.sha256(); total = 0
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk: continue
                total += len(chunk)
                if total > SAMPLE_MAX_BYTES:
                    get_logger("botnet-detect").warning(
                        f"Sample too large > {SAMPLE_MAX_BYTES} bytes: {url}"
                    )
                    return None
                h.update(chunk)
            return h.hexdigest()
    except Exception as e:
        get_logger("botnet-detect").warning(f"safe_fetch_sha256 failed for {url}: {e}")
        return None

# Gom log Cowrie theo session (src_ip, creds, URL, download).
def correlate_cowrie_sessions(events):
    """Gom theo session, lấy src_ip/creds/URL/download/time đầu tiên."""
    sessions = {}
    for s in events:
        sid = s.get("session")
        if not sid: continue
        o = sessions.setdefault(sid, {"src_ip": None, "username": None, "password": None,
                                      "urls": set(), "downloads": [], "ts_first": None})
        ip = s.get("src_ip") or s.get("source.ip")
        if ip: o["src_ip"] = str(ip)
        ts = s.get("@timestamp")
        if ts and not o["ts_first"]: o["ts_first"] = ts

        ev = (s.get("eventid") or "").lower()
        if ev.endswith("login.success"):
            u = s.get("username") or s.get("user.name")
            p = s.get("password")
            if u: o["username"] = str(u)
            if p: o["password"] = str(p)
            if not o["username"] or not o["password"]:
                m = LOGIN_SUCC_RGX.search(str(s.get("message","")))
                if m:
                    o["username"] = o["username"] or m.group(1)
                    o["password"] = o["password"] or m.group(2)

        if ev.endswith("command.input"):
            for u in extract_urls_from_command(s.get("message"), s.get("args")):
                o["urls"].add(u)

        if ev.endswith("session.file_download"):
            u = s.get("url"); sh = s.get("shasum")
            if u:
                o["downloads"].append({"url": u, "shasum": sh})
                o["urls"].add(u)

    for k in sessions:
        sessions[k]["urls"] = list(sessions[k]["urls"])
    return sessions

# Tạo event MISP cho Botnet/Cowrie và đẩy IoC (IP, creds, URL, hash).
def create_botnet_event_and_push(misp, sessions):
    title = f"{EVENT_TITLE_BOTNET} - {_get_ts_suffix_from_daily()}"
    ev = MISPEvent()
    ev.info = title
    ev.distribution = EVENT_DISTRIBUTION
    ev.analysis = EVENT_ANALYSIS
    ev.threat_level_id = THREAT_LEVEL_ID

    res = with_retry(lambda: misp.add_event(ev), who="misp.add_event_botnet")
    event_id = str(res["Event"]["id"])

    logger = get_logger("botnet-detect")
    logger.info(f"[Botnet] Created MISP event id={event_id} title='{title}'")

    # Gắn tag như event chính (nếu có)
    if MISP_TAGS:
        try:
            tag_event(misp, event_id, MISP_TAGS)
        except Exception as e:
            logger.warning(f"Tag event failed: {e}")

    for sid, info in sessions.items():
        src_ip  = info.get("src_ip")
        if not src_ip or src_ip in SAFE_IPS:
            continue

        user    = info.get("username")
        passwd  = info.get("password")
        urls    = info.get("urls", [])
        dloads  = info.get("downloads", [])
        ts_first = info.get("ts_first")
        cmt = fmt_comment(src_ip, sid, ts_first)

        # ip-src
        add_attr_safe(misp, event_id, "ip-src", src_ip, "Network activity", cmt, True)

        # creds (không to_ids)
        if user or passwd:
            cred_val = f"{user or ''}:{passwd or ''}"
            add_attr_safe(misp, event_id, "text", cred_val, "Other", cmt, False)

        # URL / domain / ip-dst
        for u in urls:
            add_attr_safe(misp, event_id, "url", u, "Payload delivery", cmt, True)
            try:
                p = urlparse(u)
                host = p.hostname
                if host and not IP_HOST_RGX.match(host):
                    add_attr_safe(misp, event_id, "domain", host, "Network activity", cmt, True)
                dst_ip = resolve_ip(host) if host else None
                if dst_ip:
                    add_attr_safe(misp, event_id, "ip-dst", dst_ip, "Network activity", cmt, True)
            except Exception as e:
                logger.warning(f"URL enrich failed for {u}: {e}")

        # hash (ưu tiên shasum)
        for d in dloads:
            u = d.get("url"); sh = d.get("shasum")
            if sh:
                add_attr_safe(misp, event_id, "sha256", sh, "Artifacts dropped", cmt, True)
            elif ALLOW_SAMPLE_FETCH and u:
                h = safe_fetch_sha256(u)
                if h:
                    add_attr_safe(misp, event_id, "sha256", h, "Artifacts dropped", cmt, True)

    return event_id

# ========================
# 6. Mapping & Push IoC
# ========================


# Tạo event đơn lẻ và đẩy danh sách IP.


 # Sinh tiêu đề event theo prefix + ngày.


# Lấy hậu tố thời gian (ngày) cho event.


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



# Lấy hoặc tạo event chính (theo DAILY hoặc APPEND mode).


 # Đẩy IoC từ DataFrame vào event MISP (check trùng, gắn tag).

# ===== main =====

 # Hàm chính: lấy IoC từ ES, tạo event MISP, chạy detection (Nmap/DDoS/Botnet).

def main():
    if not VERIFY_SSL:
        logger.warning("MISP SSL verification DISABLED (lab only)")

    # 0) Cố định hậu tố thời gian cho toàn bộ run
    ts_suffix = datetime.now().astimezone().strftime(EVENT_TITLE_FORMAT)

    # Cho toàn bộ helper dùng CÙNG một suffix (Nmap/DDoS/Botnet)
    def _fixed_suffix() -> str:
        return ts_suffix
    global _get_ts_suffix_from_daily
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
