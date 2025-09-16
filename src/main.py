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

# -----------------------------
# 3) LOGGER XOAY VÒNG
# -----------------------------
logger = logging.getLogger("ioc-es-misp-v3")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)

# ========================
# 2. Helpers chung
# ========================

 # Tạo Elasticsearch client với cấu hình từ ENV.
def es_client():
    return Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)

# Sinh range query theo @timestamp cho số giờ lookback.
def time_range_clause(hours: int):
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=hours)).isoformat()
    return {"range": {"@timestamp": {"gte": start}}}

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

# Trả về phần tử đầu nếu là list, ngược lại trả v.
def first(v):
    """Lấy phần tử đầu nếu v là list, ngược lại trả về v."""
    if isinstance(v, list) and v:
        return v[0]
    return v

# Bọc giá trị đơn thành list.
def many(v):
    """Đảm bảo giá trị là list (bọc đơn thành list)."""
    if isinstance(v, list):
        return v
    return [v] if v is not None else []

# Phân loại hash theo độ dài (md5/sha1/sha256/sha512).
def classify_hash(h: str):
    """Phân loại hash theo độ dài: md5/sha1/sha256/sha512, không khớp → None."""
    if not isinstance(h, str):
        return None
    v = h.strip()
    if MD5_RE.fullmatch(v): return "md5"
    if SHA1_RE.fullmatch(v): return "sha1"
    if SHA256_RE.fullmatch(v): return "sha256"
    if SHA512_RE.fullmatch(v): return "sha512"
    return None

# Kiểm tra IP có thuộc nhóm private/non-routable không.
def is_non_routable_ip(ip_str: str) -> bool:
    """Kiểm tra IP có phải non-routable/private/loopback..."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or getattr(ip_obj, "is_site_local", False)
        or getattr(ip_obj, "is_global", None) is False
    )
    
 # Chuẩn hóa domain/hostname (lowercase, bỏ dấu chấm cuối).
def normalize_domain(d: str) -> str:
    """Chuẩn hóa domain/hostname (lower, bỏ dấu chấm cuối)."""
    d = str(d or "").strip().lower()
    return d[:-1] if d.endswith(".") else d
    
# Chuẩn hóa URL (lowercase netloc, giữ nguyên phần còn lại).
def normalize_url(u: str) -> str:
    """Chuẩn hóa URL (lower netloc, giữ nguyên scheme/path/query)."""
    u = str(u or "").strip()
    try:
        p = urlparse(u)
        netloc = p.netloc.lower()
        return f"{p.scheme}://{netloc}{p.path or ''}{('?' + p.query) if p.query else ''}"
    except Exception:
        return u

# Sinh comment mô tả IoC (src_ip, session, timestamp).
def fmt_comment(src_ip: str, session_id: str | None, ts_first: str | None) -> str:
    parts = []
    if src_ip: parts.append(f"src_ip={src_ip}")
    if session_id: parts.append(f"session={session_id}")
    if ts_first:
        try:
            dt = parser.isoparse(ts_first)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            parts.append("ts=" + dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"))
        except Exception:
            parts.append(f"ts={ts_first}")
    return "; ".join(parts)

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


# ========================
# 3. Fetch dữ liệu từ ES
# ========================

# Truy vấn ES và trích xuất IoC (IP, URL, domain, hash, credential).
def fetch_iocs_from_es():
    """Truy vấn ES, trích IoC (dedupe), trả về DataFrame(các IoC)."""
    # ES client
    es = Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)
    esq = es.options(request_timeout=60)
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=HOURS_LOOKBACK)).isoformat()
    base_query = {
        "_source": ES_SOURCE_FIELDS,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"range": {"@timestamp": {"gte": start}}}
    }
    page_size = 3000
    search_after = None
    # Dedupe sớm theo (ioc_type, value)
    seen = set()    # {(type, value)}
    rows = []       # list[dict]
    def add_row(ts, src_ip, typ, val):
        """Thêm 1 IoC vào rows nếu chưa thấy trước đó."""
        if not typ or not val:
            return
        key = (typ, val)
        if key in seen:
            return
        seen.add(key)
        rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": typ, "value": val})
    while True:
        body = dict(base_query)
        body["size"] = page_size
        if search_after:
            body["search_after"] = search_after
        body["track_total_hits"] = False
        resp = with_retry(lambda: esq.search(index=ES_INDEX, body=body), who="es.search")
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            break
        for hit in hits:
            s = hit.get("_source", {}) or {}
            ts = first(s.get("@timestamp"))
            # 1) IP nguồn
            src_ip = first(s.get("source.ip")) or first(s.get("src_ip"))
            if src_ip:
                src_ip = str(src_ip)
                add_row(ts, src_ip, "ip", src_ip)
            # 2) Credentials (nếu có)
            u = first(s.get("user.name")) or first(s.get("username"))
            p = first(s.get("password"))
            if u or p:
                cred = f"{u or ''}:{p or ''}"
                add_row(ts, src_ip, "credential", cred)
            # 3) Hash từ field chuyên dụng
            for fld in ["md5", "sha1", "sha256", "sha512", "hash"]:
                for val in many(s.get(fld)):
                    if not val:
                        continue
                    v = str(val).strip()
                    if classify_hash(v):
                        add_row(ts, src_ip, "hash", v)
            # 3b) Hash trong text (hashes, message)
            text_buf = []
            for fld in ["hashes", "message"]:
                for val in many(s.get(fld)):
                    if val:
                        text_buf.append(str(val))
            if text_buf:
                merged = "\n".join(text_buf)
                labeled_found = False
                for _, h in LABELED_HASH_RE.findall(merged):
                    if classify_hash(h):
                        add_row(ts, src_ip, "hash", h)
                        labeled_found = True
                if not labeled_found:
                    for h in BARE_HASH_RE.findall(merged):
                        if classify_hash(h):
                            add_row(ts, src_ip, "hash", h)
            # 4) URL từ field có cấu trúc
            for fld in ["url.full", "url.original", "http.url", "url"]:
                for val in many(s.get(fld)):
                    if not val:
                        continue
                    v = normalize_url(str(val))
                    if v and v.lower().startswith(("http://", "https://")):
                        add_row(ts, src_ip, "url", v)
            # 4b) Nếu chỉ có host → ghép http://host thành URL tối thiểu
            host = first(s.get("url.domain")) or first(s.get("http.hostname")) \
                   or first(s.get("hostname"))   or first(s.get("domain"))
            if host:
                h = normalize_domain(str(host))
                if h and "." in h and " " not in h:
                    add_row(ts, src_ip, "url", f"http://{h}")
            # 4c) URL trong message (regex http/https)
            for val in many(s.get("message")):
                if not val:
                    continue
                for m in URL_RE.findall(str(val)):
                    v = normalize_url(m)
                    if v and v.lower().startswith(("http://", "https://")):
                        add_row(ts, src_ip, "url", v)
            # 5) HOSTNAME từ field có cấu trúc
            for fld in ["http.hostname", "hostname"]:
                for val in many(s.get(fld)):
                    if not val:
                        continue
                    h = normalize_domain(str(val))
                    if "." in h and " " not in h:
                        add_row(ts, src_ip, "hostname", h)
            # 6) DOMAIN từ field có cấu trúc
            for fld in ["domain", "url.domain"]:
                for val in many(s.get(fld)):
                    if not val:
                        continue
                    d = normalize_domain(str(val))
                    if "." in d and " " not in d:
                        add_row(ts, src_ip, "domain", d)
            # 7) Hostname/Domain phát hiện trong message (regex)
            for val in many(s.get("message")):
                if not val:
                    continue
                for d in DOMAIN_RE.findall(str(val)):
                    d2 = normalize_domain(d)
                    if d2 and "." in d2 and " " not in d2:
                        # Heuristic: >=3 label → hostname, =2 label → domain
                        if d2.count(".") >= 2:
                            add_row(ts, src_ip, "hostname", d2)
                        else:
                            add_row(ts, src_ip, "domain", d2)
        search_after = hits[-1]["sort"]
        if len(hits) < page_size:
            break
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows, columns=["timestamp", "src_ip", "ioc_type", "value"])

# Lấy (src_ip, dest_port) từ ES để phục vụ Nmap/DDoS.
def fetch_conn_tuples_from_es():
    """
    Lấy (src_ip, dst_port) trong khoảng HOURS_LOOKBACK để phục vụ heuristics Nmap/DDoS.
    """
    es = Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)
    esq = es.options(request_timeout=60)

    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=HOURS_LOOKBACK)).isoformat()

    body = {
        "_source": ["@timestamp", "source.ip", "src_ip", "destination.port", "dest_port"],
        "query": {"range": {"@timestamp": {"gte": start}}},
        "size": 5000,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "track_total_hits": False
    }
    resp = with_retry(lambda: esq.search(index=ES_INDEX, body=body), who="es.search_conn")

    rows = []
    for h in resp.get("hits", {}).get("hits", []):
        s = h.get("_source", {}) or {}
        ip = first(s.get("source.ip")) or first(s.get("src_ip"))
        dp = first(s.get("destination.port")) or first(s.get("dest_port"))
        if ip and dp:
            rows.append((str(ip), str(dp)))
    return rows

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
def fetch_cowrie_events():
    """Lấy log Cowrie trong khung thời gian HOURS_LOOKBACK."""
    es = es_client()
    body = {
        "_source": [
            "@timestamp","eventid","session",
            "src_ip","source.ip",
            "username","user.name","password",
            "message","args",
            "url","shasum",
            "path","type"
        ],
        "query": {
            "bool": {
                "must": [ time_range_clause(HOURS_LOOKBACK) ],
                "should": [
                    {"terms": {"eventid.keyword": [
                        "cowrie.login.success",
                        "cowrie.command.input",
                        "cowrie.session.file_download"
                    ]}},
                    {"term": {"type.keyword": "Cowrie"}},
                    {"wildcard": {"path.keyword": "*cowrie*"}}
                ],
                "minimum_should_match": 1
            }
        },
        "size": 10000,
        "sort": [{"@timestamp": {"order": "asc"}}]
    }
    resp = es.search(index=ES_INDEX, body=body)
    hits = resp.get("hits", {}).get("hits", [])
    return [h.get("_source", {}) for h in hits]

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
                    logging.getLogger("botnet-detect").warning(
                        f"Sample too large > {SAMPLE_MAX_BYTES} bytes: {url}"
                    )
                    return None
                h.update(chunk)
            return h.hexdigest()
    except Exception as e:
        logging.getLogger("botnet-detect").warning(f"safe_fetch_sha256 failed for {url}: {e}")
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

    logger = logging.getLogger("botnet-detect")
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

# Map 1 dòng IoC DataFrame sang attribute MISP.
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
    # chỉ giữ src_ip + ts, bỏ session
    comment = fmt_comment(src, None, ts_local_str)

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
