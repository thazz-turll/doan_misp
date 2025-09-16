#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
es_utils.py
-----------
Các hàm làm việc với Elasticsearch (fetch IoCs, connections, Cowrie logs).
"""

from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
import pandas as pd
from elasticsearch import Elasticsearch

from ioc_utils import first, many, classify_hash, normalize_url, normalize_domain
from config import URL_RE, LABELED_HASH_RE, BARE_HASH_RE, DOMAIN_RE, ES_URL, ES_INDEX, HOURS_LOOKBACK, ES_SOURCE_FIELDS
from misp_utils import with_retry 

from logger import get_logger

logger = get_logger("es-utils")


# Tạo Elasticsearch client với cấu hình từ ENV.
def es_client():
    return Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)

# Sinh range query theo @timestamp cho số giờ lookback.
def time_range_clause(hours: int):
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=hours)).isoformat()
    return {"range": {"@timestamp": {"gte": start}}}


# Truy vấn ES và trích xuất IoC (IP, URL, domain, hash, credential).
def fetch_iocs_from_es():
    """Truy vấn ES, trích IoC (dedupe), trả về DataFrame(các IoC)."""
    # ES client
    es = es_client()
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
    es = es_client()
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
