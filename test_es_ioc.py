#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test: Kết nối Elasticsearch, truy vấn IoC theo timeframe, xử lý lọc trùng, có phân trang.
Bao gồm đủ IoC: ip, domain, url, hash (md5/sha1/sha256/sha512), credential (username/password).
"""

import os
import sys
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import re
import ipaddress
from elasticsearch import Elasticsearch, TransportError, ConnectionError as ESConnectionError
import pandas as pd

# ===== Load .env nếu có =====
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ===== Lấy config từ ENV hoặc fallback =====
ES_URL   = os.getenv("ES_URL", "http://user:pass@127.0.0.1:9200")
ES_INDEX = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "2"))

# Nếu vẫn không có URL thì báo lỗi
if not ES_URL.strip():
    sys.stderr.write("[CONFIG ERROR] ES_URL is missing.\n")
    sys.exit(1)

# ==== Field nguồn cần lấy từ ES ====
ES_SOURCE_FIELDS = [
    "@timestamp",
    # IP/credential
    "source.ip", "src_ip",
    "user.name", "username", "password",
    # Domain/URL
    "http.hostname", "domain", "dns.rrname",
    "url", "http.url",
    # Hash + text
    "md5", "sha1", "sha256", "sha512", "hash", "hashes", "message"
]

# ==== Regex hash ====
MD5_RE    = re.compile(r"^[A-Fa-f0-9]{32}$")
SHA1_RE   = re.compile(r"^[A-Fa-f0-9]{40}$")
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
SHA512_RE = re.compile(r"^[A-Fa-f0-9]{128}$")
LABELED_HASH_RE = re.compile(r"(?i)\b(md5|sha1|sha256|sha512)\s*[:=]\s*([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b")
BARE_HASH_RE    = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b")

def classify_hash(h: str):
    if MD5_RE.fullmatch(h): return "md5"
    if SHA1_RE.fullmatch(h): return "sha1"
    if SHA256_RE.fullmatch(h): return "sha256"
    if SHA512_RE.fullmatch(h): return "sha512"
    return None

def is_non_routable_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    return (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
        ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified or
        getattr(ip_obj, "is_site_local", False) or getattr(ip_obj, "is_global", None) is False
    )

def normalize_domain(d: str) -> str:
    d = (d or "").strip().lower()
    return d[:-1] if d.endswith(".") else d

def normalize_url(u: str) -> str:
    u = (u or "").strip()
    try:
        p = urlparse(u)
        return f"{p.scheme}://{p.netloc.lower()}{p.path or ''}{('?' + p.query) if p.query else ''}"
    except Exception:
        return u

def _first(v):
    if isinstance(v, list) and v:
        return v[0]
    return v

def _many(v):
    if isinstance(v, list):
        return v
    return [v] if v is not None else []

def _is_retryable_exc(e) -> bool:
    if isinstance(e, (ESConnectionError, TransportError)):
        status = getattr(e, "status_code", None) or getattr(e, "status", None)
        if status in (429, 500, 502, 503, 504) or status is None:
            return True
        return False
    return False

def fetch_iocs_from_es(es: Elasticsearch) -> pd.DataFrame:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=HOURS_LOOKBACK)).isoformat()

    base_query = {
        "_source": ES_SOURCE_FIELDS,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"range": {"@timestamp": {"gte": start}}},
        "track_total_hits": False
    }

    page_size = 3000
    search_after = None

    rows = []
    dedupe = set()

    def add(ioc_type, value, ts, src_ip):
        if not ioc_type or not value:
            return
        key = (ioc_type, value)
        if key in dedupe:
            return
        dedupe.add(key)
        rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": ioc_type, "value": value})

    while True:
        body = dict(base_query)
        body["size"] = page_size
        if search_after is not None:
            body["search_after"] = search_after

        # 1 lần retry nhẹ nếu lỗi mạng/5xx
        try:
            resp = es.search(index=ES_INDEX, body=body, request_timeout=60)
        except Exception as e:
            if _is_retryable_exc(e):
                resp = es.search(index=ES_INDEX, body=body, request_timeout=60)
            else:
                raise

        hits = resp.get("hits", {}).get("hits", []) or []
        if not hits:
            break

        for h in hits:
            s = h.get("_source", {}) or {}
            ts = _first(s.get("@timestamp"))
            src_ip = _first(s.get("source.ip")) or _first(s.get("src_ip"))
            if src_ip:
                add("ip", str(src_ip), ts, src_ip)

            # Credentials (username/password)
            u = _first(s.get("user.name")) or _first(s.get("username"))
            p = _first(s.get("password"))
            if u or p:
                cred = f"{u or ''}:{p or ''}"
                add("credential", cred, ts, src_ip)

            # Domains
            for fld in ["http.hostname", "domain", "dns.rrname"]:
                for v in _many(s.get(fld)):
                    v = normalize_domain(str(v))
                    if v and "." in v and " " not in v:
                        add("domain", v, ts, src_ip)

            # URLs
            for fld in ["url", "http.url"]:
                for v in _many(s.get(fld)):
                    v = normalize_url(str(v))
                    if v:
                        add("url", v, ts, src_ip)

            # Hash từ field chuyên dụng
            for fld in ["md5", "sha1", "sha256", "sha512", "hash"]:
                for v in _many(s.get(fld)):
                    v = str(v).strip()
                    if classify_hash(v):
                        add("hash", v, ts, src_ip)

            # Hash trong text
            text_buf = []
            for fld in ["hashes", "message"]:
                for v in _many(s.get(fld)):
                    if v:
                        text_buf.append(str(v))
            if text_buf:
                merged = "\n".join(text_buf)
                labeled = False
                for _, hx in LABELED_HASH_RE.findall(merged):
                    if classify_hash(hx):
                        add("hash", hx, ts, src_ip)
                        labeled = True
                if not labeled:
                    for hx in BARE_HASH_RE.findall(merged):
                        if classify_hash(hx):
                            add("hash", hx, ts, src_ip)

        search_after = hits[-1]["sort"]
        if len(hits) < page_size:
            break

    return pd.DataFrame(rows, columns=["timestamp", "src_ip", "ioc_type", "value"])

def main():
    es = Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=2)
    df = fetch_iocs_from_es(es)

    if df.empty:
        print("[!] Không có IoC nào trong khoảng thời gian yêu cầu.")
        return

    # Thống kê nhanh
    counts = df["ioc_type"].value_counts().to_dict()
    print(f"[+] Tổng IoC (sau lọc trùng): {len(df)}")
    print("[+] Phân bố loại IoC:", counts)
    print(df.head(10).to_string(index=False))

    # --- Ghi CSV cố định ---
    out_file = "latest_iocs.csv"
    df.to_csv(out_file, index=False, encoding="utf-8")
    print(f"[+] Đã lưu IoC vào: {out_file}")
