#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test: Kết nối Elasticsearch, query IoC theo timeframe, xử lý lọc trùng.
Yêu cầu tối giản để kiểm tra pipeline lấy IoC từ ES.
"""

import os
import sys
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import re
import ipaddress

from elasticsearch import Elasticsearch
import pandas as pd

# ==== ENV (giữ tối giản, không hardcode URL) ====
ES_URL   = os.getenv("http://192.168.1.100:64298")                # ví dụ: https://user:pass@es.example:9200
ES_INDEX = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "2"))  # lấy dữ liệu 2 giờ gần nhất

if not ES_URL:
    sys.stderr.write("[CONFIG ERROR] Missing ES_URL\n")
    sys.exit(1)

# ==== Field nguồn cần lấy từ ES ====
ES_SOURCE_FIELDS = [
    "@timestamp",
    "source.ip", "src_ip",
    "http.hostname", "domain", "dns.rrname",
    "url", "http.url",
    "md5", "sha1", "sha256", "sha512", "hash", "hashes", "message"
]

# ==== Regex hash đơn giản ====
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
    return (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
            ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified or
            getattr(ip_obj, "is_site_local", False) or getattr(ip_obj, "is_global", None) is False)

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

def fetch_iocs_from_es(es: Elasticsearch) -> pd.DataFrame:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=HOURS_LOOKBACK)).isoformat()

    body = {
        "_source": ES_SOURCE_FIELDS,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"range": {"@timestamp": {"gte": start}}},
        "size": 3000,
        "track_total_hits": False
    }

    resp = es.search(index=ES_INDEX, body=body, request_timeout=60)
    hits = resp.get("hits", {}).get("hits", []) or []

    rows = []
    dedupe = set()  # (ioc_type, value)
    def add(ioc_type, value, ts, src_ip):
        if not ioc_type or not value:
            return
        key = (ioc_type, value)
        if key in dedupe:
            return
        dedupe.add(key)
        rows.append({"timestamp": ts, "src_ip": src_ip, "ioc_type": ioc_type, "value": value})

    for h in hits:
        s = h.get("_source", {}) or {}
        ts = _first(s.get("@timestamp"))

        # IP
        src_ip = _first(s.get("source.ip")) or _first(s.get("src_ip"))
        if src_ip:
            add("ip", str(src_ip), ts, src_ip)

        # Domain-like
        for fld in ["http.hostname", "domain", "dns.rrname"]:
            for v in _many(s.get(fld)):
                v = normalize_domain(str(v))
                if v and "." in v and " " not in v:
                    add("domain", v, ts, src_ip)

        # URL
        for fld in ["url", "http.url"]:
            for v in _many(s.get(fld)):
                v = normalize_url(str(v))
                if v:
                    add("url", v, ts, src_ip)

        # Hash (từ field riêng)
        for fld in ["md5", "sha1", "sha256", "sha512", "hash"]:
            for v in _many(s.get(fld)):
                v = str(v).strip()
                if classify_hash(v):
                    add("hash", v, ts, src_ip)

        # Hash (quét trong text)
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

    return pd.DataFrame(rows, columns=["timestamp", "src_ip", "ioc_type", "value"])

def main():
    es = Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=2)

    df = fetch_iocs_from_es(es)
    if df.empty:
        print("[!] Không có IoC nào trong khoảng thời gian yêu cầu.")
        return

    # In kết quả tóm tắt & vài dòng mẫu
    print(f"[+] Tổng IoC (sau lọc trùng): {len(df)}")
    print(df.head(10).to_string(index=False))

    # Thống kê nhanh theo loại
    print("\n[+] Thống kê theo loại:")
    print(df.groupby("ioc_type")["value"].count())

    # Ví dụ: loại bỏ IP private (nếu muốn test)
    df_public_ip = df[~((df["ioc_type"] == "ip") & (df["value"].map(is_non_routable_ip)))]
    print(f"\n[+] Public IoC sau lọc IP private: {len(df_public_ip)}")

if __name__ == "__main__":
    main()
