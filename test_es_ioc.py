#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test ES connection, query IoCs, and de-duplicate
Usage:
  python test_es_ioc.py [--out /path/to/iocs.csv]

Environment variables (same as your main script uses a subset of them):
  ES_URL                (required)  e.g., http://192.168.1.100:9200
  ES_INDEX              (optional)  default: logstash-*
  HOURS_LOOKBACK        (optional)  default: 2
"""
import os
import re
import sys
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from dateutil import parser
import argparse
import logging

import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch import TransportError, ConnectionError as ESConnectionError

# ---------- Load ENV ----------
ES_URL = os.getenv("ES_URL")
if not ES_URL:
    sys.stderr.write("[CONFIG ERROR] Missing required env: ES_URL\n")
    sys.exit(1)
ES_INDEX = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "2"))

# ---------- Logger ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
log = logging.getLogger("test-es-ioc")

# ---------- Regex/Parsers ----------
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA512_RE = re.compile(r"^[a-fA-F0-9]{128}$")

LABELED_HASH_RE = re.compile(
    r"(?i)\b(md5|sha1|sha256|sha512)\s*[:=]\s*([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b"
)
BARE_HASH_RE = re.compile(
    r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b"
)
URL_RE = re.compile(r"\bhttps?://[^\s\"']{4,}\b", re.IGNORECASE)

ES_SOURCE_FIELDS = [
    "@timestamp",
    "source.ip", "src_ip",
    "user.name", "username", "password",
    "md5","sha1","sha256","sha512","hash","hashes","message",
    "url","http.url","http.hostname","domain","dns.rrname"
]

def classify_hash(h: str):
    if not isinstance(h, str):
        return None
    v = h.strip()
    if MD5_RE.fullmatch(v): return "md5"
    if SHA1_RE.fullmatch(v): return "sha1"
    if SHA256_RE.fullmatch(v): return "sha256"
    if SHA512_RE.fullmatch(v): return "sha512"
    return None

def is_non_routable_ip(ip_str: str) -> bool:
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

def first(v):
    if isinstance(v, list) and v:
        return v[0]
    return v

def many(v):
    if isinstance(v, list):
        return v
    return [v] if v is not None else []

def normalize_domain(d: str) -> str:
    d = str(d or "").strip().lower()
    return d[:-1] if d.endswith(".") else d

def normalize_url(u: str) -> str:
    u = str(u or "").strip()
    try:
        p = urlparse(u)
        netloc = p.netloc.lower()
        return f"{p.scheme}://{netloc}{p.path or ''}{('?' + p.query) if p.query else ''}"
    except Exception:
        return u

def test_es_connection(es: Elasticsearch) -> None:
    info = es.info()
    log.info("Connected to ES: cluster=%s version=%s", info.get("cluster_name"), info.get("version", {}).get("number"))

def fetch_iocs_from_es(es: Elasticsearch, index: str, hours_lookback: int) -> pd.DataFrame:
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=hours_lookback)).isoformat()

    base_query = {
        "_source": ES_SOURCE_FIELDS,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"range": {"@timestamp": {"gte": start}}}
    }

    page_size = 2000
    search_after = None

    seen = set()   # (ioc_type, value)
    rows = []

    def add_row(ts, src_ip, typ, val):
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

        resp = es.search(index=index, body=body, request_timeout=60)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            break

        for hit in hits:
            s = hit.get("_source", {}) or {}
            ts = first(s.get("@timestamp"))

            # IP
            src_ip = first(s.get("source.ip")) or first(s.get("src_ip"))
            if src_ip:
                src_ip = str(src_ip)
                add_row(ts, src_ip, "ip", src_ip)

            # Credentials
            u = first(s.get("user.name")) or first(s.get("username"))
            p = first(s.get("password"))
            if u or p:
                cred = f"{u or ''}:{p or ''}"
                add_row(ts, src_ip, "credential", cred)

            # Hashes (explicit fields)
            for fld in ["md5", "sha1", "sha256", "sha512", "hash"]:
                for val in many(s.get(fld)):
                    if not val:
                        continue
                    v = str(val).strip()
                    if classify_hash(v):
                        add_row(ts, src_ip, "hash", v)

            # Hashes from free text
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

            # URLs
            for fld in ["url", "http.url"]:
                for val in many(s.get(fld)):
                    if not val:
                        continue
                    v = normalize_url(str(val))
                    if v:
                        add_row(ts, src_ip, "url", v)

            # Domains
            for fld in ["http.hostname", "domain", "dns.rrname"]:
                for val in many(s.get(fld)):
                    if not val:
                        continue
                    v = normalize_domain(str(val))
                    if "." in v and " " not in v:
                        add_row(ts, src_ip, "domain", v)

        search_after = hits[-1]["sort"]
        if len(hits) < page_size:
            break

    return pd.DataFrame(rows, columns=["timestamp", "src_ip", "ioc_type", "value"]) if rows else pd.DataFrame()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="iocs_sample.csv", help="CSV path to save found IoCs (deduplicated)")
    args = ap.parse_args()

    # Build ES client
    es = Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=3)

    # 1) Test connection
    try:
        test_es_connection(es)
    except (ESConnectionError, TransportError) as e:
        log.error("Cannot connect to ES at %s: %s", ES_URL, e)
        sys.exit(2)
    except Exception as e:
        log.error("Unexpected error during ES connection: %s", e)
        sys.exit(2)

    # 2) Query IoCs
    log.info("Querying IoCs from index '%s' in the last %d hour(s)...", ES_INDEX, HOURS_LOOKBACK)
    df = fetch_iocs_from_es(es, ES_INDEX, HOURS_LOOKBACK)

    if df is None or df.empty:
        log.warning("No IoCs found in the requested time window.")
        print("No IoCs found.")
        return

    # 3) Basic stats & de-dup verification
    total = len(df)
    uniq = len(df.drop_duplicates(subset=["ioc_type", "value"]))
    by_type = df.groupby("ioc_type")["value"].nunique().to_dict()

    log.info("IoC rows (after de-dup as we collect): %d", total)
    log.info("Unique pairs (ioc_type, value): %d", uniq)
    log.info("Unique by type: %s", by_type)

    # Save CSV
    out_path = os.path.abspath(args.out)
    df.to_csv(out_path, index=False, encoding="utf-8")
    print(f"Saved IoCs CSV to: {out_path}")
    print(f"Summary -> total_rows: {total} | unique_pairs: {uniq} | unique_by_type: {by_type}")

if __name__ == "__main__":
    main()
