#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from urllib.parse import urlparse

import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch import TransportError, ConnectionError as ESConnectionError
from requests.exceptions import RequestException
from pymisp import PyMISP, MISPEvent
import time, random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== Load ENV =====
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

ES_URL   = os.getenv("ES_URL")
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
ES_INDEX = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "12"))

VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
EVENT_TITLE_BOTNET = os.getenv("EVENT_TITLE_BOTNET", "Botnet Infection Attempt (Cowrie)")

SAFE_IPS = [ip.strip() for ip in os.getenv("SAFE_IPS", "").split(",") if ip.strip()]

missing = []
for k, v in {"ES_URL": ES_URL, "MISP_URL": MISP_URL, "MISP_KEY": MISP_KEY}.items():
    if not v:
        missing.append(k)
if missing:
    sys.stderr.write(f"[CONFIG ERROR] Missing required env: {', '.join(missing)}\n")
    sys.exit(1)

# ===== Logging =====
LOG_FILE = os.getenv("LOG_FILE", "botnet_cowrie_detect.log")
logger = logging.getLogger("botnet-cowrie-detect")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=1048576, backupCount=3, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)

# ===== Helpers (tối giản, theo form code chính) =====
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA512_RE = re.compile(r"^[a-fA-F0-9]{128}$")

LABELED_HASH_RE = re.compile(r"(?i)\b(md5|sha1|sha256|sha512)\s*[:=]\s*([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b")
BARE_HASH_RE    = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b")

URL_RE = re.compile(r"\bhttps?://[^\s\"']{4,}\b", re.IGNORECASE)

def classify_hash(h: str):
    v = (h or "").strip()
    if MD5_RE.fullmatch(v): return "md5"
    if SHA1_RE.fullmatch(v): return "sha1"
    if SHA256_RE.fullmatch(v): return "sha256"
    if SHA512_RE.fullmatch(v): return "sha512"
    return None

def normalize_url(u: str) -> str:
    u = str(u or "").strip()
    try:
        p = urlparse(u)
        netloc = p.netloc.lower()
        return f"{p.scheme}://{netloc}{p.path or ''}{('?' + p.query) if p.query else ''}"
    except Exception:
        return u

def first(v):
    if isinstance(v, list) and v:
        return v[0]
    return v

def many(v):
    if isinstance(v, list):
        return v
    return [v] if v is not None else []

def _is_retryable_exc(e):
    if isinstance(e, (ESConnectionError, TransportError)):
        status = getattr(e, "status_code", None) or getattr(e, "status", None)
        if status in (429, 500, 502, 503, 504) or status is None:
            return True
        return False
    if isinstance(e, RequestException):
        return True
    return False

def with_retry(func, *, max_attempts=5, base=0.5, cap=8.0, who="op"):
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

# ===== ES fetch (chỉ Cowrie) =====
ES_SOURCE_FIELDS = [
    "@timestamp",
    "source.ip","src_ip",
    "user.name","username","password",
    # Cowrie/command/message/url
    "message","cowrie.session","cowrie.command","cowrie.input","request",
    "url","http.url","url.full","url.original","url.domain","http.hostname","hostname","domain",
    "md5","sha1","sha256","sha512","hash","hashes",
    "event.dataset","event.module","program","tags"
]

def fetch_cowrie_iocs_from_es():
    """
    Truy vấn ES lấy log liên quan Cowrie trong HOURS_LOOKBACK.
    Trích xuất IoC (ip, credential, url, hash) theo từng IP nguồn.
    Trả về dict: ip -> {"creds": set, "urls": set, "hashes": set, "last_ts": str}
    """
    es = Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)
    esq = es.options(request_timeout=60)

    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=HOURS_LOOKBACK)).isoformat()

    base_query = {
        "_source": ES_SOURCE_FIELDS,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": start}}}],
                "should": [
                    {"term": {"event.dataset": "cowrie"}},
                    {"term": {"event.module":  "cowrie"}},
                    {"term": {"program":       "cowrie"}},
                    {"match_phrase": {"message": "cowrie"}},
                    {"term": {"tags":          "cowrie"}}
                ],
                "minimum_should_match": 1
            }
        }
    }

    page_size = 3000
    search_after = None

    bucket = {}  # ip -> dict(creds=set(), urls=set(), hashes=set(), last_ts=str)
    def ensure_ip(ip):
        if ip not in bucket:
            bucket[ip] = {"creds": set(), "urls": set(), "hashes": set(), "last_ts": ""}

    while True:
        body = dict(base_query)
        body["size"] = page_size
        if search_after:
            body["search_after"] = search_after
        body["track_total_hits"] = False

        resp = with_retry(lambda: esq.search(index=ES_INDEX, body=body), who="es.search.cowrie")
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            break

        for hit in hits:
            s = hit.get("_source", {}) or {}
            ts = first(s.get("@timestamp"))
            src_ip = first(s.get("source.ip")) or first(s.get("src_ip"))
            if not src_ip:
                continue
            src_ip = str(src_ip).strip()
            ensure_ip(src_ip)

            # update last_ts
            if ts:
                cur = bucket[src_ip]["last_ts"]
                bucket[src_ip]["last_ts"] = cur or ts

            # Credentials
            u = first(s.get("user.name")) or first(s.get("username"))
            p = first(s.get("password"))
            if u or p:
                bucket[src_ip]["creds"].add(f"{u or ''}:{p or ''}")

            # Hash (field)
            for fld in ["md5","sha1","sha256","sha512","hash"]:
                for v in many(s.get(fld)):
                    v2 = str(v or "").strip()
                    if classify_hash(v2):
                        bucket[src_ip]["hashes"].add(v2)

            # Hash trong message/hashes
            text_buf = []
            for fld in ["hashes","message","cowrie.command","cowrie.input","request"]:
                for v in many(s.get(fld)):
                    if v:
                        text_buf.append(str(v))
            if text_buf:
                merged = "\n".join(text_buf)
                labeled_found = False
                for _, h in LABELED_HASH_RE.findall(merged):
                    if classify_hash(h):
                        bucket[src_ip]["hashes"].add(h)
                        labeled_found = True
                if not labeled_found:
                    for h in BARE_HASH_RE.findall(merged):
                        if classify_hash(h):
                            bucket[src_ip]["hashes"].add(h)

            # URL structured fields
            for fld in ["url.full","url.original","http.url","url"]:
                for v in many(s.get(fld)):
                    if not v: continue
                    u2 = normalize_url(str(v))
                    if u2.lower().startswith(("http://","https://")):
                        bucket[src_ip]["urls"].add(u2)

            # URL từ message
            for v in many(s.get("message")):
                if not v: continue
                for m in URL_RE.findall(str(v)):
                    u2 = normalize_url(m)
                    if u2.lower().startswith(("http://","https://")):
                        bucket[src_ip]["urls"].add(u2)

        search_after = hits[-1]["sort"]
        if len(hits) < page_size:
            break

    return bucket

# ===== MISP push =====
def create_event(misp: PyMISP, title: str) -> str:
    ev = MISPEvent()
    ev.info            = title
    ev.distribution    = int(os.getenv("MISP_DISTRIBUTION", "0"))
    ev.analysis        = int(os.getenv("MISP_ANALYSIS", "0"))
    ev.threat_level_id = int(os.getenv("MISP_THREAT_LEVEL_ID", "2"))
    res = with_retry(lambda: misp.add_event(ev), who="misp.add_event")
    try:
        return str(res["Event"]["id"])
    except Exception:
        return str(getattr(res, "id", None) or getattr(getattr(res, "Event", None), "id", None))

def push_botnet_iocs(misp: PyMISP, event_id: str, data: dict):
    """
    data: ip -> {"creds": set, "urls": set, "hashes": set, "last_ts": str}
    """
    added = 0
    for ip, info in data.items():
        # IP nguồn
        attr_ip = {
            "type": "ip-src",
            "category": "Network activity",
            "value": ip,
            "to_ids": True,
            "comment": f"cowrie; ts={info.get('last_ts','')}"
        }
        with_retry(lambda: misp.add_attribute(event_id, attr_ip, pythonify=True), who="misp.add_attribute.ip")
        added += 1

        # Credentials (text, không IDS)
        for cred in sorted(info["creds"]):
            if cred.strip() == ":":
                continue
            attr_cred = {
                "type": "text",
                "category": "Other",
                "value": cred,
                "to_ids": False,
                "comment": f"cowrie credential; src_ip={ip}; ts={info.get('last_ts','')}"
            }
            with_retry(lambda: misp.add_attribute(event_id, attr_cred, pythonify=True), who="misp.add_attribute.cred")
            added += 1

        # URLs (Network activity)
        for u in sorted(info["urls"]):
            attr_url = {
                "type": "url",
                "category": "Network activity",
                "value": u,
                "to_ids": True,
                "comment": f"cowrie url; src_ip={ip}; ts={info.get('last_ts','')}"
            }
            with_retry(lambda: misp.add_attribute(event_id, attr_url, pythonify=True), who="misp.add_attribute.url")
            added += 1

        # Hashes (Payload delivery)
        for h in sorted(info["hashes"]):
            htype = classify_hash(h)
            if not htype:
                continue
            attr_h = {
                "type": htype,
                "category": "Payload delivery",
                "value": h,
                "to_ids": True,
                "comment": f"cowrie sample hash; src_ip={ip}; ts={info.get('last_ts','')}"
            }
            with_retry(lambda: misp.add_attribute(event_id, attr_h, pythonify=True), who="misp.add_attribute.hash")
            added += 1

    return added

# ===== main =====
def main():
    # 1) Lấy IoC Botnet từ ES (Cowrie only)
    bucket = fetch_cowrie_iocs_from_es()
    if not bucket:
        print("[!] Không phát hiện Botnet (Cowrie) trong log.")
        return

    # 2) Lọc SAFE_IPS (nếu có)
    if SAFE_IPS:
        bucket = {ip: v for ip, v in bucket.items() if ip not in SAFE_IPS}
        if not bucket:
            print("[!] Không phát hiện Botnet (Cowrie) trong log (hoặc chỉ thấy IP thuộc SAFE_IPS).")
            return

    # 3) Kiểm tra có thực sự có IoC đáng giá không (ít nhất có ip hoặc url/hash/cred)
    #    Trong bucket luôn có ip key; ta giữ nếu có bất kỳ IoC nào hơn IP trống.
    cleaned = {}
    for ip, info in bucket.items():
        if info["creds"] or info["urls"] or info["hashes"] or ip:
            cleaned[ip] = info

    if not cleaned:
        print("[!] Không phát hiện Botnet (Cowrie) trong log.")
        return

    # 4) Kết nối MISP & tạo event riêng cho kịch bản 3
    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)
    event_id = create_event(misp, EVENT_TITLE_BOTNET)
    if not event_id:
        print("[!] Không tạo được MISP Event cho Botnet (Cowrie).")
        return

    print(f"[+] Created Event {event_id} - {EVENT_TITLE_BOTNET}")

    # 5) Đẩy IoC
    added = push_botnet_iocs(misp, event_id, cleaned)
    print(f"[+] Done. Added {added} attribute(s) to Event {event_id}.")

if __name__ == "__main__":
    main()
