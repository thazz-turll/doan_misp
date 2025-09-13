# es_collect.py
import re
import pandas as pd
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from elasticsearch import Elasticsearch

from config import ES_URL, ES_INDEX, HOURS_LOOKBACK, logger
from utils import with_retry, first, many, classify_hash, normalize_domain, normalize_url


ES_SOURCE_FIELDS = [
    "@timestamp",
    "source.ip","src_ip",
    "user.name","username","password",
    "md5","sha1","sha256","sha512","hash","hashes","message",

    # URL & domain (bao phủ phổ biến)
    "url","http.url","url.full","url.original","url.domain",
    "http.hostname","hostname","domain",
]


# Regex phát hiện hash/URL/domain trong message
LABELED_HASH_RE = re.compile(r"(?i)\b(md5|sha1|sha256|sha512)\s*[:=]\s*([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b")
BARE_HASH_RE    = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b")
URL_RE          = re.compile(r"\bhttps?://[^\s\"']{4,}\b", re.IGNORECASE)
DOMAIN_RE       = re.compile(r"\b(?=.{1,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)

def fetch_iocs_from_es() -> pd.DataFrame:
    """Truy vấn ES, trích IoC (dedupe) → DataFrame: [timestamp, src_ip, ioc_type, value]."""
    es = Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)
    esq = es.options(request_timeout=60)

    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=HOURS_LOOKBACK)).isoformat()

    base_query = {
        "_source": ES_SOURCE_FIELDS,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"range": {"@timestamp": {"gte": start}}},
        "track_total_hits": False,
    }

    page_size = 3000
    search_after = None
    seen = set()    # {(ioc_type, value)}
    rows = []       # list of dict

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

        resp = with_retry(lambda: esq.search(index=ES_INDEX, body=body), who="es.search_iocs")
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            break

        for hit in hits:
            s = hit.get("_source", {}) or {}
            ts = first(s.get("@timestamp"))

            # 1) IP
            src_ip = first(s.get("source.ip")) or first(s.get("src_ip"))
            if src_ip:
                src_ip = str(src_ip)
                add_row(ts, src_ip, "ip", src_ip)

            # 2) Credential
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

            # 3b) Hash trong text
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

            # 4) URL có cấu trúc
            for fld in ["url.full", "url.original", "http.url", "url"]:
                for val in many(s.get(fld)):
                    if not val:
                        continue
                    v = normalize_url(str(val))
                    if v and v.lower().startswith(("http://", "https://")):
                        add_row(ts, src_ip, "url", v)

            # 4b) Nếu chỉ có host → ghép URL tối thiểu
            host = first(s.get("url.domain")) or first(s.get("http.hostname")) \
                   or first(s.get("hostname"))   or first(s.get("domain"))
            if host:
                h = normalize_domain(str(host))
                if h and "." in h and " " not in h:
                    add_row(ts, src_ip, "url", f"http://{h}")

            # 4c) URL trong message
            for val in many(s.get("message")):
                if not val:
                    continue
                for m in URL_RE.findall(str(val)):
                    v = normalize_url(m)
                    if v and v.lower().startswith(("http://", "https://")):
                        add_row(ts, src_ip, "url", v)

            # 5) HOSTNAME
            for fld in ["http.hostname", "hostname"]:
                for val in many(s.get(fld)):
                    if not val:
                        continue
                    h = normalize_domain(str(val))
                    if "." in h and " " not in h:
                        add_row(ts, src_ip, "hostname", h)

            # 6) DOMAIN
            for fld in ["domain", "url.domain"]:
                for val in many(s.get(fld)):
                    if not val:
                        continue
                    d = normalize_domain(str(val))
                    if "." in d and " " not in d:
                        add_row(ts, src_ip, "domain", d)

            # 7) Hostname/Domain trong message
            for val in many(s.get("message")):
                if not val:
                    continue
                for d in DOMAIN_RE.findall(str(val)):
                    d2 = normalize_domain(d)
                    if d2 and "." in d2 and " " not in d2:
                        if d2.count(".") >= 2:
                            add_row(ts, src_ip, "hostname", d2)
                        else:
                            add_row(ts, src_ip, "domain", d2)

        search_after = hits[-1]["sort"]
        if len(hits) < page_size:
            break

    if not rows:
        logger.info("fetch_iocs_from_es: no IoC found in window")
        return pd.DataFrame()
    df = pd.DataFrame(rows, columns=["timestamp", "src_ip", "ioc_type", "value"])
    logger.info(f"fetch_iocs_from_es: got {len(df)} unique IoCs")
    return df

def fetch_conn_tuples_from_es():
    """Lấy (src_ip, dst_port) trong khoảng HOURS_LOOKBACK để phục vụ heuristics Nmap/DDoS."""
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
    logger.info(f"fetch_conn_tuples_from_es: got {len(rows)} tuples")
    return rows
