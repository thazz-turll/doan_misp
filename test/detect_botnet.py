#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, re, hashlib, socket, json, logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from dateutil.relativedelta import relativedelta
from logging.handlers import RotatingFileHandler

import urllib3
from elasticsearch import Elasticsearch
from pymisp import PyMISP, MISPEvent

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== Load ENV =====
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ===== ENV (đồng bộ naming với Nmap script) =====
ES_URL           = os.getenv("ES_URL")
MISP_URL         = os.getenv("MISP_URL")
MISP_KEY         = os.getenv("MISP_KEY")
ES_INDEX         = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK   = int(os.getenv("HOURS_LOOKBACK", "2"))  # theo form Nmap
VERIFY_SSL       = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
EVENT_TITLE_BOTNET = os.getenv("EVENT_TITLE_BOTNET", "Botnet Infection Attempt (Cowrie)")
SAFE_IPS         = [ip.strip() for ip in os.getenv("SAFE_IPS", "").split(",") if ip.strip()]

ALLOW_SAMPLE_FETCH = os.getenv("ALLOW_SAMPLE_FETCH", "false").lower() == "true"
SAMPLE_MAX_BYTES   = int(os.getenv("SAMPLE_MAX_BYTES", "5242880"))

# Kiểm tra ENV thiếu (giống Nmap script)
_missing = [k for k, v in {"ES_URL": ES_URL, "MISP_URL": MISP_URL, "MISP_KEY": MISP_KEY}.items() if not v]
if _missing:
    sys.stderr.write(f"[CONFIG ERROR] Missing required env: {', '.join(_missing)}\n")
    sys.exit(1)

# ===== Logging (giống Nmap script) =====
LOG_FILE = os.getenv("LOG_FILE", "botnet_detect.log")
logger = logging.getLogger("botnet-detect")
logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(LOG_FILE, maxBytes=1048576, backupCount=3, encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(_handler)

# ===== Regex & hằng số =====
URL_RGX = re.compile(r"(?P<url>(?:https?|ftp)://[^\s'\"<>]+)", re.IGNORECASE)
LOGIN_SUCC_RGX = re.compile(r'login attempt \[([^/\]]+)/([^\]]+)\]\s+succeeded', re.IGNORECASE)
IP_HOST_RGX = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

# ===== ES helpers =====
def es_client():
    return Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)

def time_range_clause(hours: int):
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=hours)).isoformat()
    return {"range": {"@timestamp": {"gte": start}}}

def fetch_cowrie_events():
    """Lấy log Cowrie trong khung thời gian (form tương tự Nmap: đơn giản, rõ ràng)."""
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
    rows = [h.get("_source", {}) for h in hits]
    logger.info(f"ES returned {len(rows)} Cowrie events (lookback={HOURS_LOOKBACK}h)")
    return rows

# ===== Phân tích hành vi phiên Cowrie =====
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

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def safe_fetch_sha256(url):
    import requests
    try:
        with requests.get(url, timeout=8, stream=True, verify=VERIFY_SSL) as r:
            r.raise_for_status()
            h = hashlib.sha256(); total = 0
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk: continue
                total += len(chunk)
                if total > SAMPLE_MAX_BYTES:
                    logger.warning(f"Sample too large > {SAMPLE_MAX_BYTES} bytes: {url}")
                    return None
                h.update(chunk)
            return h.hexdigest()
    except Exception as e:
        logger.warning(f"safe_fetch_sha256 failed for {url}: {e}")
        return None

def correlate_sessions(events):
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
    logger.info(f"Correlated {len(sessions)} Cowrie sessions")
    return sessions

# ===== MISP helpers (form giống Nmap) =====
def create_event(misp: PyMISP, title: str) -> str:
    ev = MISPEvent()
    ev.info = title
    ev.distribution = 0
    ev.analysis = 0
    ev.threat_level_id = 2
    res = misp.add_event(ev)
    return str(res["Event"]["id"])

def _misp_add_attr_raw(misp, event_id, type_, value, category="Network activity", comment="", to_ids=True):
    if not value or str(value).strip() == "": return None
    payload = {"type": type_, "category": category, "value": value, "to_ids": to_ids, "comment": comment}
    return misp.add_attribute(event_id, payload, pythonify=True)

def add_attr_safe(misp, event_id, pref_type, value, category, comment, to_ids=True):
    if not value or str(value).strip() == "": return
    try:
        _misp_add_attr_raw(misp, event_id, pref_type, value, category, comment, to_ids=to_ids)
        logger.info(f"ADD {pref_type} {value} to event {event_id}")
    except Exception as e:
        if "Invalid type" in str(e) or "403" in str(e):
            _misp_add_attr_raw(misp, event_id, "text", value, category, f"{comment} [fallback text]", to_ids=False)
            logger.info(f"ADD text (fallback) {value} to event {event_id}")
        else:
            logger.warning(f"add_attr failed type={pref_type} value={value}: {e}")

def fmt_comment(src_ip: str, sess_id: str, ts_iso: str | None = None) -> str:
    try:
        if ts_iso:
            from dateutil import parser as dtparser
            dt = dtparser.isoparse(ts_iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts_local = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        else:
            ts_local = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        ts_local = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    return f"src_ip={src_ip}; ts={ts_local}; session={sess_id}"

# ===== Main =====
def main():
    events = fetch_cowrie_events()
    if not events:
        print("[!] Không có sự kiện Cowrie.")
        logger.info("No Cowrie events in lookback window")
        return

    sessions = correlate_sessions(events)

    suspects = []
    for sid, info in sessions.items():
        ip = info.get("src_ip")
        if not ip or ip in SAFE_IPS:
            continue
        # điều kiện: có login thành công & có URL/download
        if not (info.get("username") or info.get("password")):
            continue
        has_url = bool(info.get("urls")) or bool(info.get("downloads"))
        if not has_url:
            continue
        suspects.append((sid, info, has_url))

    if not suspects:
        print("[!] Không có phiên login thành công kèm tải/URL.")
        logger.info("No suspicious sessions matched criteria")
        return

    # Tiêu đề sự kiện: theo ngày (đồng bộ hoá phong cách rõ ràng)
    ts_date = datetime.now().astimezone().strftime("%Y-%m-%d")
    title = f"{EVENT_TITLE_BOTNET} - {ts_date}"

    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)
    event_id = create_event(misp, title)
    print(f"[+] Created Event {event_id} - {title}")
    logger.info(f"Created MISP event id={event_id} title='{title}'")

    for sid, info, _ in suspects:
        src_ip  = info.get("src_ip")
        user    = info.get("username")
        passwd  = info.get("password")
        urls    = info.get("urls", [])
        dloads  = info.get("downloads", [])
        ts_first = info.get("ts_first")

        cmt = fmt_comment(src_ip, sid, ts_first)

        # ip-src
        add_attr_safe(misp, event_id, "ip-src", src_ip, "Network activity", cmt, True)

        # credentials (không to_ids)
        if user or passwd:
            cred_val = f"{user or ''}:{passwd or ''}"
            add_attr_safe(misp, event_id, "text", cred_val, "Other", cmt, False)

        # URLs / domain / ip-dst
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

        # Hash sample (ưu tiên shasum của Cowrie; nếu không có và cho phép thì fetch)
        for d in dloads:
            u = d.get("url"); sh = d.get("shasum")
            if sh:
                add_attr_safe(misp, event_id, "sha256", sh, "Artifacts dropped", cmt, True)
            elif ALLOW_SAMPLE_FETCH and u:
                h = safe_fetch_sha256(u)
                if h:
                    add_attr_safe(misp, event_id, "sha256", h, "Artifacts dropped", cmt, True)

    print(f"[+] Done. {len(suspects)} session(s) pushed.")
    logger.info(f"Done push: {len(suspects)} sessions")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        sys.stderr.write(f"[FATAL] {e}\n")
        logger.exception(f"Fatal error: {e}")
        sys.exit(2)
