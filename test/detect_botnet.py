#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scenario 3 - Botnet infection attempt detector for T-Pot/Cowrie → push IoCs to MISP
- 1 EVENT DUY NHẤT: gom mọi phiên có login thành công (weak creds).
- Phiên có payload/C2 sẽ có thêm URL/domain/ip-dst/sha256.
"""

import os, sys, re, logging, hashlib, socket
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from urllib.parse import urlparse

import urllib3
from elasticsearch import Elasticsearch
from pymisp import PyMISP, MISPEvent

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================== ENV ==================
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
VERIFY_SSL     = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
EVENT_TITLE    = os.getenv("EVENT_TITLE_BOTNET", "Botnet Infection Attempt (Scenario 3)")

SAFE_IPS = [ip.strip() for ip in os.getenv("SAFE_IPS", "").split(",") if ip.strip()]
ALLOW_SAMPLE_FETCH = os.getenv("ALLOW_SAMPLE_FETCH", "false").lower() == "true"
SAMPLE_MAX_BYTES   = int(os.getenv("SAMPLE_MAX_BYTES", "5242880"))  # 5MB

LOG_FILE = os.getenv("LOG_FILE", "scenario3_botnet_detect.log")

missing = [k for k, v in {"ES_URL": ES_URL, "MISP_URL": MISP_URL, "MISP_KEY": MISP_KEY}.items() if not v]
if missing:
    sys.stderr.write(f"[CONFIG ERROR] Missing required env: {', '.join(missing)}\n")
    sys.exit(1)

# ================== Logging ==================
logger = logging.getLogger("scenario3-botnet")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=2*1024*1024, backupCount=3, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)

# ================== ES Helpers ==================
def es_client():
    return Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)

def time_range_clause(hours):
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=hours)).isoformat()
    return {"range": {"@timestamp": {"gte": start}}}

def fetch_cowrie_events():
    """
    Lấy:
      - cowrie.login.success
      - cowrie.command.input
      - cowrie.session.file_download
    """
    es = es_client()
    q = {
        "_source": [
            "@timestamp", "eventid", "session",
            "src_ip", "source.ip",
            "username", "password",
            "message", "args",
            "url", "shasum",
            "path", "type"
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
    resp = es.search(index=ES_INDEX, body=q)
    hits = resp.get("hits", {}).get("hits", [])
    events = [h.get("_source", {}) for h in hits]
    logger.info(f"Fetched {len(events)} Cowrie events from ES")
    return events

# ================== Parse Helpers ==================
URL_RGX = re.compile(r"""(?P<url>(?:https?|ftp)://[^\s'"]+)""", re.IGNORECASE)

def extract_urls_from_command(msg, args):
    texts = []
    if isinstance(msg, str):
        texts.append(msg)
    if isinstance(args, list):
        texts.extend([str(a) for a in args])
    elif isinstance(args, str):
        texts.append(args)
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
    """LAB ONLY: tải file để băm SHA256 (giới hạn kích thước)."""
    import requests
    try:
        with requests.get(url, timeout=8, stream=True, verify=False) as r:
            r.raise_for_status()
            h = hashlib.sha256()
            total = 0
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                total += len(chunk)
                if total > SAMPLE_MAX_BYTES:
                    logger.warning(f"Skip hashing (size>{SAMPLE_MAX_BYTES}) for {url}")
                    return None
                h.update(chunk)
            return h.hexdigest()
    except Exception as e:
        logger.warning(f"Hash fetch failed for {url}: {e}")
        return None

# ================== Correlate by session ==================
def correlate_sessions(events):
    """
    session -> {
      'src_ip': ..., 'username': ..., 'password': ...,
      'urls': [..], 'downloads': [{'url':..., 'shasum':...}, ...]
    }
    """
    sessions = {}

    for s in events:
        sess = s.get("session")
        if not sess:
            continue
        o = sessions.setdefault(sess, {
            "src_ip": None, "username": None, "password": None,
            "urls": set(), "downloads": []
        })

        ip = s.get("src_ip") or s.get("source.ip")
        if ip:
            o["src_ip"] = str(ip)

        ev = s.get("eventid") or ""
        if ev.endswith("cowrie.login.success"):
            if s.get("username"):
                o["username"] = str(s["username"])
            if s.get("password"):
                o["password"] = str(s["password"])

        if ev.endswith("command.input"):
            urls = extract_urls_from_command(s.get("message"), s.get("args"))
            for u in urls:
                o["urls"].add(u)

        if ev.endswith("session.file_download"):
            u = s.get("url")
            sh = s.get("shasum")
            if u:
                o["downloads"].append({"url": u, "shasum": sh})
                o["urls"].add(u)

    for k in sessions:
        sessions[k]["urls"] = list(sessions[k]["urls"])
    return sessions

# ================== MISP Helpers ==================
def misp_client():
    return PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL)

def create_event(misp: PyMISP, title: str):
    ev = MISPEvent()
    ev.info = title
    ev.distribution = 0            # org-only
    ev.analysis = 0                # initial
    ev.threat_level_id = 2         # medium
    res = misp.add_event(ev)
    return str(res["Event"]["id"])

def add_attr(misp, event_id, type_, value, category="Network activity", comment="", to_ids=True):
    if value is None or str(value).strip() == "":
        return
    attr = {"type": type_, "category": category, "value": value, "to_ids": to_ids, "comment": comment}
    misp.add_attribute(event_id, attr, pythonify=True)
    logger.info(f"ADD {type_} {value} -> event {event_id}")

# ================== Main ==================
def main():
    # B1: Lấy log Cowrie
    events = fetch_cowrie_events()
    if not events:
        print("[!] Không có sự kiện Cowrie trong khoảng thời gian chỉ định.")
        return

    # B2: Tương quan theo session
    sessions = correlate_sessions(events)
    logger.info(f"Total sessions: {len(sessions)}")

    # B3: Chỉ cần login success (có user/pass) là đưa vào EVENT (không cần có URL)
    suspects = []  # (sess_id, info, has_url)
    for sess_id, info in sessions.items():
        ip = info.get("src_ip")
        if not ip or ip in SAFE_IPS:
            continue
        weak_cred = bool(info.get("username") or info.get("password"))
        if not weak_cred:
            continue
        has_url = bool(info.get("urls")) or bool(info.get("downloads"))
        suspects.append((sess_id, info, has_url))

    if not suspects:
        print("[!] Chưa thấy phiên login thành công (weak creds) hợp lệ.")
        return

    # B4: Tạo 1 EVENT duy nhất
    ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    title = f"{EVENT_TITLE} - {ts}"
    misp = misp_client()
    event_id = create_event(misp, title)
    print(f"[+] Created Event {event_id} - {title}")

    # B5: Đẩy IoC cho từng phiên
    for sess_id, info, has_url in suspects:
        src_ip  = info.get("src_ip")
        user    = info.get("username")
        passwd  = info.get("password")
        urls    = info.get("urls", [])
        dloads  = info.get("downloads", [])

        # ip-src (attacker)
        add_attr(misp, event_id, "ip-src", src_ip,
                 category="Network activity",
                 comment=f"Attacker IP (Cowrie session {sess_id})")

        # username/password (luôn đẩy, to_ids=False)
        add_attr(misp, event_id, "username", user,
                 category="Payload delivery",
                 comment=f"Credential used (session {sess_id})", to_ids=False)
        add_attr(misp, event_id, "password", passwd,
                 category="Payload delivery",
                 comment=f"Credential used (session {sess_id})", to_ids=False)

        # Nếu có dấu hiệu payload/C2 thì thêm URL/domain/ip-dst/sha256
        if has_url:
            for u in urls:
                add_attr(misp, event_id, "url", u,
                         category="Payload delivery",
                         comment=f"Payload URL observed in commands (session {sess_id})")
                try:
                    p = urlparse(u)
                    if p.hostname:
                        add_attr(misp, event_id, "domain", p.hostname,
                                 category="Network activity",
                                 comment=f"C2 host from URL (session {sess_id})")
                        dst_ip = resolve_ip(p.hostname)
                        add_attr(misp, event_id, "ip-dst", dst_ip,
                                 category="Network activity",
                                 comment=f"Resolved C2 IP (session {sess_id})")
                except Exception:
                    pass

            for d in dloads:
                u = d.get("url")
                sh = d.get("shasum")
                if sh:
                    add_attr(misp, event_id, "sha256", sh,
                             category="Artifacts dropped",
                             comment=f"File hash reported by Cowrie (session {sess_id})")
                elif ALLOW_SAMPLE_FETCH and u:
                    h = safe_fetch_sha256(u)
                    add_attr(misp, event_id, "sha256", h,
                             category="Artifacts dropped",
                             comment=f"SHA256 computed in LAB (session {sess_id})")

    print(f"[+] Done. Pushed {len(suspects)} session(s) worth of IoCs to MISP into ONE event.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.stderr.write(f"[FATAL] {e}\n")
        sys.exit(2)
