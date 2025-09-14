#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scenario 3 - Botnet infection attempt detector for T-Pot/Cowrie → push IoCs to MISP
- 1 EVENT DUY NHẤT: gom mọi phiên có login thành công (weak creds).
- Phiên có payload/C2 sẽ có thêm URL/ip-dst/sha256.
- Bản này: credential xuất value dạng "user:pass" (text, Other, to_ids=False) giống code chính.
"""

import os, sys, re, logging, hashlib, socket, json
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from urllib.parse import urlparse

import urllib3
from elasticsearch import Elasticsearch
from pymisp import PyMISP, MISPEvent
from requests.exceptions import RequestException

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
EVENT_TITLE    = os.getenv("EVENT_TITLE_BOTNET", "Botnet Infection Attempt (Cowrie)")

SAFE_IPS = [ip.strip() for ip in os.getenv("SAFE_IPS", "").split(",") if ip.strip()]
ALLOW_SAMPLE_FETCH = os.getenv("ALLOW_SAMPLE_FETCH", "false").lower() == "true"
SAMPLE_MAX_BYTES   = int(os.getenv("SAMPLE_MAX_BYTES", "5242880"))  # 5MB

LOG_FILE  = os.getenv("LOG_FILE", "scenario3_botnet_detect.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
DRY_RUN   = os.getenv("DRY_RUN", "false").lower() == "true"

missing = [k for k, v in {"ES_URL": ES_URL, "MISP_URL": MISP_URL, "MISP_KEY": MISP_KEY}.items() if not v]
if missing:
    sys.stderr.write(f"[CONFIG ERROR] Missing required env: {', '.join(missing)}\n")
    sys.exit(1)

# ================== Logging ==================
logger = logging.getLogger("scenario3-botnet")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
handler = RotatingFileHandler(LOG_FILE, maxBytes=2*1024*1024, backupCount=3, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)

console = logging.StreamHandler(sys.stdout)
console.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
console.setFormatter(logging.Formatter("%(levelname)s | %(message)s"))
logger.addHandler(console)

logger.info("=== Scenario3 botnet detector started ===")
logger.info(f"Config: ES_INDEX={ES_INDEX}, HOURS_LOOKBACK={HOURS_LOOKBACK}, DRY_RUN={DRY_RUN}, LOG_LEVEL={LOG_LEVEL}")

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
            "username", "user.name", "password",
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
    for i, e in enumerate(events[:5]):
        logger.debug(f"[ES SAMPLE {i}] {json.dumps(e, ensure_ascii=False)}")
    return events

# ================== Parse Helpers ==================
URL_RGX = re.compile(r"""(?P<url>(?:https?|ftp)://[^\s'"]+)""", re.IGNORECASE)
LOGIN_SUCC_RGX = re.compile(r'login attempt \[([^/\]]+)/([^\]]+)\]\s+succeeded', re.IGNORECASE)
IP_HOST_RGX = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

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

        ev = (s.get("eventid") or "").lower()

        if ev.endswith("login.success"):
            # Lấy trực tiếp field có cấu trúc
            u_direct = s.get("username") or s.get("user.name")
            p_direct = s.get("password")
            if u_direct: o["username"] = str(u_direct)
            if p_direct: o["password"] = str(p_direct)
            logger.info(f"[DEBUG] login.success session={sess} user={o['username']} pass={o['password']} (direct fields)")

            # Fallback regex từ message nếu thiếu
            if not o["username"] or not o["password"]:
                m = LOGIN_SUCC_RGX.search(str(s.get("message","")))
                if m:
                    o["username"] = o["username"] or m.group(1)
                    o["password"] = o["password"] or m.group(2)
                    logger.info(f"[DEBUG] Fallback regex session={sess} user={o['username']} pass={o['password']}")

        if ev.endswith("command.input"):
            urls = extract_urls_from_command(s.get("message"), s.get("args"))
            if urls:
                logger.debug(f"[DEBUG] session={sess} command URLs found: {urls}")
            for u in urls:
                o["urls"].add(u)

        if ev.endswith("session.file_download"):
            u = s.get("url")
            sh = s.get("shasum")
            if u:
                o["downloads"].append({"url": u, "shasum": sh})
                o["urls"].add(u)
                logger.debug(f"[DEBUG] session={sess} file_download url={u} shasum={sh}")

    for k in sessions:
        sessions[k]["urls"] = list(sessions[k]["urls"])
    logger.info(f"[DEBUG] correlate_sessions built {len(sessions)} session(s)")
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
    if DRY_RUN:
        logger.info(f"[DRY_RUN] Would create MISP event: {title}")
        return "DRY_EVENT_ID"
    res = misp.add_event(ev)
    return str(res["Event"]["id"])

def _misp_add_attr_raw(misp, event_id, type_, value, category="Network activity", comment="", to_ids=True):
    if value is None or str(value).strip() == "":
        return None
    payload = {"type": type_, "category": category, "value": value, "to_ids": to_ids, "comment": comment}
    if DRY_RUN:
        logger.info(f"[DRY_RUN] ADD {type_} {value} -> event {event_id} | category={category} to_ids={to_ids} comment={comment}")
        return None
    res = misp.add_attribute(event_id, payload, pythonify=True)
    return res

def add_attr_safe(misp, event_id, pref_type, value, category, comment, to_ids=True):
    """
    Thử type ưa thích (pref_type). Nếu MISP trả lỗi 'Invalid type', fallback sang 'text' (to_ids=False).
    """
    if value is None or str(value).strip() == "":
        return
    try:
        logger.debug(f"[DEBUG] add_attr_safe try type={pref_type} value={value}")
        _misp_add_attr_raw(misp, event_id, pref_type, value, category, comment, to_ids=to_ids)
        logger.info(f"ADD {pref_type} {value} -> event {event_id}")
    except Exception as e:
        msg = str(e)
        logger.warning(f"[WARN] add_attr type={pref_type} failed: {msg}")
        if "Invalid type" in msg or "403" in msg:
            try:
                _misp_add_attr_raw(misp, event_id, "text", value, category, f"{comment} [fallback text]", to_ids=False)
                logger.info(f"ADD text (fallback) {value} -> event {event_id}")
            except Exception as e2:
                logger.error(f"[ERROR] fallback text failed: {e2}")
        else:
            logger.error(f"[ERROR] add_attr failed: {e}")

# ================== Main ==================
def main():
    # B1: Lấy log Cowrie
    events = fetch_cowrie_events()
    if not events:
        print("[!] Không có sự kiện Cowrie trong khoảng thời gian chỉ định.")
        logger.info("No Cowrie events in time window, exit.")
        return

    # B2: Tương quan theo session
    sessions = correlate_sessions(events)

    # B3: Lọc phiên có login success (weak creds)
    suspects = []  # (sess_id, info, has_url)
    for sess_id, info in sessions.items():
        ip = info.get("src_ip")
        if not ip or ip in SAFE_IPS:
            logger.debug(f"[DEBUG] Skip session={sess_id} ip={ip} in SAFE_IPS or missing")
            continue
        weak_cred = bool(info.get("username") or info.get("password"))
        if not weak_cred:
            logger.debug(f"[DEBUG] Skip session={sess_id} no creds")
            continue
        has_url = bool(info.get("urls")) or bool(info.get("downloads"))
        logger.info(f"[DEBUG] candidate session={sess_id} ip={ip} user={info.get('username')} pass={info.get('password')} has_url={has_url}")
        suspects.append((sess_id, info, has_url))

    if not suspects:
        print("[!] Chưa thấy phiên login thành công (weak creds) hợp lệ.")
        logger.info("No suspect sessions found, exit.")
        return

    # B4: Tạo 1 EVENT duy nhất
    ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    title = f"{EVENT_TITLE} - {ts}"
    misp = None if DRY_RUN else misp_client()
    event_id = create_event(misp if misp else PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL), title)
    print(f"[+] Created Event {event_id} - {title}")
    logger.info(f"Created event id={event_id} title='{title}'")

    # B5: Đẩy IoC cho từng phiên
    for sess_id, info, has_url in suspects:
        src_ip  = info.get("src_ip")
        user    = info.get("username")
        passwd  = info.get("password")
        urls    = info.get("urls", [])
        dloads  = info.get("downloads", [])

        logger.info(f"[PUSH] session={sess_id} ip={src_ip} user={user} pass={passwd} urls={len(urls)} dloads={len(dloads)}")

        # ip-src (attacker)
        add_attr_safe(misp, event_id, "ip-src", src_ip,
                      category="Network activity",
                      comment=f"Attacker IP (Cowrie session {sess_id})", to_ids=True)

        # ===== Credential: user:pass (giống code chính) =====
        if user or passwd:
            cred_val = f"{user or ''}:{passwd or ''}"
            # type text, category Other, to_ids=False
            add_attr_safe(misp, event_id, "text", cred_val,
                          category="Other",
                          comment=f"credential used (session {sess_id})", to_ids=False)

        # Nếu có dấu hiệu payload/C2 thì thêm URL/ip-dst/sha256
        if has_url:
            for u in urls:
                add_attr_safe(misp, event_id, "url", u,
                              category="Payload delivery",
                              comment=f"Payload URL observed in commands (session {sess_id})", to_ids=True)
                try:
                    p = urlparse(u)
                    host = p.hostname
                    if host:
                        # KHÔNG add domain nếu host là IP
                        if not IP_HOST_RGX.match(host):
                            add_attr_safe(misp, event_id, "domain", host,
                                          category="Network activity",
                                          comment=f"C2 host from URL (session {sess_id})", to_ids=True)
                        dst_ip = resolve_ip(host)
                        if dst_ip:
                            add_attr_safe(misp, event_id, "ip-dst", dst_ip,
                                          category="Network activity",
                                          comment=f" Resolved C2 IP (session {sess_id})", to_ids=True)
                except Exception as e:
                    logger.warning(f"[WARN] parse/resolve URL failed: {u} | {e}")

            for d in dloads:
                u = d.get("url")
                sh = d.get("shasum")
                if sh:
                    add_attr_safe(misp, event_id, "sha256", sh,
                                  category="Artifacts dropped",
                                  comment=f"File hash reported by Cowrie (session {sess_id})", to_ids=True)
                elif ALLOW_SAMPLE_FETCH and u:
                    h = safe_fetch_sha256(u)
                    if h:
                        add_attr_safe(misp, event_id, "sha256", h,
                                      category="Artifacts dropped",
                                      comment=f"SHA256 computed in LAB (session {sess_id})", to_ids=True)

    print(f"[+] Done. Pushed {len(suspects)} session(s) worth of IoCs to MISP into ONE event.")
    logger.info(f"Done. Suspect sessions pushed: {len(suspects)}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.stderr.write(f"[FATAL] {e}\n")
        sys.exit(2)
