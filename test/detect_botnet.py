#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scenario 3 - Botnet infection attempt detector for T-Pot/Cowrie → push IoCs to MISP
- Gom log Cowrie theo session
- Nhóm 1: login thành công + có URL/download (payload/C2) → Event BOTNET
- Nhóm 2: chỉ login thành công (chưa thấy tải) → Event LOGIN-ONLY (tùy chọn)
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

# Khoảng thời gian truy vấn log
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "12"))

# Bật/tắt verify SSL với MISP
VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"

# Tiêu đề event
EVENT_TITLE_BOTNET     = os.getenv("EVENT_TITLE_BOTNET", "Botnet Infection Attempt (Scenario 3)")
EVENT_TITLE_LOGIN_ONLY = os.getenv("EVENT_TITLE_LOGIN_ONLY", "Successful SSH Login (Cowrie) - awaiting payload")

# Danh sách IP an toàn cần bỏ qua (CSV)
SAFE_IPS = [ip.strip() for ip in os.getenv("SAFE_IPS", "").split(",") if ip.strip()]

# Cho phép tải mẫu để băm SHA256 (CHỈ LAB!)
ALLOW_SAMPLE_FETCH = os.getenv("ALLOW_SAMPLE_FETCH", "false").lower() == "true"
SAMPLE_MAX_BYTES   = int(os.getenv("SAMPLE_MAX_BYTES", "5242880"))  # 5MB

# Tạo event LOGIN-ONLY?
CREATE_LOGIN_ONLY_EVENT = os.getenv("CREATE_LOGIN_ONLY_EVENT", "true").lower() == "true"

# Log file
LOG_FILE = os.getenv("LOG_FILE", "scenario3_botnet_detect.log")

# Bắt buộc
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
    # Có thể thêm http_auth / api_key nếu cần (qua ENV)
    return Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)

def time_range_clause(hours):
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=hours)).isoformat()
    return {"range": {"@timestamp": {"gte": start}}}

def fetch_cowrie_events():
    """
    Lấy events liên quan:
      - cowrie.login.success     (user/pass + session + src_ip)
      - cowrie.command.input     (trích URL từ lệnh wget/curl)
      - cowrie.session.file_download (url + shasum)
    Lọc thêm theo type/path để bớt nhiễu.
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
    """TUỲ CHỌN LAB: tải file để băm SHA256 (giới hạn kích thước)."""
    import requests
    try:
        with requests.get(url, timeout=8, stream=True, verify=False) as r:
            r.raise_for_status()
            h = hashlib.sha256()
            total = 0
            for chunk in r.iterate_content(chunk_size=8192) if hasattr(r, "iterate_content") else r.iter_content(chunk_size=8192):
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
    Trả về dict session -> thông tin:
      {
        'src_ip': ..., 'username': ..., 'password': ...,
        'urls': [..], 'downloads': [{'url':..., 'shasum':...}, ...]
      }
    """
    sessions = {}

    for s in events:
        sess = s.get("session")
        if not sess:
            # 1 số log có thể thiếu session → bỏ qua để tránh gộp sai
            continue
        o = sessions.setdefault(sess, {
            "src_ip": None, "username": None, "password": None,
            "urls": set(), "downloads": []
        })

        # src_ip
        ip = s.get("src_ip") or s.get("source.ip")
        if ip:
            o["src_ip"] = str(ip)

        ev = s.get("eventid") or ""
        # login success
        if ev.endswith("login.success"):
            if s.get("username"):
                o["username"] = str(s["username"])
            if s.get("password"):
                o["password"] = str(s["password"])

        # command input -> trích url
        if ev.endswith("command.input"):
            urls = extract_urls_from_command(s.get("message"), s.get("args"))
            for u in urls:
                o["urls"].add(u)

        # file download -> url + shasum
        if ev.endswith("session.file_download"):
            u = s.get("url")
            sh = s.get("shasum")
            if u:
                o["downloads"].append({"url": u, "shasum": sh})
                o["urls"].add(u)

    # Đổi set->list
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

    # B2: Tương quan theo session + debug ngắn
    sessions = correlate_sessions(events)
    logger.info(f"Total sessions: {len(sessions)}")
    for s, i in list(sessions.items())[:50]:  # tránh log quá dài
        logger.info(f"{s} ip={i.get('src_ip')} user={i.get('username')} pass={i.get('password')} "
                    f"urls={len(i.get('urls',[]))} dls={len(i.get('downloads',[]))}")

    # B3: Phân loại phiên
    sessions_payload = []
    sessions_login_only = []

    for sess_id, info in sessions.items():
        ip = info.get("src_ip")
        if not ip or ip in SAFE_IPS:
            continue

        weak_cred = bool(info.get("username") or info.get("password"))
        has_url   = bool(info.get("urls")) or bool(info.get("downloads"))

        if weak_cred and has_url:
            sessions_payload.append((sess_id, info))
        elif weak_cred:
            sessions_login_only.append((sess_id, info))

    if not sessions_payload and not sessions_login_only:
        print("[!] Chưa thấy phiên phù hợp.")
        return

    misp = misp_client()
    ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    # Event 1: Botnet (có tải payload/C2)
    if sessions_payload:
        title1 = f"{EVENT_TITLE_BOTNET} - {ts}"
        ev_payload = create_event(misp, title1)
        print(f"[+] Created Event {ev_payload} - {title1}")

        for sess_id, info in sessions_payload:
            src_ip  = info.get("src_ip")
            user    = info.get("username")
            passwd  = info.get("password")
            urls    = info.get("urls", [])
            dloads  = info.get("downloads", [])

            # ip-src (attacker)
            add_attr(misp, ev_payload, "ip-src", src_ip,
                     category="Network activity",
                     comment=f"Attacker IP (Cowrie session {sess_id})")

            # username/password yếu (không bật IDS)
            add_attr(misp, ev_payload, "username", user,
                     category="Payload delivery",
                     comment=f"Credential used (session {sess_id})", to_ids=False)
            add_attr(misp, ev_payload, "password", passwd,
                     category="Payload delivery",
                     comment=f"Credential used (session {sess_id})", to_ids=False)

            # URL/C2 + domain/ip-dst
            for u in urls:
                add_attr(misp, ev_payload, "url", u,
                         category="Payload delivery",
                         comment=f"Payload URL observed in commands (session {sess_id})")
                try:
                    p = urlparse(u)
                    if p.hostname:
                        add_attr(misp, ev_payload, "domain", p.hostname,
                                 category="Network activity",
                                 comment=f"C2 host from URL (session {sess_id})")
                        dst_ip = resolve_ip(p.hostname)
                        add_attr(misp, ev_payload, "ip-dst", dst_ip,
                                 category="Network activity",
                                 comment=f"Resolved C2 IP (session {sess_id})")
                except Exception:
                    pass

            # SHA256 từ Cowrie hoặc tự tính (nếu bật)
            for d in dloads:
                u = d.get("url")
                sh = d.get("shasum")
                if sh:
                    add_attr(misp, ev_payload, "sha256", sh,
                             category="Artifacts dropped",
                             comment=f"File hash reported by Cowrie (session {sess_id})")
                elif ALLOW_SAMPLE_FETCH and u:
                    h = safe_fetch_sha256(u)
                    add_attr(misp, ev_payload, "sha256", h,
                             category="Artifacts dropped",
                             comment=f"SHA256 computed in LAB (session {sess_id})")

        print(f"[+] Done. Pushed {len(sessions_payload)} session(s) with payload to MISP.")

    # Event 2 (tùy chọn): Successful login (chưa thấy tải)
    if CREATE_LOGIN_ONLY_EVENT and sessions_login_only:
        title2 = f"{EVENT_TITLE_LOGIN_ONLY} - {ts}"
        ev_login = create_event(misp, title2)
        print(f"[+] Created Event {ev_login} - {title2}")

        for sess_id, info in sessions_login_only:
            src_ip  = info.get("src_ip")
            user    = info.get("username")
            passwd  = info.get("password")

            add_attr(misp, ev_login, "ip-src", src_ip,
                     category="Network activity",
                     comment=f"Attacker IP (Cowrie session {sess_id})")
            add_attr(misp, ev_login, "username", user,
                     category="Payload delivery",
                     comment=f"Credential used (session {sess_id})", to_ids=False)
            add_attr(misp, ev_login, "password", passwd,
                     category="Payload delivery",
                     comment=f"Credential used (session {sess_id})", to_ids=False)

        print(f"[+] Logged {len(sessions_login_only)} session(s) with creds but no payload yet.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.stderr.write(f"[FATAL] {e}\n")
        sys.exit(2)
