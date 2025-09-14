#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, re, logging, hashlib, socket
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from urllib.parse import urlparse

import pandas as pd
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
EVENT_TITLE_BOTNET = os.getenv("EVENT_TITLE_BOTNET", "Botnet Infection Attempt (Scenario 3)")

# Danh sách IP an toàn cần bỏ qua (CSV)
SAFE_IPS = [ip.strip() for ip in os.getenv("SAFE_IPS", "").split(",") if ip.strip()]

# Cho phép tải mẫu để băm SHA256 (CHỈ LAB!)
ALLOW_SAMPLE_FETCH = os.getenv("ALLOW_SAMPLE_FETCH", "false").lower() == "true"
SAMPLE_MAX_BYTES = int(os.getenv("SAMPLE_MAX_BYTES", "5242880"))  # 5MB giới hạn an toàn

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
    return Elasticsearch([ES_URL], http_compress=True, retry_on_timeout=True, max_retries=5)

def time_range_clause(hours):
    now = datetime.now(timezone.utc)
    start = (now - relativedelta(hours=hours)).isoformat()
    return {"range": {"@timestamp": {"gte": start}}}

def fetch_cowrie_events():
    """
    Lấy events liên quan kịch bản:
      - cowrie.login.success   (để lấy username/password + session + src_ip)
      - cowrie.command.input   (để trích URL từ lệnh curl/wget)
      - cowrie.session.file_download (để lấy url + shasum)
    Thêm bộ lọc gợi ý của bạn:
      eventid wildcard "cowrie.*", term type = "Cowrie", path.keyword chứa "cowrie".
    """
    es = es_client()
    q = {
        "_source": [
            "@timestamp", "eventid", "session", "src_ip", "source.ip",
            "username", "password", "message", "args", "url", "shasum",
            "path", "type"
        ],
        "query": {
            "bool": {
                "must": [ time_range_clause(HOURS_LOOKBACK) ],
                "should": [
                    {"wildcard": {"eventid.keyword": "cowrie.*"}},
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
    return [h.get("_source", {}) for h in hits]

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
            # 1 số log có thể thiếu session, bỏ qua để tránh nhầm
            continue
        o = sessions.setdefault(sess, {"src_ip": None, "username": None, "password": None,
                                       "urls": set(), "downloads": []})

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

    # B3: Lọc các phiên có dấu hiệu botnet (login success + có URL tải/cmd)
    suspects = []
    for sess_id, info in sessions.items():
        ip = info.get("src_ip")
        if not ip or ip in SAFE_IPS:
            continue
        weak_cred = bool(info.get("username") or info.get("password"))
        has_url = len(info.get("urls", [])) > 0 or len(info.get("downloads", [])) > 0
        if weak_cred and has_url:
            suspects.append((sess_id, info))

    if not suspects:
        print("[!] Chưa thấy phiên botnet phù hợp (login thành công + tải payload).")
        return

    # B4: Tạo MISP event
    ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    title = f"{EVENT_TITLE_BOTNET} - {ts}"
    misp = misp_client()
    event_id = create_event(misp, title)
    print(f"[+] Created Event {event_id} - {title}")

    # B5: Đẩy IoC cho từng phiên nghi vấn
    for sess_id, info in suspects:
        src_ip = info.get("src_ip")
        username = info.get("username")
        password = info.get("password")
        urls = info.get("urls", [])
        downloads = info.get("downloads", [])

        # ip-src (attacker)
        if src_ip:
            add_attr(misp, event_id, "ip-src", src_ip,
                     category="Network activity",
                     comment=f"Attacker IP (Cowrie session {sess_id})")

        # username/password yếu
        if username:
            add_attr(misp, event_id, "username", username,
                     category="Payload delivery",
                     comment=f"Credential used (session {sess_id})", to_ids=False)
        if password:
            add_attr(misp, event_id, "password", password,
                     category="Payload delivery",
                     comment=f"Credential used (session {sess_id})", to_ids=False)

        # URL/C2 + domain/ip-dst
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
                    if dst_ip:
                        add_attr(misp, event_id, "ip-dst", dst_ip,
                                 category="Network activity",
                                 comment=f"Resolved C2 IP (session {sess_id})")
            except Exception:
                pass

        # SHA256 từ Cowrie hoặc tự tính (nếu bật)
        for d in downloads:
            u = d.get("url")
            sh = d.get("shasum")
            if sh:
                add_attr(misp, event_id, "sha256", sh,
                         category="Artifacts dropped",
                         comment=f"File hash reported by Cowrie (session {sess_id})")
            elif ALLOW_SAMPLE_FETCH and u:
                h = safe_fetch_sha256(u)
                if h:
                    add_attr(misp, event_id, "sha256", h,
                             category="Artifacts dropped",
                             comment=f"SHA256 computed in LAB (session {sess_id})")

    print(f"[+] Done. Pushed {len(suspects)} session(s) worth of IoCs to MISP.")

if __name__ == "__main__":
    main()
