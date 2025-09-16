#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
botnet.py
---------
Kịch bản Botnet / Cowrie:
- extract_urls_from_command(msg, args)
- resolve_ip(host)
- safe_fetch_sha256(url)
- correlate_cowrie_sessions(events)
- create_botnet_event_and_push(misp, sessions)
"""

import logging
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone

from ..logger import get_logger
from pymisp import MISPEvent

from ..config import (
    URL_RGX, LOGIN_SUCC_RGX, IP_HOST_RGX,
    ALLOW_SAMPLE_FETCH, SAMPLE_MAX_BYTES, EVENT_TITLE_BOTNET,
    VERIFY_SSL, EVENT_DISTRIBUTION, EVENT_ANALYSIS, THREAT_LEVEL_ID,
    MISP_TAGS, SAFE_IPS,
)
from ..ioc_utils import fmt_comment
from ..misp_utils import add_attr_safe, tag_event, with_retry, _get_ts_suffix_from_daily

logger = get_logger("detect-botnet")


# Trích URL từ command input/args của Cowrie.
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

# Chuyển hostname thành IP.
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

# Tải file (giới hạn dung lượng) và tính sha256.
def safe_fetch_sha256(url):
    import requests, hashlib
    try:
        with requests.get(url, timeout=8, stream=True, verify=VERIFY_SSL) as r:
            r.raise_for_status()
            h = hashlib.sha256(); total = 0
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk: continue
                total += len(chunk)
                if total > SAMPLE_MAX_BYTES:
                    logging.getLogger("botnet-detect").warning(
                        f"Sample too large > {SAMPLE_MAX_BYTES} bytes: {url}"
                    )
                    return None
                h.update(chunk)
            return h.hexdigest()
    except Exception as e:
        logging.getLogger("botnet-detect").warning(f"safe_fetch_sha256 failed for {url}: {e}")
        return None

# Gom log Cowrie theo session (src_ip, creds, URL, download).
def correlate_cowrie_sessions(events):
    """Gom theo session, lấy src_ip/creds/URL/download/time đầu tiên."""
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
    return sessions

# Tạo event MISP cho Botnet/Cowrie và đẩy IoC (IP, creds, URL, hash).
def create_botnet_event_and_push(misp, sessions):
    title = f"{EVENT_TITLE_BOTNET} - {_get_ts_suffix_from_daily()}"
    ev = MISPEvent()
    ev.info = title
    ev.distribution = EVENT_DISTRIBUTION
    ev.analysis = EVENT_ANALYSIS
    ev.threat_level_id = THREAT_LEVEL_ID

    res = with_retry(lambda: misp.add_event(ev), who="misp.add_event_botnet")
    event_id = str(res["Event"]["id"])

    logger = logging.getLogger("botnet-detect")
    logger.info(f"[Botnet] Created MISP event id={event_id} title='{title}'")

    # Gắn tag như event chính (nếu có)
    if MISP_TAGS:
        try:
            tag_event(misp, event_id, MISP_TAGS)
        except Exception as e:
            logger.warning(f"Tag event failed: {e}")

    for sid, info in sessions.items():
        src_ip  = info.get("src_ip")
        if not src_ip or src_ip in SAFE_IPS:
            continue

        user    = info.get("username")
        passwd  = info.get("password")
        urls    = info.get("urls", [])
        dloads  = info.get("downloads", [])
        ts_first = info.get("ts_first")
        cmt = fmt_comment(src_ip, sid, ts_first)

        # ip-src
        add_attr_safe(misp, event_id, "ip-src", src_ip, "Network activity", cmt, True)

        # creds (không to_ids)
        if user or passwd:
            cred_val = f"{user or ''}:{passwd or ''}"
            add_attr_safe(misp, event_id, "text", cred_val, "Other", cmt, False)

        # URL / domain / ip-dst
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

        # hash (ưu tiên shasum)
        for d in dloads:
            u = d.get("url"); sh = d.get("shasum")
            if sh:
                add_attr_safe(misp, event_id, "sha256", sh, "Artifacts dropped", cmt, True)
            elif ALLOW_SAMPLE_FETCH and u:
                h = safe_fetch_sha256(u)
                if h:
                    add_attr_safe(misp, event_id, "sha256", h, "Artifacts dropped", cmt, True)

    return event_id
