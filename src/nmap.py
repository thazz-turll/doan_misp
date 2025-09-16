#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
nmap.py
------
Kịch bản phát hiện Nmap scan:
- detect_nmap_scanners(conns, threshold)
- create_nmap_event_and_push(misp, ip_list)
"""

from logger import get_logger
from config import SAFE_IPS, EVENT_TITLE_NMAP
from ioc_utils import fmt_comment
from misp_utils import _create_event_with_title, add_attr_safe
from datetime import datetime, timezone

logger = get_logger("detect-nmap")


# Phát hiện IP quét nhiều cổng (nghi vấn Nmap).
def detect_nmap_scanners(conns, threshold: int):
    """Trả về list IP có số cổng duy nhất >= threshold."""
    if not conns:
        return []
    df = pd.DataFrame(conns, columns=["ip", "port"])
    grouped = df.groupby("ip")["port"].nunique()
    suspects = [ip for ip, cnt in grouped.items() if cnt >= threshold]
    return [ip for ip in suspects if ip not in SAFE_IPS]

# Lấy hậu tố thời gian (ngày) cho event.
def _get_ts_suffix_from_daily() -> str:
    return create_daily_event_title().split(" - ", 1)[-1]

# Tạo event MISP cho Nmap scan và đẩy IP nguồn.
def create_nmap_event_and_push(misp, ip_list):
    """Tạo event Nmap và push IP (không ghi session vào comment)."""
    title = f"{EVENT_TITLE_NMAP} - {_get_ts_suffix_from_daily()}"
    ev_id = _create_event_with_title(misp, title)
    ts_local = _fmt_local_ts_for_comment()
    for ip in ip_list:
        if ip in SAFE_IPS:
            continue
        # comment chỉ gồm src_ip + ts
        cmt = fmt_comment(ip, None, ts_local)
        add_attr_safe(misp, ev_id, "ip-src", ip, "Network activity", cmt, True)
    return ev_id
