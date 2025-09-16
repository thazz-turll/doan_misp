#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ddos.py
------
Kịch bản phát hiện DDoS:
- detect_ddos_sources(conns, threshold)
- create_ddos_event_and_push(misp, ip_list)
"""

from logger import get_logger
from config import SAFE_IPS, EVENT_TITLE_DDOS
from ioc_utils import fmt_comment
from misp_utils import _create_event_with_title, add_attr_safe, create_daily_event_title, _fmt_local_ts_for_comment, _get_ts_suffix_from_daily
from datetime import datetime, timezone
import pandas as pd

logger = get_logger("detect-ddos")

def detect_ddos_sources(conns, threshold: int):
    """Trả về list IP có tổng số record >= threshold (dấu hiệu flood)."""
    if not conns:
        return []
    df = pd.DataFrame([c[0] for c in conns], columns=["ip"])
    grouped = df.groupby("ip").size()
    suspects = [ip for ip, cnt in grouped.items() if cnt >= threshold]
    return [ip for ip in suspects if ip not in SAFE_IPS]

# Tạo event MISP cho DDoS và đẩy IP nguồn.
def create_ddos_event_and_push(misp, ip_list):
    """Tạo event DDoS và push IP (không ghi session vào comment)."""
    title = f"{EVENT_TITLE_DDOS} - {_get_ts_suffix_from_daily()}"
    ev_id = _create_event_with_title(misp, title)
    ts_local = _fmt_local_ts_for_comment()
    for ip in ip_list:
        if ip in SAFE_IPS:
            continue
        # comment chỉ gồm src_ip + ts
        cmt = fmt_comment(ip, None, ts_local)
        add_attr_safe(misp, ev_id, "ip-src", ip, "Network activity", cmt, True)
    return ev_id

