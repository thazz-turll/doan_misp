#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ioc_utils.py
------------
Các hàm tiện ích xử lý IoC: chuẩn hóa, phân loại hash, mapping sang MISP.
"""

import ipaddress
from urllib.parse import urlparse
from dateutil import parser
from datetime import timezone
from config import (
    MD5_RE, SHA1_RE, SHA256_RE, SHA512_RE,
    MAPPING_BASE
)
from logger import get_logger

logger = get_logger("ioc-utils")

# Trả về phần tử đầu nếu là list, ngược lại trả v.
def first(v):
    """Lấy phần tử đầu nếu v là list, ngược lại trả về v."""
    if isinstance(v, list) and v:
        return v[0]
    return v

# Bọc giá trị đơn thành list.
def many(v):
    """Đảm bảo giá trị là list (bọc đơn thành list)."""
    if isinstance(v, list):
        return v
    return [v] if v is not None else []

# Phân loại hash theo độ dài (md5/sha1/sha256/sha512).
def classify_hash(h: str):
    """Phân loại hash theo độ dài: md5/sha1/sha256/sha512, không khớp → None."""
    if not isinstance(h, str):
        return None
    v = h.strip()
    if MD5_RE.fullmatch(v): return "md5"
    if SHA1_RE.fullmatch(v): return "sha1"
    if SHA256_RE.fullmatch(v): return "sha256"
    if SHA512_RE.fullmatch(v): return "sha512"
    return None

# Kiểm tra IP có thuộc nhóm private/non-routable không.
def is_non_routable_ip(ip_str: str) -> bool:
    """Kiểm tra IP có phải non-routable/private/loopback..."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or getattr(ip_obj, "is_site_local", False)
        or getattr(ip_obj, "is_global", None) is False
    )
    
 # Chuẩn hóa domain/hostname (lowercase, bỏ dấu chấm cuối).
def normalize_domain(d: str) -> str:
    """Chuẩn hóa domain/hostname (lower, bỏ dấu chấm cuối)."""
    d = str(d or "").strip().lower()
    return d[:-1] if d.endswith(".") else d
    
# Chuẩn hóa URL (lowercase netloc, giữ nguyên phần còn lại).
def normalize_url(u: str) -> str:
    """Chuẩn hóa URL (lower netloc, giữ nguyên scheme/path/query)."""
    u = str(u or "").strip()
    try:
        p = urlparse(u)
        netloc = p.netloc.lower()
        return f"{p.scheme}://{netloc}{p.path or ''}{('?' + p.query) if p.query else ''}"
    except Exception:
        return u

# Sinh comment mô tả IoC (src_ip, session, timestamp).
def fmt_comment(src_ip: str, session_id: str | None, ts_first: str | None) -> str:
    parts = []
    if src_ip: parts.append(f"src_ip={src_ip}")
    if session_id: parts.append(f"session={session_id}")
    if ts_first:
        try:
            dt = parser.isoparse(ts_first)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            parts.append("ts=" + dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"))
        except Exception:
            parts.append(f"ts={ts_first}")
    return "; ".join(parts)



# Map 1 dòng IoC DataFrame sang attribute MISP.
def map_row_to_misp(row):
    """Map 1 dòng IoC → tuple attribute cho MISP (type, category, to_ids, value, comment, is_private)."""
    ioc_type = str(row.get("ioc_type", "")).strip().lower()
    value    = str(row.get("value", "")).strip()
    if not value:
        return None

    ts_str = str(row.get("timestamp", "")).strip()
    ts_local_str = ts_str
    if ts_str:
        try:
            dt = parser.isoparse(ts_str)
            # Chỉ gán UTC nếu thiếu thông tin timezone
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            # Đổi sang giờ local của server
            ts_local_str = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        except Exception:
            pass

    src = str(row.get("src_ip", "")).strip()
    # chỉ giữ src_ip + ts, bỏ session
    comment = fmt_comment(src, None, ts_local_str)

    # Hash
    if ioc_type == "hash":
        htype = classify_hash(value)
        if not htype:
            return None
        return (htype, "Payload delivery", True, value, comment, False)

    # IP
    elif ioc_type == "ip":
        is_private = is_non_routable_ip(value)
        to_ids = not (DISABLE_IDS_FOR_PRIVATE and is_private)
        if is_private:
            comment = (comment + "; non-routable") if comment else "non-routable"
        return ("ip-src", "Network activity", to_ids, value, comment, is_private)

    # Domain / URL / Hostname
    elif ioc_type in ("domain", "url", "hostname"):
        misp_type, category, to_ids = MAPPING_BASE[ioc_type]
        return (misp_type, category, to_ids, value, comment, False)

    # Credential
    elif ioc_type == "credential":
        misp_type, category, to_ids = MAPPING_BASE[ioc_type]
        return (misp_type, category, to_ids, value, comment, False)

    else:
        return None
