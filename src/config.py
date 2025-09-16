#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
config.py
----------
Quản lý cấu hình & hằng số cho hệ thống IoC Collector.
"""

import os
import sys
import re
from dotenv import load_dotenv

# Nạp .env (nếu có)
try:
    load_dotenv()
except Exception:
    pass

# =========================
# 1. CONFIG BẮT BUỘC
# =========================
ES_URL = os.getenv("ES_URL")                # Elasticsearch URL
MISP_URL = os.getenv("MISP_URL")            # MISP URL
MISP_KEY = os.getenv("MISP_KEY")            # API key MISP

missing = []
if not ES_URL:   missing.append("ES_URL")
if not MISP_URL: missing.append("MISP_URL")
if not MISP_KEY: missing.append("MISP_KEY")
if missing:
    sys.stderr.write(f"[CONFIG ERROR] Missing required env: {', '.join(missing)}\n")
    sys.exit(1)

# =========================
# 2. CONFIG TÙY CHỌN
# =========================
ES_INDEX       = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "2"))

VERIFY_SSL     = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
EVENT_MODE     = os.getenv("EVENT_MODE", "DAILY").upper()     # DAILY | APPEND
MISP_EVENT_ID  = os.getenv("MISP_EVENT_ID")

EVENT_TITLE_PREFIX = os.getenv("EVENT_TITLE_PREFIX", "T-Pot IoC Collection")
EVENT_TITLE_FORMAT = os.getenv("EVENT_TITLE_FORMAT", "%Y-%m-%d")

EVENT_DISTRIBUTION = int(os.getenv("MISP_DISTRIBUTION", "0"))
EVENT_ANALYSIS     = int(os.getenv("MISP_ANALYSIS", "0"))
THREAT_LEVEL_ID    = int(os.getenv("MISP_THREAT_LEVEL_ID", "2"))

MISP_TAGS = [t.strip() for t in os.getenv("MISP_TAGS", "source:t-pot,tlp:amber").split(",") if t.strip()]

DISABLE_IDS_FOR_PRIVATE = os.getenv("DISABLE_IDS_FOR_PRIVATE_IP", "true").lower() == "true"
TAG_PRIVATE_IP_ATTR     = os.getenv("TAG_PRIVATE_IP_ATTR", "false").lower() == "true"
PRIVATE_IP_TAG          = os.getenv("PRIVATE_IP_TAG", "scope:internal")

# Logging config
LOG_FILE       = os.getenv("LOG_FILE", "ioc_es_to_misp.log")
LOG_MAX_BYTES  = int(os.getenv("LOG_MAX_BYTES", "1048576"))  # 1MB
LOG_BACKUPS    = int(os.getenv("LOG_BACKUPS", "3"))

# Retry config
RETRY_BASE = float(os.getenv("RETRY_BASE", "0.5"))
RETRY_CAP  = float(os.getenv("RETRY_CAP", "8"))
RETRY_MAX  = int(os.getenv("RETRY_MAX", "5"))

# Detection flags
ALLOW_SAMPLE_FETCH = os.getenv("ALLOW_SAMPLE_FETCH", "false").lower() == "true"
SAMPLE_MAX_BYTES   = int(os.getenv("SAMPLE_MAX_BYTES", "5242880"))

DETECT_NMAP   = os.getenv("DETECT_NMAP", "false").lower() == "true"
DETECT_DDOS   = os.getenv("DETECT_DDOS", "false").lower() == "true"
DETECT_BOTNET = os.getenv("DETECT_BOTNET", "true").lower() == "true"

NMAP_THRESHOLD   = int(os.getenv("NMAP_THRESHOLD", "10"))
DDOS_THRESHOLD   = int(os.getenv("DDOS_THRESHOLD", "100"))

EVENT_TITLE_NMAP   = os.getenv("EVENT_TITLE_NMAP", "Nmap Scan Detected")
EVENT_TITLE_DDOS   = os.getenv("EVENT_TITLE_DDOS", "Potential DDoS Activity (SYN Flood)")
EVENT_TITLE_BOTNET = os.getenv("EVENT_TITLE_BOTNET", "Botnet Infection Attempt (Cowrie)")

SAFE_IPS = [ip.strip() for ip in os.getenv("SAFE_IPS", "").split(",") if ip.strip()]

# Elasticsearch fields cần query
ES_SOURCE_FIELDS = [
    "@timestamp",
    "source.ip","src_ip",
    "user.name","username","password",
    "md5","sha1","sha256","sha512","hash","hashes","message",
    "url","http.url","url.full","url.original","url.domain",
    "http.hostname","hostname","domain",
]

# =========================
# 3. REGEX & MAPPING
# =========================
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA512_RE = re.compile(r"^[a-fA-F0-9]{128}$")

URL_RGX         = re.compile(r"(?P<url>(?:https?|ftp)://[^\s'\"<>]+)", re.IGNORECASE)
LOGIN_SUCC_RGX  = re.compile(r'login attempt \[([^/\]]+)/([^\]]+)\]\s+succeeded', re.IGNORECASE)
IP_HOST_RGX     = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

LABELED_HASH_RE = re.compile(
    r"(?i)\b(md5|sha1|sha256|sha512)\s*[:=]\s*([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b"
)
BARE_HASH_RE = re.compile(
    r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b"
)
URL_RE = re.compile(r"\bhttps?://[^\s\"']{4,}\b", re.IGNORECASE)

DOMAIN_RE = re.compile(
    r"\b(?=.{1,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE
)

MAPPING_BASE = {
    "ip":        ("ip-src", "Network activity", True),
    "domain":    ("domain", "Network activity", True),
    "hostname":  ("hostname", "Network activity", True),
    "url":       ("url",    "Network activity", True),
    "credential":("text",   "Other",            False),
}
