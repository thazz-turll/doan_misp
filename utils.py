# utils.py
import random, time, ipaddress, re
from datetime import datetime
from urllib.parse import urlparse
from requests.exceptions import RequestException
from elasticsearch import TransportError, ConnectionError as ESConnectionError
from config import RETRY_BASE, RETRY_CAP, RETRY_MAX, logger

# ===== retry/backoff chung =====
def _is_retryable_exc(e: Exception) -> bool:
    if isinstance(e, (ESConnectionError, TransportError)):
        status = getattr(e, "status_code", None) or getattr(e, "status", None)
        return (status in (429, 500, 502, 503, 504)) or (status is None)
    if isinstance(e, RequestException):
        return True
    return False

def with_retry(fn, who="op"):
    attempt = 0
    while True:
        try:
            return fn()
        except Exception as e:
            attempt += 1
            if (not _is_retryable_exc(e)) or attempt >= RETRY_MAX:
                logger.error(f"[{who}] FAILED after {attempt} attempts: {e}")
                raise
            delay = min(RETRY_CAP, RETRY_BASE * (2 ** (attempt - 1))) + random.uniform(0, RETRY_BASE)
            logger.warning(f"[{who}] attempt {attempt} failed: {e} → retry in {delay:.2f}s")
            time.sleep(delay)

# ===== helpers chung =====
def first(v):
    if isinstance(v, list) and v:
        return v[0]
    return v

def many(v):
    if isinstance(v, list):
        return v
    return [v] if v is not None else []

def classify_hash(h: str):
    """Nhận diện md5/sha1/sha256/sha512 theo độ dài."""
    if not isinstance(h, str):
        return None
    v = h.strip()
    if re.fullmatch(r"[A-Fa-f0-9]{32}", v):   return "md5"
    if re.fullmatch(r"[A-Fa-f0-9]{40}", v):   return "sha1"
    if re.fullmatch(r"[A-Fa-f0-9]{64}", v):   return "sha256"
    if re.fullmatch(r"[A-Fa-f0-9]{128}", v):  return "sha512"
    return None

def is_non_routable_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    return (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast
        or ip_obj.is_reserved or ip_obj.is_unspecified
        or getattr(ip_obj, "is_site_local", False) or getattr(ip_obj, "is_global", None) is False
    )

def normalize_domain(d: str) -> str:
    d = str(d or "").strip().lower()
    return d[:-1] if d.endswith(".") else d

def normalize_url(u: str) -> str:
    u = str(u or "").strip()
    try:
        p = urlparse(u)
        netloc = p.netloc.lower()
        return f"{p.scheme}://{netloc}{p.path or ''}{('?' + p.query) if p.query else ''}"
    except Exception:
        return u

def fmt_local_ts_for_comment() -> str:
    d = datetime.now().astimezone()
    tz_raw = d.strftime("%z")  # ví dụ +0700
    tz_short = tz_raw[:3] if tz_raw else ""
    return d.strftime("%Y-%m-%d %H:%M:%S") + (f" {tz_short}" if tz_short else "")
