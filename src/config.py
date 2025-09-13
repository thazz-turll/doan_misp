# config.py
import os, sys, logging
from logging.handlers import RotatingFileHandler

# --- .env ---
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# --- REQUIRED ---
ES_URL  = os.getenv("ES_URL")
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")

EVENT_TITLE_PREFIX = os.getenv("EVENT_TITLE_PREFIX", "T-Pot IoC Collection")
EVENT_TITLE_FORMAT = os.getenv("EVENT_TITLE_FORMAT", "%Y-%m-%d")

_missing = [k for k, v in {"ES_URL": ES_URL, "MISP_URL": MISP_URL, "MISP_KEY": MISP_KEY}.items() if not v]
if _missing:
    sys.stderr.write(f"[CONFIG ERROR] Missing required env: {', '.join(_missing)}\n")
    sys.exit(1)

# --- GENERAL / OPTIONAL ---
ES_INDEX       = os.getenv("ES_INDEX", "logstash-*")
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "2"))

VERIFY_SSL     = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
EVENT_MODE     = os.getenv("EVENT_MODE", "DAILY").upper()       # DAILY | APPEND
MISP_EVENT_ID  = os.getenv("MISP_EVENT_ID")

EVENT_DISTRIBUTION = int(os.getenv("MISP_DISTRIBUTION", "0"))
EVENT_ANALYSIS     = int(os.getenv("MISP_ANALYSIS", "0"))
THREAT_LEVEL_ID    = int(os.getenv("MISP_THREAT_LEVEL_ID", "2"))
MISP_TAGS = [t.strip() for t in os.getenv("MISP_TAGS", "source:t-pot,tlp:amber").split(",") if t.strip()]

DISABLE_IDS_FOR_PRIVATE = os.getenv("DISABLE_IDS_FOR_PRIVATE_IP", "true").lower() == "true"
TAG_PRIVATE_IP_ATTR     = os.getenv("TAG_PRIVATE_IP_ATTR", "false").lower() == "true"
PRIVATE_IP_TAG          = os.getenv("PRIVATE_IP_TAG", "scope:internal")

# --- Retry config (cho utils/requests/ES/MISP) ---
RETRY_BASE = float(os.getenv("RETRY_BASE", "0.5"))   # giây
RETRY_CAP  = float(os.getenv("RETRY_CAP", "8"))      # giây
RETRY_MAX  = int(os.getenv("RETRY_MAX", "5"))        # số lần

# --- Detection (Nmap / DDoS) ---
DETECT_NMAP      = os.getenv("DETECT_NMAP", "false").lower() == "true"
DETECT_DDOS      = os.getenv("DETECT_DDOS", "false").lower() == "true"
NMAP_THRESHOLD   = int(os.getenv("NMAP_THRESHOLD", "10"))
DDOS_THRESHOLD   = int(os.getenv("DDOS_THRESHOLD", "100"))
EVENT_TITLE_NMAP = os.getenv("EVENT_TITLE_NMAP", "Nmap Scan Detected")
EVENT_TITLE_DDOS = os.getenv("EVENT_TITLE_DDOS", "Potential DDoS Activity (SYN Flood)")
SAFE_IPS         = [ip.strip() for ip in os.getenv("SAFE_IPS", "").split(",") if ip.strip()]

# --- Logging ---
LOG_FILE      = os.getenv("LOG_FILE", "ioc_es_to_misp.log")
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", "1048576"))  # 1MB
LOG_BACKUPS   = int(os.getenv("LOG_BACKUPS", "3"))

logger = logging.getLogger("ioc-es-misp")
logger.setLevel(logging.INFO)
if not logger.handlers:  # tránh add handler nhiều lần khi module bị import lặp
    try:
        # tạo thư mục nếu LOG_FILE có path
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    except Exception:
        pass
    _h = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8")
    _h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(_h)
logger.propagate = False

# (tuỳ chọn) export rõ để IDE/linter dễ kiểm soát
__all__ = [
    "ES_URL","MISP_URL","MISP_KEY",
    "EVENT_TITLE_PREFIX","EVENT_TITLE_FORMAT",
    "ES_INDEX","HOURS_LOOKBACK",
    "VERIFY_SSL","EVENT_MODE","MISP_EVENT_ID",
    "EVENT_DISTRIBUTION","EVENT_ANALYSIS","THREAT_LEVEL_ID","MISP_TAGS",
    "DISABLE_IDS_FOR_PRIVATE","TAG_PRIVATE_IP_ATTR","PRIVATE_IP_TAG",
    "RETRY_BASE","RETRY_CAP","RETRY_MAX",
    "DETECT_NMAP","DETECT_DDOS","NMAP_THRESHOLD","DDOS_THRESHOLD",
    "EVENT_TITLE_NMAP","EVENT_TITLE_DDOS","SAFE_IPS",
    "LOG_FILE","LOG_MAX_BYTES","LOG_BACKUPS","logger"
]
