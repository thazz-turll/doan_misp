#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
logger.py
---------
Cấu hình logging dùng chung cho toàn bộ project.
"""

import logging
from logging.handlers import RotatingFileHandler
from config import LOG_FILE, LOG_MAX_BYTES, LOG_BACKUPS

# =========================
# Hàm tạo logger xoay vòng
# =========================
def get_logger(name: str = "ioc-collector") -> logging.Logger:
    """
    Trả về logger với RotatingFileHandler.
    
    Args:
        name: tên logger (ví dụ: 'es', 'misp', 'nmap')

    Returns:
        logging.Logger
    """
    logger = logging.getLogger(name)

    # Nếu đã có handler → tránh add lại (log trùng lặp)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUPS,
            encoding="utf-8"
        )
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
        handler.setFormatter(fmt)
        logger.addHandler(handler)

    return logger
