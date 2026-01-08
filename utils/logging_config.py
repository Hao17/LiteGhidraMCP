"""
Centralized logging configuration for Ghidra MCP Bridge.

Handles both console output (for main script) and file logging (for daemon threads).
File logs go to system temp directory with rotation support.

This module solves the problem where Ghidrathon daemon threads lose access to
the Ghidra console after the main script finishes executing.
"""

import logging
import os
import tempfile
from logging.handlers import RotatingFileHandler
from typing import Optional

# Module-level logger and file path
_logger: Optional[logging.Logger] = None
_log_file_path: Optional[str] = None

# Constants
LOG_NAME = "ghidra-mcp-bridge"
LOG_FILE_NAME = "ghidra_mcp_bridge.log"
LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 3


def get_log_file_path() -> str:
    """Get the log file path in system temp directory."""
    global _log_file_path
    if _log_file_path is None:
        _log_file_path = os.path.join(tempfile.gettempdir(), LOG_FILE_NAME)
    return _log_file_path


def get_logger() -> logging.Logger:
    """
    Get the configured logger for Ghidra MCP Bridge.

    Creates and configures the logger on first call.
    Uses DEBUG level for full debug logging.

    Returns:
        Configured logger instance with file and console handlers.
    """
    global _logger

    if _logger is not None:
        return _logger

    _logger = logging.getLogger(LOG_NAME)
    _logger.setLevel(logging.DEBUG)
    _logger.propagate = False  # Prevent duplicate output to root logger

    # Prevent duplicate handlers on reload
    if _logger.handlers:
        return _logger

    formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)

    # File handler (always active - essential for daemon threads)
    log_path = get_log_file_path()
    try:
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        _logger.addHandler(file_handler)
    except Exception:
        # If file handler fails, continue without it
        pass

    # No console handler - only file logging for daemon threads
    # Main script uses print() for Ghidra console output

    return _logger


def log_debug(msg: str, *args, **kwargs):
    """Log debug message."""
    get_logger().debug(msg, *args, **kwargs)


def log_info(msg: str, *args, **kwargs):
    """Log info message."""
    get_logger().info(msg, *args, **kwargs)


def log_warning(msg: str, *args, **kwargs):
    """Log warning message."""
    get_logger().warning(msg, *args, **kwargs)


def log_error(msg: str, *args, **kwargs):
    """Log error message."""
    get_logger().error(msg, *args, **kwargs)


def log_exception(msg: str, *args, **kwargs):
    """Log exception with traceback."""
    get_logger().exception(msg, *args, **kwargs)
