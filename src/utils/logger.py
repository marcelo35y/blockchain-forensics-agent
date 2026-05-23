"""
Logging configuration for Blockchain Forensics Agent.
Provides structured logging with console and file output.
"""

import logging
import sys
from datetime import datetime
from typing import Optional


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    format_style: str = "detailed",
) -> logging.Logger:
    """
    Configure logging for the application.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        format_style: Format style ('simple', 'detailed', 'json')
    """
    logger = logging.getLogger("blockchain_forensics")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))

    if format_style == "simple":
        formatter = logging.Formatter('%(levelname)s - %(message)s')
    elif format_style == "json":
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(module)s:%(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(module)s:%(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(file_handler)

    return logger


class JsonFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


class AnalysisLogger:
    """Specialized logger for analysis operations."""

    def __init__(self, agent_name: str, logger: Optional[logging.Logger] = None):
        self.agent_name = agent_name
        self.logger = logger or logging.getLogger(f"blockchain_forensics.{agent_name}")
        self._start_time: Optional[datetime] = None
        self._metrics: dict = {}

    def start_analysis(self, target: str, analysis_type: str = "full") -> None:
        self._start_time = datetime.utcnow()
        self.logger.info(
            f"[{self.agent_name}] Starting analysis | "
            f"target={target} | type={analysis_type}"
        )

    def end_analysis(self, status: str = "completed") -> float:
        if self._start_time:
            elapsed = (datetime.utcnow() - self._start_time).total_seconds()
            self.logger.info(
                f"[{self.agent_name}] Analysis {status} | "
                f"elapsed={elapsed:.2f}s | metrics={self._metrics}"
            )
            return elapsed
        return 0.0

    def log_finding(self, finding_type: str, severity: str, description: str) -> None:
        self.logger.warning(
            f"[{self.agent_name}] Finding | type={finding_type} | "
            f"severity={severity} | {description}"
        )

    def log_metric(self, name: str, value: float) -> None:
        self._metrics[name] = value
        self.logger.debug(f"[{self.agent_name}] Metric | {name}={value}")

    def log_progress(self, current: int, total: int, description: str = "") -> None:
        pct = (current / total * 100) if total > 0 else 0
        self.logger.info(
            f"[{self.agent_name}] Progress | {current}/{total} ({pct:.1f}%) | {description}"
        )
