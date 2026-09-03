"""Logging setup for the framework."""

import logging
import sys
from pathlib import Path

FORMAT = "[%(asctime)s] %(levelname)s: %(message)s"


def setup_logger(output_dir: Path) -> logging.Logger:
    """Configure root logger to write to console and {output_dir}/framework.log."""
    logger = logging.getLogger("okvir")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(FORMAT)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)

    output_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(output_dir / "framework.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def get_logger() -> logging.Logger:
    """Return the framework logger."""
    return logging.getLogger("okvir")
