"""
config.py
---------
Central configuration for the Flask application. Values can be overridden
via environment variables, which is what Render (or any PaaS) will set in
production.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Base configuration shared by all environments."""

    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    DEBUG: bool = os.environ.get("FLASK_DEBUG", "0") == "1"

    MODEL_PATH: Path = BASE_DIR / "models" / "model.pkl"
    METRICS_PATH: Path = BASE_DIR / "models" / "metrics.json"
    RESEARCH_INFO_PATH: Path = BASE_DIR / "docs" / "research.json"

    MAX_URL_LENGTH: int = 2048
    HISTORY_PAGE_SIZE: int = 25
