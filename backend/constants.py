"""
constants.py
------------
Small, shared constants used across the backend. Kept separate from
config.py because these are fixed application behaviour (not environment-
overridable settings).
"""

from __future__ import annotations

# Number of top SHAP-ranked features returned per prediction.
SHAP_TOP_K = 5

# Rate limits for the public /api/analyze endpoint (see backend/app.py).
# Generous enough for interactive use, tight enough to blunt naive scraping.
ANALYZE_RATE_LIMIT = "20 per minute"

# Blocked URL schemes -- never treated as analyzable web URLs.
BLOCKED_SCHEMES = {"javascript", "data", "vbscript", "file"}
