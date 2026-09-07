"""
app.py
------
PhishGuard AI Flask application.

Routes
------
GET  /                    Dashboard UI (paste URL, analyze, view history)
POST /api/analyze         Run a URL through the model, return prediction +
                           confidence + SHAP explanation, and log the scan
GET  /api/history          Return recent scan history from SQLite
POST /api/history/clear    Wipe scan history
GET  /api/model-info        Return saved training metrics for the dashboard
GET  /api/research-info     Return the research-paper context (Phase 7)
POST /api/domain-intel      WHOIS lookup for a URL's hostname (Phase 5)
POST /api/virustotal        VirusTotal reputation lookup (Phase 6, optional)
GET  /api/lexicon            Suspicious-keyword/TLD/shortener lists, so the
                             frontend never hardcodes a second copy
GET  /healthz                 Liveness endpoint
"""

from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

sys.path.append(str(Path(__file__).resolve().parent.parent))
from backend.config import Config  # noqa: E402
from backend.constants import ANALYZE_RATE_LIMIT, BLOCKED_SCHEMES, SHAP_TOP_K  # noqa: E402
from database import db  # noqa: E402
from utils import domain_intel, virustotal  # noqa: E402
from utils.explainer import PhishExplainer  # noqa: E402
from utils.feature_extractor import (  # noqa: E402
    SHORTENING_SERVICES,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    URLFeatures,
    extract_features,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


def create_app(config_class: type = Config) -> Flask:
    """Application factory -- builds and returns a configured Flask app."""
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parent.parent / "templates"),
        static_folder=str(Path(__file__).resolve().parent.parent / "static"),
    )
    app.config.from_object(config_class)

    limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")

    logger.info("Loading model from %s", app.config["MODEL_PATH"])
    model = joblib.load(app.config["MODEL_PATH"])

    metrics_path = app.config["METRICS_PATH"]
    saved_metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else {}
    thresholds = saved_metrics.get("feature_thresholds", {})

    explainer = PhishExplainer(model, feature_thresholds=thresholds)
    db.init_db()

    # ---------------------------------------------------------------- #
    # Views
    # ---------------------------------------------------------------- #
    @app.route("/")
    def index():
        """Serve the single-page dashboard."""
        return render_template("index.html")

    @app.route("/api/analyze", methods=["POST"])
    @limiter.limit(ANALYZE_RATE_LIMIT)
    def analyze():
        """Extract features, predict, explain, and log a URL scan."""
        payload = request.get_json(silent=True) or {}
        url = (payload.get("url") or "").strip()

        error = _validate_url(url, app.config["MAX_URL_LENGTH"])
        if error:
            return jsonify({"error": error}), 400

        try:
            features = extract_features(url)
        except ValueError as exc:
            logger.warning("Feature extraction failed for %r: %s", url, exc)
            return jsonify({"error": "Could not parse that URL."}), 400
        except Exception:  # noqa: BLE001 - never let a bad URL 500 the app
            logger.exception("Unexpected error extracting features for %r", url)
            return jsonify({"error": "Could not analyze that URL."}), 400

        vector = features.to_list()
        X = pd.DataFrame([vector], columns=URLFeatures.feature_names())

        try:
            proba = model.predict_proba(X)[0]  # [P(legit), P(phishing)]
        except Exception:  # noqa: BLE001
            logger.exception("Model prediction failed for %r", url)
            return jsonify({"error": "Prediction failed. Please try again."}), 500

        phishing_confidence = float(proba[1])
        prediction = "phishing" if phishing_confidence >= 0.5 else "legitimate"
        confidence = phishing_confidence if prediction == "phishing" else 1 - phishing_confidence

        explanation = explainer.explain(vector, top_k=SHAP_TOP_K)
        top_feature = explanation["top_features"][0]["feature"] if explanation["top_features"] else ""

        scan_id = db.save_scan(
            url=url,
            prediction=prediction,
            confidence=round(confidence, 4),
            top_feature=top_feature,
        )

        response = {
            "id": scan_id,
            "url": url,
            "prediction": prediction,
            "confidence": round(confidence * 100, 2),
            "phishing_risk_score": round(phishing_confidence * 100, 2),
            "features": {name: getattr(features, name) for name in features.feature_names()},
            "explanation": explanation,
        }
        logger.info("Analyzed %s -> %s (%.1f%% confidence)", url, prediction, response["confidence"])
        return jsonify(response)

    @app.route("/api/domain-intel", methods=["POST"])
    @limiter.limit(ANALYZE_RATE_LIMIT)
    def domain_intel_route():
        """Phase 5 -- WHOIS-based domain metadata, separate from the ML verdict."""
        payload = request.get_json(silent=True) or {}
        url = (payload.get("url") or "").strip()
        error = _validate_url(url, app.config["MAX_URL_LENGTH"])
        if error:
            return jsonify({"error": error}), 400
        return jsonify(domain_intel.get_domain_intelligence(url))

    @app.route("/api/virustotal", methods=["POST"])
    @limiter.limit(ANALYZE_RATE_LIMIT)
    def virustotal_route():
        """Phase 6 -- optional third-party VirusTotal reputation lookup."""
        if not virustotal.is_configured():
            return jsonify({"available": False, "reason": "No VirusTotal API key configured on this server."})
        payload = request.get_json(silent=True) or {}
        url = (payload.get("url") or "").strip()
        error = _validate_url(url, app.config["MAX_URL_LENGTH"])
        if error:
            return jsonify({"error": error}), 400
        return jsonify(virustotal.get_reputation(url))

    @app.route("/api/history")
    def history():
        """Return recent scan history for the dashboard table."""
        limit = request.args.get("limit", app.config["HISTORY_PAGE_SIZE"], type=int)
        return jsonify(db.get_history(limit=limit))

    @app.route("/api/history/clear", methods=["POST"])
    def clear_history():
        """Clear all stored scan history."""
        db.clear_history()
        return jsonify({"status": "cleared"})

    @app.route("/api/model-info")
    def model_info():
        """Expose saved training metrics (accuracy, feature importance, dataset stats)."""
        if not metrics_path.exists():
            return jsonify({"error": "Metrics not available. Run train_model.py first."}), 404
        return jsonify(json.loads(metrics_path.read_text()))

    @app.route("/api/research-info")
    def research_info():
        """Phase 7 -- research paper context shown in the dashboard's Research panel."""
        research_path = app.config["RESEARCH_INFO_PATH"]
        if not research_path.exists():
            return jsonify({"error": "Research info not available."}), 404
        return jsonify(json.loads(research_path.read_text()))

    @app.route("/api/lexicon")
    def lexicon():
        """Expose the keyword/TLD/shortener lists so the frontend URL-autopsy
        highlighting always matches the backend feature extractor exactly."""
        return jsonify(
            {
                "suspicious_keywords": SUSPICIOUS_KEYWORDS,
                "shortening_services": SHORTENING_SERVICES,
                "suspicious_tlds": sorted(SUSPICIOUS_TLDS),
            }
        )

    @app.route("/healthz")
    def healthz():
        """Simple liveness endpoint for deployment platforms."""
        return jsonify({"status": "ok"})

    @app.errorhandler(429)
    def rate_limited(_exc):
        return jsonify({"error": "Too many requests. Please slow down and try again shortly."}), 429

    return app


_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")


def _validate_url(url: str, max_length: int) -> str | None:
    """Return an error message if `url` is invalid, else None."""
    if not url:
        return "Please provide a URL to analyze."
    if len(url) > max_length:
        return "URL is too long."

    # Check the scheme against the RAW input first -- prepending "http://"
    # below (to support scheme-less input like "example.com") would
    # otherwise mask a dangerous scheme such as "javascript:" or "data:".
    scheme_match = _SCHEME_RE.match(url.strip())
    if scheme_match and scheme_match.group(1).lower() in BLOCKED_SCHEMES:
        return "That URL scheme is not supported."

    candidate = url if "://" in url else f"http://{url}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return "That doesn't look like a valid URL."

    if parsed.scheme.lower() in BLOCKED_SCHEMES:
        return "That URL scheme is not supported."
    if not parsed.hostname or "." not in parsed.hostname:
        return "That doesn't look like a valid URL."
    return None


app = create_app()

if __name__ == "__main__":
    import os

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=app.config["DEBUG"])
