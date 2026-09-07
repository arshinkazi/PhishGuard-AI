"""
explainer.py
------------
Wraps a trained tree model with SHAP TreeExplainer to turn a raw
prediction into something a non-technical user can read: which features
pushed the URL towards "phishing" or "legitimate", how much each one
mattered, and a plain-English sentence per feature.

This is Module 3 (Explainable AI) of PhishGuard AI, and the deliberate
"small improvement" this project adds on top of the base research paper
(see README.md), which evaluates classifier accuracy but does not surface
per-prediction feature explanations to the end user.

v2 adds threshold-aware phrasing: each explanation is compared against the
feature's average value across the *phishing* class in the training set
(computed once in models/train_model.py and stored in metrics.json), so
sentences read like "URL length (91) exceeds the average phishing
threshold (75)" instead of a bare "raises/lowers the risk score".
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import shap

from utils.feature_extractor import URLFeatures

logger = logging.getLogger(__name__)


def _fmt(value: Any) -> str:
    """Compact numeric formatting for use inside sentences."""
    if isinstance(value, float):
        return f"{value:.2f}".rstrip("0").rstrip(".")
    return str(value)


# Each entry is a function(value, phishing_avg, contribution) -> sentence.
# `phishing_avg` may be None if no threshold was recorded for that feature.
def _url_length(value, avg, contrib):
    if avg is not None and value > avg:
        return f"The URL length ({_fmt(value)} characters) exceeds the average phishing threshold (~{_fmt(avg)})."
    return f"The URL length ({_fmt(value)} characters) is within a typical range."


def _num_subdomains(value, avg, contrib):
    if value >= 3 or (avg is not None and value > avg):
        return f"This URL contains an unusually high number of subdomains ({_fmt(value)})."
    return f"Subdomain count ({_fmt(value)}) is not unusual."


def _shannon_entropy(value, avg, contrib):
    if avg is not None and value > avg:
        return f"The character entropy ({_fmt(value)} bits/char) is unusually high, suggesting a randomly generated or obfuscated URL."
    return f"The character entropy ({_fmt(value)} bits/char) looks ordinary."


def _suspicious_keyword_count(value, avg, contrib):
    if value > 0:
        return f"Suspicious keyword detected ({_fmt(value)} match{'es' if value != 1 else ''} against a known phishing-lure wordlist)."
    return "No suspicious keywords were found in the URL."


def _suspicious_keyword_density(value, avg, contrib):
    if value > 0:
        return "Suspicious keywords make up an unusually large share of this URL's characters."
    return "Suspicious-keyword density is low."


def _num_hyphens(value, avg, contrib):
    if avg is not None and value > avg:
        return f"The URL uses more hyphens ({_fmt(value)}) than a typical legitimate domain — often used to imitate a brand name."
    return f"Hyphen count ({_fmt(value)}) is unremarkable."


def _num_digits(value, avg, contrib):
    if avg is not None and value > avg:
        return f"The URL contains more digits ({_fmt(value)}) than average — a common trait of auto-generated phishing links."
    return f"Digit count ({_fmt(value)}) is unremarkable."


def _digit_ratio(value, avg, contrib):
    if avg is not None and value > avg:
        return "A high proportion of the URL is numeric characters, which is atypical for a human-chosen domain."
    return "The digit-to-length ratio looks normal."


def _has_ip(value, avg, contrib):
    return "The URL uses a raw IP address instead of a domain name — a strong phishing indicator." if value else "The URL uses a proper domain name rather than a raw IP."


def _has_https(value, avg, contrib):
    return "The URL uses HTTPS, which is a mild trust signal (though phishing sites increasingly use HTTPS too)." if value else "The URL does not use HTTPS."


def _is_shortened(value, avg, contrib):
    return "The URL uses a known link-shortening service, which hides the true destination." if value else "No link-shortening service detected."


def _has_at_symbol(value, avg, contrib):
    return "The URL contains an '@' symbol, a classic trick for disguising the real destination host." if value else "No '@' symbol found in the URL."


def _suspicious_tld(value, avg, contrib):
    return "The domain uses a top-level domain frequently associated with disposable phishing sites." if value else "The domain's TLD is not on the commonly-abused list."


def _max_char_repeat(value, avg, contrib):
    if avg is not None and value > avg:
        return f"The URL contains an unusually long run of repeated characters ({_fmt(value)} in a row), a sign of randomly generated text."
    return "No unusual repeated-character runs detected."


def _longest_token_length(value, avg, contrib):
    if avg is not None and value > avg:
        return f"The longest single token in the URL ({_fmt(value)} characters) is longer than typical, often seen in obfuscated links."
    return "Token lengths in the URL look ordinary."


def _special_char_ratio(value, avg, contrib):
    if avg is not None and value > avg:
        return "A higher-than-average share of the URL is special characters."
    return "Special-character density looks normal."


def _path_depth(value, avg, contrib):
    if avg is not None and value > avg:
        return f"The URL path is deeper ({_fmt(value)} segments) than average, which can indicate an attempt to bury the real destination."
    return "URL path depth is unremarkable."


def _query_param_count(value, avg, contrib):
    if value > 3:
        return f"The URL carries an unusually large number of query parameters ({_fmt(value)})."
    return "Query parameter count is unremarkable."


def _encoded_char_count(value, avg, contrib):
    if value > 0:
        return f"The URL contains {_fmt(value)} percent-encoded character(s), sometimes used to obscure suspicious content."
    return "No percent-encoded characters found."


def _num_dots(value, avg, contrib):
    if avg is not None and value > avg:
        return f"The URL contains more dots ({_fmt(value)}) than average, often from nested/fake subdomains."
    return f"Dot count ({_fmt(value)}) is unremarkable."


_TEMPLATES = {
    "url_length": _url_length,
    "num_dots": _num_dots,
    "num_hyphens": _num_hyphens,
    "has_ip": _has_ip,
    "has_https": _has_https,
    "suspicious_keyword_count": _suspicious_keyword_count,
    "num_digits": _num_digits,
    "num_subdomains": _num_subdomains,
    "has_at_symbol": _has_at_symbol,
    "is_shortened": _is_shortened,
    "shannon_entropy": _shannon_entropy,
    "digit_ratio": _digit_ratio,
    "special_char_ratio": _special_char_ratio,
    "longest_token_length": _longest_token_length,
    "suspicious_tld": _suspicious_tld,
    "max_char_repeat": _max_char_repeat,
    "path_depth": _path_depth,
    "query_param_count": _query_param_count,
    "encoded_char_count": _encoded_char_count,
    "suspicious_keyword_density": _suspicious_keyword_density,
}


def _describe_feature(name: str, value: Any, contribution: float, phishing_avg: float | None) -> str:
    """Build a single human-readable sentence for one feature's effect."""
    template = _TEMPLATES.get(name)
    if template is None:
        direction = "raises" if contribution > 0 else "lowers"
        return f"{name} ({_fmt(value)}) — {direction} the phishing risk score."
    return template(value, phishing_avg, contribution)


class PhishExplainer:
    """Wraps shap.TreeExplainer for the RandomForest model with plain-English output."""

    def __init__(self, model: Any, feature_thresholds: dict | None = None):
        """
        Args:
            model: Trained RandomForestClassifier (or any SHAP-tree-compatible model).
            feature_thresholds: Optional dict with a "phishing_avg" sub-dict
                (feature_name -> mean value across phishing-labelled training
                URLs), as saved by models/train_model.py into metrics.json.
        """
        self.model = model
        self.feature_names = URLFeatures.feature_names()
        self.phishing_avg = (feature_thresholds or {}).get("phishing_avg", {})
        logger.info("Initialising SHAP TreeExplainer ...")
        self.explainer = shap.TreeExplainer(model)

    def explain(self, feature_vector: list[float], top_k: int = 5) -> dict:
        """Explain a single prediction.

        Args:
            feature_vector: Ordered feature values (see URLFeatures).
            top_k: Number of top contributing features to return.

        Returns:
            dict with `top_features` (list of {feature, value, shap_value,
            explanation}), `base_value`, and a one-sentence `summary`.
        """
        x = np.array(feature_vector, dtype=float).reshape(1, -1)
        shap_values = self.explainer.shap_values(x)

        # shap_values can be a list (per-class), a 2D/3D ndarray, or (in
        # newer SHAP versions) an Explanation object -- normalise all of
        # them to the "phishing" class (label 1) contribution vector.
        if hasattr(shap_values, "values") and not isinstance(shap_values, (list, np.ndarray)):
            arr = np.array(shap_values.values)
            base_value = np.array(shap_values.base_values)
            if arr.ndim == 3:
                class_values = arr[0, :, 1]
                base_value = base_value[0][1] if np.ndim(base_value) > 0 else base_value
            else:
                class_values = arr[0]
                base_value = base_value[0] if np.ndim(base_value) > 0 else base_value
        elif isinstance(shap_values, list):
            class_values = shap_values[1][0]
            base_value = self.explainer.expected_value[1]
        else:
            arr = np.array(shap_values)
            if arr.ndim == 3:  # (n_samples, n_features, n_classes)
                class_values = arr[0, :, 1]
                base_value = self.explainer.expected_value[1]
            else:
                class_values = arr[0]
                base_value = self.explainer.expected_value

        ranked_idx = np.argsort(-np.abs(class_values))[:top_k]

        top_features = []
        for idx in ranked_idx:
            name = self.feature_names[idx]
            value = feature_vector[idx]
            contribution = float(class_values[idx])
            avg = self.phishing_avg.get(name)
            top_features.append(
                {
                    "feature": name,
                    "value": value,
                    "shap_value": round(contribution, 4),
                    "explanation": _describe_feature(name, value, contribution, avg),
                    "direction": "phishing" if contribution > 0 else "legitimate",
                }
            )

        summary = _build_summary(top_features)

        return {
            "base_value": float(base_value),
            "top_features": top_features,
            "summary": summary,
        }


def _build_summary(top_features: list[dict]) -> str:
    """Collapse the top contributing features into one readable sentence."""
    phishing_reasons = [f for f in top_features if f["direction"] == "phishing"]
    if not phishing_reasons:
        return "No strong phishing indicators were found in this URL's structure."
    leads = [f["feature"].replace("_", " ") for f in phishing_reasons[:3]]
    if len(leads) == 1:
        joined = leads[0]
    elif len(leads) == 2:
        joined = f"{leads[0]} and {leads[1]}"
    else:
        joined = f"{', '.join(leads[:-1])}, and {leads[-1]}"
    return f"Flagged primarily due to: {joined}."
