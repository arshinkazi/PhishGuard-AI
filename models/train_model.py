"""
train_model.py
---------------
Trains PhishGuard AI's phishing-URL classifier.

Pipeline
--------
1. Load the raw URL dataset (real URLs + ground-truth label).
2. Run every URL through utils.feature_extractor to build the same
   20-feature lexical vector (v2 -- see utils/feature_extractor.py) the
   Flask app will use at inference time.
3. Train a Random Forest (primary model) and a Logistic Regression
   (baseline, for the brief comparison requested in the project scope).
4. Evaluate both on a held-out test split.
5. Compute per-feature phishing-class averages, used by
   utils/explainer.py to generate threshold-aware human explanations
   (e.g. "URL length exceeds the average phishing threshold").
6. Persist the Random Forest as models/model.pkl (used by the web app),
   the Logistic Regression as models/model_lr.pkl (comparison only),
   and a metrics.json summary consumed by the README / dashboard.

Dataset provenance
-------------------
datasets/phishing_dataset_raw.csv contains 11,430 raw URLs with a binary
legitimate/phishing label, taken from the benchmark dataset released by
Hannousse, A. & Yahiouche, S. (2021), "Towards benchmark datasets for
machine learning based website phishing detection: An experimental
study," Engineering Applications of Artificial Intelligence, 104, 104347.
Only the `url` and `status` columns are used -- PhishGuard AI intentionally
re-derives its own lightweight lexical features rather than using the
dataset's original 87 pre-computed (and partly content/host-based)
columns, to keep the whole pipeline URL-string-only and dependency-free.

Usage
-----
    python train_model.py
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

sys.path.append(str(Path(__file__).resolve().parent.parent))
from utils.feature_extractor import URLFeatures, extract_features  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
)
logger = logging.getLogger(__name__)

THIS_DIR = Path(__file__).resolve().parent
DATASET_PATH = THIS_DIR.parent / "datasets" / "phishing_dataset_raw.csv"
MODEL_PATH = THIS_DIR / "model.pkl"
BASELINE_MODEL_PATH = THIS_DIR / "model_lr.pkl"
SCALER_PATH = THIS_DIR / "scaler.pkl"
METRICS_PATH = THIS_DIR / "metrics.json"
RANDOM_STATE = 42


def load_dataset(path: Path) -> pd.DataFrame:
    """Load the raw URL dataset and normalise the label column."""
    logger.info("Loading raw dataset from %s", path)
    df = pd.read_csv(path, usecols=["url", "status"])
    df["label"] = (df["status"].str.strip().str.lower() == "phishing").astype(int)
    df = df.drop(columns=["status"]).dropna(subset=["url"])
    logger.info("Loaded %d rows (%d phishing / %d legitimate)",
                len(df), df["label"].sum(), (df["label"] == 0).sum())
    return df


def build_feature_matrix(urls: pd.Series) -> pd.DataFrame:
    """Vectorise every URL into the lexical feature space."""
    logger.info("Extracting lexical features for %d URLs ...", len(urls))
    rows = []
    failures = 0
    for url in urls:
        try:
            rows.append(extract_features(url).to_list())
        except (ValueError, TypeError):
            failures += 1
            rows.append([0] * len(URLFeatures.feature_names()))
    if failures:
        logger.warning("Failed to parse %d URLs; filled with zero-vectors.", failures)
    return pd.DataFrame(rows, columns=URLFeatures.feature_names())


def compute_feature_thresholds(X: pd.DataFrame, y: pd.Series) -> dict:
    """Per-feature mean values for the phishing vs. legitimate classes.

    Consumed by utils/explainer.py so a single prediction's feature values
    can be compared against "what a typical phishing URL looks like" --
    e.g. "URL length (78) exceeds the average phishing threshold (62)".
    """
    phishing_means = X[y == 1].mean().round(4).to_dict()
    legitimate_means = X[y == 0].mean().round(4).to_dict()
    return {
        "phishing_avg": phishing_means,
        "legitimate_avg": legitimate_means,
    }


def compute_dataset_stats(df: pd.DataFrame, X: pd.DataFrame) -> dict:
    """Summary stats surfaced on the dashboard's 'Dataset Statistics' card."""
    return {
        "total_urls": int(len(df)),
        "phishing_urls": int(df["label"].sum()),
        "legitimate_urls": int((df["label"] == 0).sum()),
        "avg_url_length": round(float(X["url_length"].mean()), 1),
        "avg_phishing_url_length": round(float(X[df["label"] == 1]["url_length"].mean()), 1),
        "avg_legitimate_url_length": round(float(X[df["label"] == 0]["url_length"].mean()), 1),
    }


def evaluate(model, X_test, y_test) -> dict:
    """Compute standard classification metrics for one model."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    cm = confusion_matrix(y_test, y_pred).tolist()
    return {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_test, y_proba), 4),
        "confusion_matrix": cm,  # [[tn, fp], [fn, tp]]
    }


def main() -> None:
    start = time.time()

    df = load_dataset(DATASET_PATH)
    X = build_feature_matrix(df["url"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    logger.info("Train/test split: %d / %d", len(X_train), len(X_test))

    # ---- Primary model: Random Forest -------------------------------
    logger.info("Training Random Forest classifier ...")
    rf_model = RandomForestClassifier(
        n_estimators=120,
        max_depth=10,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf_model.fit(X_train, y_train)
    rf_metrics = evaluate(rf_model, X_test, y_test)
    logger.info("Random Forest metrics: %s", rf_metrics)

    feature_importance = dict(
        zip(URLFeatures.feature_names(), rf_model.feature_importances_.round(4).tolist())
    )

    # ---- Baseline model: Logistic Regression -------------------------
    logger.info("Training Logistic Regression baseline ...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    lr_model = LogisticRegression(max_iter=1000, class_weight="balanced")
    lr_model.fit(X_train_scaled, y_train)
    lr_metrics = evaluate(lr_model, X_test_scaled, y_test)
    logger.info("Logistic Regression metrics: %s", lr_metrics)

    lr_coefficients = dict(
        zip(URLFeatures.feature_names(), lr_model.coef_[0].round(4).tolist())
    )

    # ---- Feature thresholds + dataset stats (for explanations/dashboard) --
    thresholds = compute_feature_thresholds(X, y)
    dataset_stats = compute_dataset_stats(df, X)

    # ---- Persist artefacts --------------------------------------------
    joblib.dump(rf_model, MODEL_PATH)
    joblib.dump(lr_model, BASELINE_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    logger.info("Saved Random Forest -> %s", MODEL_PATH)
    logger.info("Saved Logistic Regression baseline -> %s", BASELINE_MODEL_PATH)

    metrics_summary = {
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_rows": len(df),
        "feature_names": URLFeatures.feature_names(),
        "random_forest": rf_metrics,
        "logistic_regression": lr_metrics,
        "feature_importance": feature_importance,
        "lr_coefficients": lr_coefficients,
        "feature_thresholds": thresholds,
        "dataset_stats": dataset_stats,
    }
    METRICS_PATH.write_text(json.dumps(metrics_summary, indent=2))
    logger.info("Saved metrics summary -> %s", METRICS_PATH)

    logger.info("Done in %.1fs", time.time() - start)
    print("\n=== Model comparison (test set) ===")
    print(f"{'Metric':<12}{'RandomForest':>14}{'LogisticReg':>14}")
    for key in ["accuracy", "precision", "recall", "f1_score", "roc_auc"]:
        print(f"{key:<12}{rf_metrics[key]:>14}{lr_metrics[key]:>14}")


if __name__ == "__main__":
    main()
