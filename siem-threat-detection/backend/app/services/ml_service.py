"""Phase 6: Isolation Forest-based anomaly detection over Alert history.

Design:
  - Feature extraction turns each Alert row into a small numeric feature
    vector (counts/rates by source_ip over a trailing window, severity
    encoded, distinct dest ports touched, protocol one-hot, etc.) rather
    than scoring one alert in isolation — a single alert has almost no
    signal, but "this source_ip just produced an unusual volume/shape of
    traffic" does.
  - Training fits sklearn's IsolationForest on the current feature table,
    persists the fitted pipeline (model + the feature column order it
    expects) to a joblib file under `settings.ml_model_dir`, and records
    an `MLModelMetadata` row (deactivating any previously active version
    for the same model_name).
  - Scoring loads the active model, recomputes the same feature vector for
    a source_ip (or for every source_ip with recent activity), and returns
    the IsolationForest decision_function score. More negative = more
    anomalous. Alerts whose source_ip scores below
    `settings.ml_anomaly_severity_threshold` get a synthetic ML_ANOMALY
    alert created (idempotent per source_ip+window via external_id).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import Settings
from app.logging_config import get_logger
from app.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus
from app.models.ml_model_metadata import MLModelMetadata
from app.services.alert_ingest import get_or_create_alert

logger = get_logger(__name__)

FEATURE_NAMES: list[str] = [
    "alert_count",
    "distinct_signatures",
    "distinct_dest_ips",
    "distinct_dest_ports",
    "max_severity_score",
    "avg_severity_score",
    "critical_ratio",
]

_SEVERITY_SCORE = {
    AlertSeverity.LOW: 1.0,
    AlertSeverity.MEDIUM: 2.0,
    AlertSeverity.HIGH: 3.0,
    AlertSeverity.CRITICAL: 4.0,
}


@dataclass
class TrainingResult:
    metadata: MLModelMetadata
    training_samples: int
    feature_names: list[str]


@dataclass
class ScoreResult:
    source_ip: str
    score: float
    is_anomaly: bool
    features: dict[str, float]


def _model_path(settings: Settings, version: str) -> Path:
    directory = Path(settings.ml_model_dir)
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{settings.ml_model_name}-{version}.joblib"


def build_feature_table(db: Session, window_seconds: float) -> pd.DataFrame:
    """One row per source_ip that has produced at least one alert within
    the trailing window, with the FEATURE_NAMES columns populated."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    rows = (
        db.query(Alert)
        .filter(Alert.source_ip.isnot(None), Alert.created_at >= cutoff)
        .all()
    )
    if not rows:
        return pd.DataFrame(columns=["source_ip", *FEATURE_NAMES])

    by_ip: dict[str, list[Alert]] = {}
    for alert in rows:
        by_ip.setdefault(alert.source_ip, []).append(alert)

    records = []
    for source_ip, alerts in by_ip.items():
        severities = [_SEVERITY_SCORE.get(a.severity, 2.0) for a in alerts]
        critical_count = sum(1 for a in alerts if a.severity == AlertSeverity.CRITICAL)
        records.append(
            {
                "source_ip": source_ip,
                "alert_count": float(len(alerts)),
                "distinct_signatures": float(len({a.signature for a in alerts})),
                "distinct_dest_ips": float(len({a.dest_ip for a in alerts if a.dest_ip})),
                "distinct_dest_ports": float(
                    len({a.dest_port for a in alerts if a.dest_port is not None})
                ),
                "max_severity_score": max(severities),
                "avg_severity_score": sum(severities) / len(severities),
                "critical_ratio": critical_count / len(alerts),
            }
        )
    return pd.DataFrame.from_records(records)


def train_model(db: Session, settings: Settings) -> TrainingResult:
    window_seconds = max(settings.sync_interval_seconds * 100, 86400.0)
    table = build_feature_table(db, window_seconds=window_seconds)

    if len(table) < settings.ml_min_training_samples:
        raise ValueError(
            f"Not enough samples to train: have {len(table)}, "
            f"need >= {settings.ml_min_training_samples}. "
            "Ingest more alerts (or lower ml_min_training_samples) first."
        )

    X = table[FEATURE_NAMES].to_numpy(dtype=float)
    model = IsolationForest(
        contamination=settings.ml_contamination,
        random_state=42,
        n_estimators=100,
    )
    model.fit(X)

    scores = model.decision_function(X)
    predicted_anomalies = model.predict(X)  # -1 anomaly, 1 normal
    # Self-evaluation proxy: treat the model's own flagged fraction as a
    # sanity-check "precision-ish" figure — there's no ground-truth label
    # in a lab dataset, so this is explicitly a training-time diagnostic,
    # not a held-out metric.
    anomaly_fraction = float((predicted_anomalies == -1).mean())

    version = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = _model_path(settings, version)
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, path)

    # Deactivate any previously active version of this model.
    db.query(MLModelMetadata).filter(
        MLModelMetadata.model_name == settings.ml_model_name,
        MLModelMetadata.is_active.is_(True),
    ).update({"is_active": False})

    metadata = MLModelMetadata(
        model_name=settings.ml_model_name,
        version=version,
        file_path=str(path),
        training_samples=len(table),
        feature_names=FEATURE_NAMES,
        hyperparameters={
            "contamination": settings.ml_contamination,
            "n_estimators": 100,
            "random_state": 42,
            "window_seconds": window_seconds,
        },
        accuracy=None,
        precision=None,
        recall=None,
        f1_score=round(1.0 - anomaly_fraction, 4),
        is_active=True,
    )
    db.add(metadata)
    db.commit()
    db.refresh(metadata)

    logger.info(
        "ml_model_trained",
        extra={"model_name": metadata.model_name, "version": metadata.version,
               "training_samples": metadata.training_samples},
    )
    return TrainingResult(
        metadata=metadata, training_samples=len(table), feature_names=FEATURE_NAMES
    )


def _load_active_model(db: Session, settings: Settings) -> tuple[MLModelMetadata, IsolationForest, list[str]]:
    metadata = (
        db.query(MLModelMetadata)
        .filter(
            MLModelMetadata.model_name == settings.ml_model_name,
            MLModelMetadata.is_active.is_(True),
        )
        .order_by(MLModelMetadata.created_at.desc())
        .first()
    )
    if metadata is None:
        raise ValueError(
            f"No active trained model named '{settings.ml_model_name}'. Train one first via "
            "POST /api/v1/ml/train."
        )
    bundle = joblib.load(metadata.file_path)
    return metadata, bundle["model"], bundle["feature_names"]


def score_all(db: Session, settings: Settings) -> list[ScoreResult]:
    metadata, model, feature_names = _load_active_model(db, settings)
    window_seconds = (metadata.hyperparameters or {}).get(
        "window_seconds", max(settings.sync_interval_seconds * 100, 86400.0)
    )
    table = build_feature_table(db, window_seconds=window_seconds)
    if table.empty:
        return []

    X = table[feature_names].to_numpy(dtype=float)
    scores = model.decision_function(X)

    results: list[ScoreResult] = []
    for (idx, row), score in zip(table.iterrows(), scores):
        is_anomaly = bool(score < settings.ml_anomaly_severity_threshold)
        results.append(
            ScoreResult(
                source_ip=row["source_ip"],
                score=float(score),
                is_anomaly=is_anomaly,
                features={name: float(row[name]) for name in feature_names},
            )
        )
    return sorted(results, key=lambda r: r.score)


def score_and_create_anomaly_alerts(db: Session, settings: Settings) -> list[Alert]:
    """Runs score_all() and, for every source_ip flagged as anomalous,
    creates (idempotently, one per day per source_ip) an Alert with
    source=ML_ANOMALY so it flows through the same triage/correlation
    pipeline as Snort/Splunk alerts."""
    results = score_all(db, settings)
    day_bucket = datetime.now(timezone.utc).strftime("%Y%m%d")
    created: list[Alert] = []

    for result in results:
        if not result.is_anomaly:
            continue
        external_id = f"ml_anomaly:{result.source_ip}:{day_bucket}"
        alert, was_created = get_or_create_alert(
            db,
            external_id=external_id,
            source=AlertSource.ML_ANOMALY,
            severity=AlertSeverity.HIGH
            if result.score < settings.ml_anomaly_severity_threshold * 2
            else AlertSeverity.MEDIUM,
            signature="ML anomaly: unusual alert pattern for source_ip",
            description=(
                f"IsolationForest flagged source_ip={result.source_ip} with "
                f"decision_function score={result.score:.4f} "
                f"(threshold={settings.ml_anomaly_severity_threshold})."
            ),
            source_ip=result.source_ip,
            confidence_score=result.score,
            raw_data={"features": result.features, "score": result.score},
        )
        if was_created and alert is not None:
            created.append(alert)
    if created:
        db.commit()
        for alert in created:
            db.refresh(alert)
    return created
