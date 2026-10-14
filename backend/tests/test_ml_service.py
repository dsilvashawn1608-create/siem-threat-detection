from __future__ import annotations

import pytest

from app.models.alert import Alert, AlertSeverity, AlertSource
from app.services import ml_service


def _seed_alerts(db, n_ips=5, alerts_per_ip=5):
    for i in range(n_ips):
        for j in range(alerts_per_ip):
            db.add(
                Alert(
                    source=AlertSource.SNORT,
                    severity=AlertSeverity.MEDIUM if j % 3 else AlertSeverity.CRITICAL,
                    signature=f"sig-{j % 2}",
                    source_ip=f"10.0.0.{i}",
                    dest_ip="10.0.0.254",
                    dest_port=80 + j,
                )
            )
    db.commit()


def test_build_feature_table_shapes(db_session):
    _seed_alerts(db_session, n_ips=3, alerts_per_ip=4)
    table = ml_service.build_feature_table(db_session, window_seconds=86400)
    assert len(table) == 3
    for col in ml_service.FEATURE_NAMES:
        assert col in table.columns


def test_build_feature_table_empty(db_session):
    table = ml_service.build_feature_table(db_session, window_seconds=86400)
    assert table.empty


def test_train_model_insufficient_samples_raises(db_session, test_settings):
    _seed_alerts(db_session, n_ips=1, alerts_per_ip=1)
    with pytest.raises(ValueError):
        ml_service.train_model(db_session, test_settings)


def test_train_model_persists_and_registers_metadata(db_session, test_settings):
    _seed_alerts(db_session, n_ips=5, alerts_per_ip=6)
    result = ml_service.train_model(db_session, test_settings)

    assert result.training_samples == 5
    assert result.metadata.is_active is True
    assert result.metadata.f1_score is None

    from pathlib import Path

    assert Path(result.metadata.file_path).exists()


def test_active_model_path_must_remain_in_configured_directory(
    db_session, test_settings, tmp_path
):
    _seed_alerts(db_session, n_ips=5, alerts_per_ip=6)
    result = ml_service.train_model(db_session, test_settings)
    result.metadata.file_path = str(tmp_path / "outside.joblib")
    db_session.commit()

    with pytest.raises(ValueError, match="outside the configured model directory"):
        ml_service.score_all(db_session, test_settings)


def test_train_model_deactivates_previous_version(db_session, test_settings):
    _seed_alerts(db_session, n_ips=5, alerts_per_ip=6)
    first = ml_service.train_model(db_session, test_settings)
    second = ml_service.train_model(db_session, test_settings)

    db_session.refresh(first.metadata)
    assert first.metadata.is_active is False
    assert second.metadata.is_active is True


def test_score_all_without_trained_model_raises(db_session, test_settings):
    with pytest.raises(ValueError):
        ml_service.score_all(db_session, test_settings)


def test_score_all_returns_sorted_results(db_session, test_settings):
    _seed_alerts(db_session, n_ips=6, alerts_per_ip=6)
    # Make one source_ip a clear outlier.
    for _ in range(40):
        db_session.add(
            Alert(
                source=AlertSource.SNORT,
                severity=AlertSeverity.CRITICAL,
                signature="outlier sig",
                source_ip="10.0.0.254",
                dest_ip="10.0.0.254",
                dest_port=9999,
            )
        )
    db_session.commit()

    ml_service.train_model(db_session, test_settings)
    results = ml_service.score_all(db_session, test_settings)

    assert len(results) >= 6
    # Sorted ascending by score (most anomalous first).
    assert results[0].score <= results[-1].score


def test_score_all_returns_empty_when_no_alerts_in_window(db_session, test_settings):
    _seed_alerts(db_session, n_ips=5, alerts_per_ip=6)
    ml_service.train_model(db_session, test_settings)

    # Wipe all alerts so a subsequent score_all() sees an empty feature table.
    db_session.query(Alert).delete()
    db_session.commit()

    results = ml_service.score_all(db_session, test_settings)
    assert results == []


def test_score_and_create_anomaly_alerts_skips_non_anomalous_results(db_session, test_settings):
    _seed_alerts(db_session, n_ips=6, alerts_per_ip=6)
    for _ in range(40):
        db_session.add(
            Alert(
                source=AlertSource.SNORT,
                severity=AlertSeverity.CRITICAL,
                signature="outlier sig",
                source_ip="10.0.0.254",
                dest_ip="10.0.0.254",
                dest_port=9999,
            )
        )
    db_session.commit()

    # Default (strict negative) threshold — only the genuine outlier should
    # flag, so at least one scored source_ip is skipped via the non-anomalous
    # branch in score_and_create_anomaly_alerts.
    ml_service.train_model(db_session, test_settings)
    all_results = ml_service.score_all(db_session, test_settings)
    created = ml_service.score_and_create_anomaly_alerts(db_session, test_settings)

    assert len(created) < len(all_results)


def test_score_and_create_anomaly_alerts_is_idempotent(db_session, test_settings):
    _seed_alerts(db_session, n_ips=5, alerts_per_ip=6)
    for _ in range(40):
        db_session.add(
            Alert(
                source=AlertSource.SNORT,
                severity=AlertSeverity.CRITICAL,
                signature="outlier sig",
                source_ip="10.0.0.254",
                dest_ip="10.0.0.254",
                dest_port=9999,
            )
        )
    db_session.commit()

    test_settings.ml_anomaly_severity_threshold = 10.0  # force everything "anomalous"
    ml_service.train_model(db_session, test_settings)

    created_first = ml_service.score_and_create_anomaly_alerts(db_session, test_settings)
    created_second = ml_service.score_and_create_anomaly_alerts(db_session, test_settings)

    assert len(created_first) > 0
    assert created_first[0].confidence_score is None
    assert "score" in created_first[0].raw_data
    assert len(created_second) == 0  # same-day external_id dedupes
