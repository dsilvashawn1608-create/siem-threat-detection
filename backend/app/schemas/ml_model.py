from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class MLModelMetadataRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: str
    model_name: str
    version: str
    file_path: str
    trained_at: datetime
    training_samples: int | None = None
    feature_names: list[str] | None = None
    hyperparameters: dict | None = None
    accuracy: float | None = None
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    is_active: bool


class MLScoreResultOut(BaseModel):
    source_ip: str
    score: float
    is_anomaly: bool
    features: dict[str, float]


class MLScoreResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    model_version: str
    results: list[MLScoreResultOut]
    anomalies_flagged: int


class MLTrainResponse(BaseModel):
    metadata: MLModelMetadataRead
    training_samples: int
    feature_names: list[str]
