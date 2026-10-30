from __future__ import annotations

import hashlib
import random
from pathlib import Path
from typing import Any


from schema import Artifact, IncidentPackage, LABELS


IDENTIFIER_COLUMNS = {
    "AccountUpn", "AccountName", "AccountSid", "AccountObjectId", "DeviceName",
    "DeviceId", "IpAddress", "Url", "Sha256", "FileName", "FolderPath",
    "NetworkMessageId", "EmailClusterId", "RegistryKey", "RegistryValueName",
    "RegistryValueData", "ApplicationName", "ResourceIdName",
}
USE_COLUMNS = {
    "Id", "OrgId", "IncidentId", "AlertId", "Timestamp", "AlertTitle", "Category",
    "MitreTechniques", "IncidentGrade", "EntityType", "EvidenceRole", "DeviceId",
    "DeviceName", "OSFamily", "OSVersion", "FileName", "FolderPath", "ThreatFamily",
    "IpAddress", "Url", "AccountUpn", "AccountName", "AccountSid", "AccountObjectId",
    "NetworkMessageId", "EmailClusterId", "ApplicationName", "ResourceType",
    "CountryCode", "State", "City", "ProcessName", "ProcessCommandLine",
}


def _token(value: Any, salt: str) -> str:
    if value is None or str(value).strip() in {"", "nan", "<NA>"}:
        return ""
    return hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:10]


def _safe(value: Any) -> str:
    return "" if value is None or str(value) in {"<NA>", "nan"} else str(value)


def select_incident(csv_path: str | Path, *, seed: int = 17,
                    org_id: str | None = None, incident_id: str | None = None,
                    sample_rows: int = 100_000) -> tuple[str, str]:
    import pandas as pd

    if org_id is not None and incident_id is not None:
        return str(org_id), str(incident_id)
    rng = random.Random(seed)
    choices: list[tuple[str, str]] = []
    for chunk in pd.read_csv(csv_path, usecols=lambda c: c in {"OrgId", "IncidentId", "IncidentGrade"},
                             dtype="string", chunksize=sample_rows, low_memory=False):
        chunk = chunk[chunk.IncidentGrade.isin(LABELS)]
        counts = chunk.groupby(["OrgId", "IncidentId"], dropna=True).size()
        choices.extend((str(org), str(inc)) for (org, inc), n in counts.items() if n >= 2)
        if len(choices) > 30000:
            choices = rng.sample(choices, 15000)
    if not choices:
        raise ValueError("Could not find a labeled incident with at least two rows")
    return rng.choice(choices)


def build_package(csv_path: str | Path, *, seed: int = 17, org_id: str | None = None,
                  incident_id: str | None = None, case_size: int = 120) -> IncidentPackage:
    import pandas as pd
    org, incident = select_incident(csv_path, seed=seed, org_id=org_id, incident_id=incident_id)
    pieces = []
    for chunk in pd.read_csv(csv_path, usecols=lambda c: c in USE_COLUMNS,
                             dtype="string", chunksize=100_000, low_memory=False):
        selected = chunk[(chunk.OrgId == org) & (chunk.IncidentId == incident)]
        if not selected.empty:
            pieces.append(selected)
    if not pieces:
        raise ValueError("Selected incident was not found while loading artifact fields")
    frame = pd.concat(pieces, ignore_index=True)
    labels = set(frame.IncidentGrade.dropna().astype(str))
    if len(labels) != 1 or next(iter(labels), "") not in LABELS:
        raise ValueError(f"Incident grade is missing or inconsistent: {labels}")
    answer = labels.pop()
    frame = frame.sort_values("Timestamp", kind="stable").head(max(1, min(case_size, 1000))).fillna("")
    case_id = hashlib.sha256(f"{org}:{incident}".encode()).hexdigest()[:12]
    salt = case_id
    artifacts: dict[str, Artifact] = {}

    def records(kind: str, fields: list[str], transform=None) -> Artifact:
        rows = []
        for _, row in frame.iterrows():
            record = {k: _safe(row.get(k, "")) for k in fields if k in frame.columns}
            record["evidence_id"] = f"{kind[:3].upper()}-{_safe(row.get('Id', ''))}"
            if transform:
                record = transform(record)
            rows.append(record)
        return Artifact(f"{kind}-{case_id}", kind, rows)

    alert_fields = ["Id", "AlertId", "Timestamp", "AlertTitle", "Category", "EntityType", "EvidenceRole"]
    artifacts["alert"] = records("alert", alert_fields)
    endpoint_fields = ["Id", "Timestamp", "DeviceId", "DeviceName", "OSFamily", "OSVersion", "FileName", "FolderPath", "ApplicationName", "EntityType"]
    def endpoint_transform(row):
        for key in ("DeviceId", "DeviceName", "FileName", "FolderPath", "ApplicationName"):
            if row.get(key): row[key] = _token(row[key], salt)
        return row
    artifacts["endpoint"] = records("endpoint", endpoint_fields, endpoint_transform)
    identity_fields = ["Id", "Timestamp", "AccountUpn", "AccountName", "AccountSid", "AccountObjectId", "EntityType", "EvidenceRole"]
    def identity_transform(row):
        for key in list(row):
            if key in IDENTIFIER_COLUMNS and row[key]: row[key] = _token(row[key], salt)
        row["record_type"] = "identity_entity_proxy"
        return row
    artifacts["identity"] = records("identity", identity_fields, identity_transform)
    network_fields = ["Id", "Timestamp", "IpAddress", "Url", "NetworkMessageId", "EmailClusterId", "CountryCode", "State", "City", "EntityType"]
    def network_transform(row):
        for key in ("IpAddress", "Url", "NetworkMessageId", "EmailClusterId"):
            if row.get(key): row[key] = _token(row[key], salt)
        row["record_type"] = "network_indicator_proxy; no connection/flow telemetry in GUIDE"
        return row
    artifacts["network"] = records("network", network_fields, network_transform)
    threat_fields = ["Id", "Timestamp", "MitreTechniques", "ThreatFamily", "Category", "AlertTitle"]
    artifacts["threat"] = records("threat", threat_fields)
    history_rows = []
    for _, row in frame.iterrows():
        history_rows.append({"evidence_id": f"HIS-{_safe(row.get('Id', ''))}",
                             "timestamp": _safe(row.get("Timestamp", "")),
                             "alert_id": _safe(row.get("AlertId", "")),
                             "title": _safe(row.get("AlertTitle", "")),
                             "category": _safe(row.get("Category", ""))})
    artifacts["history"] = Artifact(f"history-{case_id}", "incident_history", history_rows,
                                      "Only alert history available; no prior analyst notes supplied.")
    return IncidentPackage(case_id, artifacts, answer, history_rows)

