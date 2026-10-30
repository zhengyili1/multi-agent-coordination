from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


LABELS = ("TruePositive", "BenignPositive", "FalsePositive")


@dataclass
class Artifact:
    artifact_id: str
    kind: str
    rows: list[dict[str, Any]]
    caveat: str = ""


@dataclass
class IncidentPackage:
    case_id: str
    artifacts: dict[str, Artifact]
    answer: str
    incident_history: list[dict[str, Any]] = field(default_factory=list)

    def visible_package(self) -> dict[str, Any]:
        return {"case_id": self.case_id,
                "artifacts": {k: asdict(v) for k, v in self.artifacts.items()},
                "incident_history": self.incident_history}


@dataclass
class Finding:
    agent: str
    role: str
    summary: str
    observations: list[str]
    source_artifacts: list[str]
    confidence: float
    uncertainties: list[str] = field(default_factory=list)


@dataclass
class Report:
    architecture: str
    verdict: str
    confidence: float
    rationale: str
    key_entities: list[str]
    timeline: list[str]
    techniques: list[str]
    proposed_next_action: str
    findings: list[Finding] = field(default_factory=list)
    kb_version: int = 0
    conflicts: list[str] = field(default_factory=list)
    followups: int = 0

