from __future__ import annotations

from dataclasses import asdict
from .schema import Finding


class SharedKnowledgeBase:
    """Append-only, versioned findings ledger with source-artifact provenance."""
    def __init__(self):
        self.version = 0
        self.findings: list[Finding] = []
        self.decisions: list[dict] = []

    def add(self, finding: Finding) -> bool:
        key = (finding.agent, finding.summary, tuple(finding.source_artifacts))
        if any((f.agent, f.summary, tuple(f.source_artifacts)) == key for f in self.findings):
            self.decisions.append({"event": "duplicate_suppressed", "agent": finding.agent,
                                   "summary": finding.summary, "version": self.version})
            return False
        self.findings.append(finding)
        self.version += 1
        self.decisions.append({"event": "finding_added", "agent": finding.agent,
                               "sources": finding.source_artifacts, "version": self.version})
        return True

    def view(self) -> dict:
        return {"version": self.version,
                "findings": [asdict(f) for f in self.findings],
                "decisions": list(self.decisions)}
