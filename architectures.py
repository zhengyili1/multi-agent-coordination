from __future__ import annotations

from collections import Counter
from agents import LLMAdapter, general_agent, specialist_team
from knowledge_base import SharedKnowledgeBase
from schema import Finding, IncidentPackage, Report


def _report(name: str, verdict: str, confidence: float, rationale: str,
            findings: list[Finding], *, kb_version: int = 0,
            conflicts: list[str] | None = None, followups: int = 0) -> Report:
    return Report(name, verdict, confidence, rationale,
                  sorted({f.role for f in findings}), [], [],
                  "Propose evidence-preserving next steps for analyst approval; no action executed.",
                  findings, kb_version, conflicts or [], followups)


def single_agent(package: IncidentPackage, adapter: LLMAdapter) -> Report:
    result = general_agent(package.visible_package(), adapter)
    return _report("general", result["verdict"], result["confidence"], result["summary"], [])


def indepenpend_agents(package: IncidentPackage, adapter: LLMAdapter) -> Report:
    view = package.visible_package()
    findings = [agent.investigate(view) for agent in specialist_team(adapter)]
    # The independent condition has no commander/KB and only this fixed reducer sees all reports.
    votes = Counter()
    for f in findings:
        label = next((x for x in ("TruePositive", "BenignPositive", "FalsePositive")
                      if x.lower() in f.summary.lower()), None)
        if label:
            votes[label] += 1
    if not votes:
        result = adapter.classify("Independent fixed reducer", {},
                                  context={"private_specialist_reports": [f.summary for f in findings]})
        verdict, confidence, rationale = result["verdict"], result["confidence"], result["summary"]
    else:
        verdict, n = votes.most_common(1)[0]
        confidence, rationale = n / len(findings), "Fixed majority over independent specialist classifications; agents could not share evidence or request follow-up."
    return _report("independent", verdict, confidence, rationale, findings)


def collaborative_agents(package: IncidentPackage, adapter: LLMAdapter) -> Report:
    agents = specialist_team(adapter)
    kb = SharedKnowledgeBase()
    view = package.visible_package()
    # Specialists see only their assigned artifact even in the collaborative condition.
    for agent in agents:
        kb.add(agent.investigate(view))
    return IncidentCommander(adapter).orchestrate(package, agents, kb)


class IncidentCommander:
    """Orchestrator reviewing the shared KB, deciding on a bounded follow-up, and classifying."""
    def __init__(self, adapter: LLMAdapter):
        self.adapter = adapter

    def orchestrate(self, package: IncidentPackage, agents, kb: SharedKnowledgeBase) -> Report:
        # Detect missing specialist submissions. At most one follow-up call is allowed.
        submitted = {f.role for f in kb.findings}
        missing = [agent for agent in agents if agent.role not in submitted]
        followups = 0
        if missing:
            target = missing[0]
            followup = target.investigate(package.visible_package(), context={
                "shared_knowledge_base": kb.view(),
                "request": "Submit the missing specialist assessment. Use only your assigned artifact."})
            kb.add(followup)
            followups = 1
        history = package.artifacts["history"]
        result = self.adapter.classify("Incident Commander / Orchestrator",
            {"incident_history": {"artifact_id": history.artifact_id, "rows": history.rows,
                                  "caveat": history.caveat}},
            context={"shared_knowledge_base": kb.view(),
                     "task": "Resolve conflicting findings, identify gaps, classify using only supported evidence. "
                             "Return a JSON classification and rationale."})
        verdicts = [label for finding in kb.findings for label in
                    ("TruePositive", "BenignPositive", "FalsePositive")
                    if label.lower() in finding.summary.lower()]
        conflicts = ["Specialist claims contain different explicit classifications."] if len(set(verdicts)) > 1 else []
        return _report("collaborative", result["verdict"], result["confidence"], result["summary"],
                       kb.findings, kb_version=kb.version, conflicts=conflicts, followups=followups)
