from __future__ import annotations

from collections import Counter
from .schema import LABELS, Report


def score(reports: list[Report], answer: str) -> dict:
    out = {"answer": answer, "architectures": {}}
    for report in reports:
        correct = report.verdict == answer
        out["architectures"][report.architecture] = {
            "verdict": report.verdict, "correct": correct,
            "confidence": round(report.confidence, 3),
            "brier_one_case": round((report.confidence - float(correct)) ** 2, 3),
            "findings": len(report.findings), "unique_source_artifacts": len({s for f in report.findings for s in f.source_artifacts}),
            "kb_version": report.kb_version, "followups": report.followups,
            "conflicts": report.conflicts,
        }
    return out


def summarize(rows: list[dict]) -> dict:
    """Across cases: accuracy and per-class precision/recall/F1 plus macro-F1."""
    result = {}
    for architecture in ("general", "independent", "collaborative"):
        pairs = [(r["answer"], r["architectures"][architecture]["verdict"]) for r in rows]
        per_class = {}
        f1s = []
        for label in LABELS:
            tp = sum(a == label and p == label for a, p in pairs)
            fp = sum(a != label and p == label for a, p in pairs)
            fn = sum(a == label and p != label for a, p in pairs)
            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            per_class[label] = {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}
            f1s.append(f1)
        result[architecture] = {"accuracy": round(sum(a == p for a, p in pairs) / len(pairs), 3) if pairs else 0,
                                "macro_f1": round(sum(f1s) / len(f1s), 3), "per_class": per_class,
                                "cases": len(pairs)}
    return result
