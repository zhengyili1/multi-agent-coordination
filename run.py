from __future__ import annotations

# Allow this package-style module to run as `python3 run.py`, `python3 -m run`,
# or (on Python versions that accept it) `python3 -m run.py`.
if __package__ in (None, ""):
    import sys
    import types
    from pathlib import Path as _Path

    __package__ = "multi_artifact_incident_response"
    _package = types.ModuleType(__package__)
    _package.__path__ = [str(_Path(__file__).resolve().parent)]
    sys.modules.setdefault(__package__, _package)

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .agents import LLMAdapter
from .architectures import run_collaborative, run_general, run_independent
from .data_loader import build_package
from .evaluator import score, summarize


def main() -> None:
    p = argparse.ArgumentParser(description="Compare three GUIDE incident-response architectures")
    p.add_argument("--csv", required=True, help="Path to GUIDE_Train.csv")
    p.add_argument("--org-id")
    p.add_argument("--incident-id")
    p.add_argument("--cases", type=int, default=1)
    p.add_argument("--case-size", type=int, default=120)
    p.add_argument("--seed", type=int, default=17)
    p.add_argument("--output", default="outputs/lab_code2")
    p.add_argument("--base-url", default=None)
    p.add_argument("--api-key", default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--offline", action="store_true", help="Use deterministic keyword baseline instead of calling an LLM")
    args = p.parse_args()
    if bool(args.org_id) != bool(args.incident_id):
        p.error("--org-id and --incident-id must be supplied together")
    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    adapter = LLMAdapter(base_url=args.base_url, api_key=args.api_key,
                         model=args.model, offline=args.offline)
    scores = []
    for i in range(max(1, args.cases)):
        package = build_package(args.csv, seed=args.seed + i, org_id=args.org_id,
                                incident_id=args.incident_id, case_size=args.case_size)
        base = outdir / package.case_id
        base.mkdir(parents=True, exist_ok=True)
        (base / "incident_package.json").write_text(json.dumps(package.visible_package(), indent=2), encoding="utf-8")
        (base / "answer.json").write_text(json.dumps({"case_id": package.case_id, "IncidentGrade": package.answer}, indent=2), encoding="utf-8")
        reports = [run_general(package, adapter), run_independent(package, adapter), run_collaborative(package, adapter)]
        for report in reports:
            (base / f"{report.architecture}.json").write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        scores.append(score(reports, package.answer))
        print(f"case {package.case_id}: " + ", ".join(f"{r.architecture}={r.verdict}" for r in reports) + f" (gold={package.answer})")
    (outdir / "case_scores.json").write_text(json.dumps(scores, indent=2), encoding="utf-8")
    summary = summarize(scores)
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
