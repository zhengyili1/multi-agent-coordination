from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from agents import LLMAdapter
from architectures import collaborative_agents, single_agent, indepenpend_agents
from data_loader import build_package
from evaluator import score, summarize

ARCHITECTURES = {
    "single": ("general", single_agent),
    "independent": ("independent", indepenpend_agents),
    "collaborative": ("collaborative", collaborative_agents),
}


def main(argv: list[str] | None = None, *) -> None:
    parser = argparse.ArgumentParser(description="Run one GUIDE incident-response architecture")
    
    parser.add_argument("--csv", required=True, help="Path to GUIDE_Train.csv")
    parser.add_argument("--org-id")
    parser.add_argument("--incident-id")
    parser.add_argument("--cases", type=int, default=1)
    parser.add_argument("--case-size", type=int, default=120)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--output", default="outputs")
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--architecture", choices=ARCHITECTURES, required=True,
                            help="single, independent, or collaborative")
    args = parser.parse_args(argv)
    
    if bool(args.org_id) != bool(args.incident_id):
        parser.error("--org-id and --incident-id must be supplied together")
    
    architecture = args.architecture
    report_name, architecture_runner = ARCHITECTURES[architecture]
    outdir = Path(args.output) / architecture
    outdir.mkdir(parents=True, exist_ok=True)

    adapter = LLMAdapter(base_url=args.base_url, api_key=args.api_key,
                         model=args.model, offline=args.offline)
    scores = []
    
    for i in range(max(1, args.cases)):
        package = build_package(args.csv, seed=args.seed + i, org_id=args.org_id,
                                incident_id=args.incident_id, case_size=args.case_size)
        case_dir = outdir / package.case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "incident_package.json").write_text(
            json.dumps(package.visible_package(), indent=2), encoding="utf-8")
        (case_dir / "answer.json").write_text(
            json.dumps({"case_id": package.case_id, "IncidentGrade": package.answer}, indent=2), encoding="utf-8")
        report = architecture_runner(package, adapter)
        (case_dir / f"{report_name}.json").write_text(
            json.dumps(asdict(report), indent=2), encoding="utf-8")
        scores.append(score([report], package.answer))
        print(f"{architecture} case {package.case_id}: {report.verdict} (gold={package.answer})")
    (outdir / "case_scores.json").write_text(json.dumps(scores, indent=2), encoding="utf-8")
    summary = summarize(scores)
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
