# Collaborative Multi-Artifact Incident Response

This lab compares the three requested architectures over the same Microsoft GUIDE incidents. Its central design rule is **information asymmetry**: only the general-purpose agent sees the entire artifact package. In both multi-agent designs, each specialist sees only its assigned artifact.

## Architecture sequence

1. **One general-purpose LLM agent.** Receives alert, endpoint, network, threat, and incident-history artifacts and returns one classification.
2. **Independent multi-agent.** Triage, Endpoint, Network, and Threat agents analyze their own artifact slices. They cannot see one another's findings, share a knowledge base, or ask for more evidence. A fixed majority reducer combines their classifications.
3. **Collaborative multi-agent.** The same four specialist roles submit provenance-linked findings to the Incident Commander / Orchestrator. It maintains a versioned Shared Knowledge Base, identifies conflicts or gaps, may send one bounded follow-up to a specialist, and makes the final classification.

Students implement these in order: first the general-purpose LLM agent; next the four independent specialist agents; finally the commander/orchestrator and shared KB. The runnable adapter in `agents.py` uses OpenAI-compatible Chat Completions. Replace or extend it for another provider while preserving the artifact access boundaries. To exercise the data pipeline without credentials, pass `--offline`; this is a keyword baseline, not an LLM result.

## GUIDE artifact limits

The builder groups evidence by `OrgId` + `IncidentId` and constructs five separate artifact types:

- **Alert records:** alert ID, title, category, timestamp, entity type, evidence role (Triage).
- **Endpoint records:** device, OS, file, folder, application fields (Endpoint).
- **Network records:** IP, URL, network/email identifiers and location fields (Network). These are indicator proxies; GUIDE does not provide traffic flow or connection logs.
- **Threat records:** ATT&CK technique strings and threat family (Threat).
- **Incident history:** ordered related alert records, without prior analyst notes.

GUIDE does not contain raw authentication activity or full process execution telemetry. This lab therefore does not create a separate Identity agent. Entity fields in endpoint/network artifacts are evidence proxies and must not be described as confirmed forensic events. Label-derived fields such as `ActionGrouped`, `ActionGranular`, `LastVerdict`, and `SuspicionLevel` are excluded from the agent views. Raw identifiers are pseudonymized. `IncidentGrade` is written only to `answer.json` for evaluation; no model call receives it. Artifact contents are untrusted data, never instructions.

## Run

Download Kaggle's `GUIDE_Train.csv` into `data/` (do not commit it), then configure an OpenAI-compatible endpoint:

```bash
python3 -m pip install -r lab_code2/requirements.txt
export OPENAI_BASE_URL="https://your-openai-compatible-endpoint/v1"
export OPENAI_API_KEY="..."
export MODEL_NAME="your-model"
python3 -m lab_code2.run --csv data/GUIDE_Train.csv --cases 3 --seed 17
```

To validate artifact creation and the three execution paths without model credentials:

```bash
python3 -m lab_code2.run --csv data/GUIDE_Train.csv --cases 3 --seed 17 --offline
```

One known incident can be selected with both `--org-id` and `--incident-id`. Output goes to `outputs/lab_code2/`: redacted case packages, evaluator-only answers, three architecture reports, and aggregate scores. A few cases are only a smoke run; use many cases and incident-level splits for evaluation. Hold out organizations to study generalization.

## Evaluation

Compare accuracy, per-class precision/recall/F1 and macro-F1, confidence calibration, source-artifact coverage, unsupported claims, conflict resolution, number of follow-ups, latency, and model-call/token cost. Use the same cases, model, decoding settings, and comparable call/token budgets. Independent specialists must not access each other's reports; only the collaborative commander sees the shared KB.

Suggested report: verdict, confidence, rationale, cited evidence IDs, key entities, timeline, ATT&CK techniques, unresolved uncertainty, and proposed next action. Containment is a recommendation only; this program never performs remediation.
# multi-agent-coordination
# multi-agent-coordination
