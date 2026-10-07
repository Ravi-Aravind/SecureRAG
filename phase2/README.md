# ClaimGuard Phase 2

Status: primary matrix rerun after applicability resolver correction. ClaimGuard contradicted 2/2 verifiable incorrect Condition C claims; 10/12 incorrect claims remain UNVERIFIABLE. See the final report for denominators and limits.

Read [Phase 2 Specification v1.0](docs/phase2_design.md) and [final report](results/derived/phase2_final_report.md). The NVD manifest is `config/kb_snapshot_manifest.json`; original official feeds and metadata are in `data/nvd/`. Run audits are in `results/audits/` and per-CVE records are in `results/raw/`.

Validate software and frozen inputs:

```powershell
python -m unittest discover -s phase2/validation -p 'test_*.py' -v
python phase2/validation/validate_inputs.py
python phase2/runners/run_evaluation.py --dry-run
```

Reproduce the selected-CVE audit, validate the pinned snapshot, run the matrix, and derive metrics with the commands in the final report. The feeds are already locally available; no live NVD/API call is needed for experiment execution.
