# Finish The Vision

## Meaning
This repository now has a single top-level command for driving the production vision to completion through the 14-day finisher gates.

## One Command
PowerShell:

```powershell
./Finish-The-Vision.ps1
```

Fast validation mode:

```powershell
./Finish-The-Vision.ps1 -Fast
```

Fast mode keeps strict scoring but skips heavyweight build, test, and runtime-probe work where the finisher pipeline is explicitly configured to allow safe verification.

## What It Does
- Executes the 14-day production finisher pipeline
- Enforces strict gating by default
- Writes JSON and Markdown reports under `reports/14day`
- Prints the final scorecard after a successful run
- In fast mode, performs structural validation instead of full heavy execution on selected gates

## Core Files
- `Finish-The-Vision.ps1`
- `Run-14Day-ProductionFinishers.ps1`
- `scripts/production/Invoke-14Day-ProductionFinishers.ps1`
- `14_DAY_PRODUCTION_FINISHERS_PLAN.md`
- `reports/14day/final_scorecard.md`

## Output of Success
A successful run ends with:
- `reports/14day/final_scorecard.md`
- `Status: PASS`
- `Failed Day Reports: 0`

## Working Rule
When the goal is to finish and verify the production roadmap rather than just build one artifact, use `Finish-The-Vision.ps1` first.
