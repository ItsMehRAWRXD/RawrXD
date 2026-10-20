# Deep2 TPS campaign evaluator

`deep2_tps_campaign_evaluator.ps1` is a read-only evaluator for mutation campaign receipts. It does not launch a model, modify the active source tree, promote a candidate, or alter weights.

It extracts route configuration and TPS samples, then evaluates:

- `G1`: SPIR-V validation exit code;
- `G2`: independent parity/hash evidence explicitly present in the captured logs;
- `G3`: zero host fallback, NaN/Inf, and fence failures;
- `G4`: the required number of valid samples;
- `G5`: checkpoint threshold, default `40 TPS`;
- `G6`: improvement over the accepted baseline;
- `G7`: restoration/rebuild status.

Missing parity or hash evidence is recorded as `MISSING`, never as a pass. A checkpoint is written only when `G1`–`G5` pass. Promotion eligibility additionally requires `G6` and `G7`. Every candidate evaluation is appended as one JSON object per line to `evidence_ledger.jsonl`.

Example:

```powershell
pwsh -NoProfile -File .\scripts\deep2_tps_campaign_evaluator.ps1 `
  -CampaignDir 'F:\wt_ide1\deep2_mutation_campaign_run' `
  -BaselineMedianTps 31.392 `
  -CheckpointTps 40 `
  -EvidenceLedger 'F:\wt_ide1\deep2_mutation_campaign_run\evidence_ledger.jsonl'
```
