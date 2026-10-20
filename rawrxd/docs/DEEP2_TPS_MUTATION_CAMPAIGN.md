# Deep2 TPS mutation campaign

`deep2_tps_mutation_campaign.ps1` composes the Q6 mutation family with route and tile tweaks. It is fail-closed in two ways:

- without `-ResumeBenchmarks`, it writes only a candidate manifest and launches no model process;
- with `-ResumeBenchmarks`, each candidate goes through the existing mutation gate, which restores the declared shader files and rebuilds the baseline after rejection before the next candidate.

The campaign tries algebraic changes and route/tile variations independently before accepting a combination. It never edits model weights. Acceptance still requires a complete recorder pass, zero fallback/nonfinite/fence errors, and a median above the configured baseline margin.

Prepare a manifest without running hardware work:

```powershell
pwsh -NoProfile -File .\scripts\deep2_tps_mutation_campaign.ps1 `
  -BaselineMedianTps 31.392 `
  -OutputDir 'F:\wt_ide1\deep2_mutation_campaign_plan'
```

After the controlled capture is complete and benchmark execution is explicitly resumed, add `-ResumeBenchmarks` to run the campaign.
