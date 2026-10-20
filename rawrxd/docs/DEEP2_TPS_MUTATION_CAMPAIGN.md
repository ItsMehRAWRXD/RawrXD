# Deep2 TPS mutation campaign

`deep2_tps_mutation_campaign.ps1` composes the Q6 mutation family with route and tile tweaks. It is fail-closed in two ways:

- without `-ResumeBenchmarks`, it writes only a candidate manifest and launches no model process;
- with `-ResumeBenchmarks`, each candidate goes through the mutation gate in a detached checkout;
  benchmark execution also requires the separate explicit-resume authorization.

The campaign tries algebraic changes and route/tile variations independently before accepting a combination. It never edits model weights. Acceptance still requires a complete recorder pass, zero fallback/nonfinite/fence errors, and a median above the configured baseline margin.

Prepare a manifest without running hardware work:

```powershell
pwsh -NoProfile -File .\rawrxd\scripts\deep2_tps_mutation_campaign.ps1 `
  -BaselineMedianTps 31.392 `
  -OutputDir 'F:\wt_ide1\deep2_mutation_campaign_plan'
```

After the controlled capture is complete and benchmark execution is explicitly resumed, add `-ResumeBenchmarks` to run the campaign.

## Isolated candidate build

The default build command invokes `rawrxd/scripts/build_deep2_candidate.ps1`. It configures
`<candidate>/rawrxd` into `<candidate>/_s12_parity_build` with Ninja and Release settings,
then builds `deep2_end_to_end_bench`. It initializes the MSVC x64 environment when needed.
The existing primary build directory and executable are not copied into the candidate.

The builder rejects a build path outside the candidate, a path inside its source directory,
reparse points in the build path, and caches belonging to another checkout. Before compiling,
it checks the compile commands for the `InferenceEngine` and benchmark sources against the
candidate paths. On success, `candidate_build.json` records the compiler, source paths, and
executable SHA-256. The same JSON is emitted into the gate's retained build log before the
disposable worktree is removed.

Manifest preparation requires the scripts only. The executable is produced during the isolated
build and the model is checked by the recorder when execution is authorized. The gate supplies
the benchmark output directory once and locates the resulting report in its trial directory.

Run the path/cache and manifest regression checks without compiling or launching a model:

```powershell
pwsh -NoProfile -File .\rawrxd\tests\test_deep2_candidate_build_guards.ps1
```

A source-only gate run can use the same default builder without `-ResumeBenchmarks`. A
successful compile and SPIR-V validation yield `DRY_RUN_ONLY`; they do not certify inference
correctness, performance, or promotion.

The fresh isolated build, five guard checks, ledger verification, and unchanged primary build
hashes from base `55fb490c0` are recorded in
`audit/DEEP2_CANDIDATE_BUILD_001/receipt_55fb490c0.json`.
