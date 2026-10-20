# Q6 algebra mutation family

`tools/mutate_qgemv_q6_algebra.ps1` prepares reversible shader candidates for the existing TPS mutation gate. It does not run the model or change weights.

Variants:

- `hoist_scale`: computes `d * scale` once per four-value decode group;
- `half_load`: reads the aligned word containing the Q6 scale and selects its lower or upper half;
- `hoist_scale_half_load`: combines both changes.
- `skip_unused_batch_rows`: avoids writing inactive shared activation planes when the push-constant batch is one.

Each variant requires the shader and generated SPIR-V to be declared in the gate's file list.
The generator assembles the final shader after applying the function-body changes and rejects
unchanged output. Reapplying an existing variant is rejected before either file is written.

Q6 blocks occupy 210 bytes, so the scale alternates between the lower and upper half of an
aligned 32-bit word. Loading four bytes starting at the scale can cross the final buffer
boundary. The `half_load` variant reads only the containing word instead.

Run the source-only regression from the worktree root:

```powershell
pwsh -NoProfile -File .\rawrxd\tests\test_deep2_q6_mutations.ps1 `
  -ReportPath "$env:TEMP\rawrxd_q6_mutations.json"
```

The regression runs all four variants in disposable fixtures, checks the requested source
changes, compiles the emitted sources independently, and validates the generated SPIR-V.
It also checks replay rejection, unsupported variants, missing function anchors, compiler
failure, undeclared output, both half-word offsets over all 65,536 bit patterns, and final
buffer bounds for 128 block counts. The accepted shader source and SPIR-V are hashed before
and after the run.

The receipt records source and binary hashes separately: a compiler may optimize two source
variants to the same binary. These checks establish mutation generation and compilation only.
Independent inference parity and paired TPS measurements are still required before promotion;
the R9700/Vulkan benchmark pause remains active.

The before/after run and outer isolation check from base `a209f5222` are recorded in
`audit/DEEP2_Q6_MUTATION_SOURCE_001/receipt_a209f5222.json`.
