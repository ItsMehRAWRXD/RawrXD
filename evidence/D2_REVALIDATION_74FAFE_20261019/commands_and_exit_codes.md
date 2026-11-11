# Recorded verification commands

All commands were run in `F:\rawrxd\.worktrees\codex-d2-revalidate-74fafe` unless an absolute build path is shown. Exit codes are preserved in the corresponding `*_exit.txt` files and `build_replay_summary.json`.

- GGML configure: see `configure_replay_command.txt`; exit 0.
- GGML Release build: `cmake --build F:\rawrxd\.build_d2_revalidate_74fafe\ggml --config Release --target ggml`; exit 0.
- Deep2 build/link: `cmd.exe /c "F:\rawrxd\.build_d2_revalidate_74fafe\build_deep2_d2.cmd"`; exact compiler/link script is `deep2_build_command.cmd`; exit 0.
- Serial control: `& .\evidence\D2_REVALIDATION_74FAFE_20261019\capture_d2_control.ps1 -Mode serial`; exit 0. Exact binary arguments are in `serial_pair_final_command.txt`.
- Batched control: `& .\evidence\D2_REVALIDATION_74FAFE_20261019\capture_d2_control.ps1 -Mode batched`; exit 0. Exact binary arguments are in `batched_pair_final_command.txt`.
- Full-logit comparator: exact invocation is in `compare_pair_final_command.txt`; exit 0.
- Per-position SHA-256 manifest: exact invocation is in `hash_pair_final_command.txt`; exit 0.
