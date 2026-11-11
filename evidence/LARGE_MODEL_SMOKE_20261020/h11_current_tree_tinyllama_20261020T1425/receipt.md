# H11 current-tree prefill parity receipt

- Command: `build/Release/deep2_h11_prefill_parity.exe models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf Hello`
- Exit code: 1
- Model: `models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
- H11-P1 chunk 1: FAIL; `LinearW: nonfinite output`, `blk.0.attn_output.weight`, 48/2048 bad, first bad index 3
- H11-P2 chunk 2: FAIL; same first non-finite output
- H11-P3 chunk 16: FAIL; same first non-finite output
- H11-P4 chunk 128: FAIL; same first non-finite output
- Dispatch accounting: vkCmdDispatch 0, queue submits 0, fence waits 0

This is a current-working-tree regression/blocker. It does not overwrite the
sealed D1 PASS receipt from the isolated worktree. The executable reached model
load and layer execution, then failed closed on non-finite attention output.
