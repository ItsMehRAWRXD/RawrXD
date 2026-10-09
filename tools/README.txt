Deep2 position-2 differential capture + RoPE sign repair
========================================================
Source baseline: 4fcb181f2979ea905a0dcbd621109d1fadd0d99b
Target: tools/rawrxd_modelgenie_ir_executor.cpp
Python 3 standard library only; no runtime dependency added to Deep2.

Why two stages?
  capture: fix CLI --teacher-forced/--differential crash and collect position-2
           IR activations, Q RoPE, attention scores/weights, all-prefix MLA KV,
           and MoE TopK records. No changes to model arithmetic.
  rope:    flip cached-key RoPE alpha to positive, matching native query RoPE.
           This is a candidate numerical correction, NOT a parity PASS.

From an exact baseline checkout (e.g. F:\rawrxd):

  python apply_deep2_pos2_fix.py --repo F:\rawrxd --stage capture --dry-run
  python apply_deep2_pos2_fix.py --repo F:\rawrxd --stage capture

Rebuild modelgenie_ir_executor.exe with your normal MSVC build command.
Run the repaired capture path (on a system with the model and evidence):

  F:\rawrxd\tmp_build\modelgenie_ir_executor.exe ^
    G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf ^
    F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001 ^
    --teacher-forced 1 185 16 15 ^
    --differential F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\pos2_capture ^
    --diff-position 2

Expected behavior: no exception on --differential; 300/300 per position;
recorded position-2 activations with stable unique filenames and real op IDs;
a manifest.json under pos2_capture. Do not call parity PASS unless compared
against reference activations from the identical GGUF and token positions.

To run the key RoPE sign repair separately after inspecting the capture,
use --no-git-guard ONLY if the only edit is this earlier capture patch:

  python apply_deep2_pos2_fix.py --repo F:\rawrxd --stage rope --no-git-guard --dry-run
  python apply_deep2_pos2_fix.py --repo F:\rawrxd --stage rope --no-git-guard

Rebuild and rerun the SAME teacher-forced sequence (with/without --differential).
Compare pos0-3 argmax and full-logit metrics against the unchanged reference:
  reference outputs = [185,185,13,13]
  original native    = [185,185,1,15]

Keep separately identified evidence for each executable build. 
If parity regresses, revert only the sign change; preserve the capture fix.

IMPORTANT: A full Windows model build and 10+ GB GGUF runtime test were NOT
run in the creator's environment. The patcher is guarded to fail closed on
missing/multiple source anchors, refusing to modify an unknown file layout.
GitHub App write access was denied (HTTP 403); nothing was pushed.
