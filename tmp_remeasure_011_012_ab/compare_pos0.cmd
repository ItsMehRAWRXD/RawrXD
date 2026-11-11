@echo off
setlocal
set P=F:\rawrxd\tmp_remeasure_011_012_ab\plain\digest_extract.txt
set O=F:\rawrxd\tmp_remeasure_011_012_ab\oneplus\digest_extract.txt
set OUT=F:\rawrxd\tmp_remeasure_011_012_ab\compare_pos0.txt
echo COMPARE_POS0> %OUT%
for %%K in (PROMPT_EMBED ATTN_NORM_0 Q_PRE_ROPE_0 K_PRE_ROPE_0 V_0 Q_POST_ROPE_0 K_POST_ROPE_0 ATTN_PRE_O_0 FFN_INP_0 FFN_NORM_0 FFN_GATE_0 FFN_UP_0 FFN_ACT_0 FFN_DOWN_0 POST_FFN_0 LAYER_OUT_0 ATTN_NORM_1 LAYER_OUT_1 FINAL_NORM) do (
  findstr /C:"key=%%K pos=0 " %P% > F:\rawrxd\tmp_remeasure_011_012_ab\_p.txt
  findstr /C:"key=%%K pos=0 " %O% > F:\rawrxd\tmp_remeasure_011_012_ab\_o.txt
  fc /b F:\rawrxd\tmp_remeasure_011_012_ab\_p.txt F:\rawrxd\tmp_remeasure_011_012_ab\_o.txt >nul
  if errorlevel 1 (
    echo DIFF %%K>> %OUT%
    type F:\rawrxd\tmp_remeasure_011_012_ab\_p.txt >> %OUT%
    type F:\rawrxd\tmp_remeasure_011_012_ab\_o.txt >> %OUT%
  ) else (
    echo MATCH %%K>> %OUT%
  )
)
findstr /C:"key=LOGITS pos=69" %P% >> %OUT%
findstr /C:"key=LOGITS pos=69" %O% >> %OUT%
findstr /C:"key=ARGMAX pos=69" %P% >> %OUT%
findstr /C:"key=ARGMAX pos=69" %O% >> %OUT%
findstr GEMMA_RMSNORM_ONEPLUS_FORCE F:\rawrxd\tmp_remeasure_011_012_ab\plain\stdout.txt >> %OUT%
findstr GEMMA_RMSNORM_ONEPLUS_FORCE F:\rawrxd\tmp_remeasure_011_012_ab\oneplus\stdout.txt >> %OUT%
echo COMPARE_DONE>> %OUT%
type %OUT%
endlocal
