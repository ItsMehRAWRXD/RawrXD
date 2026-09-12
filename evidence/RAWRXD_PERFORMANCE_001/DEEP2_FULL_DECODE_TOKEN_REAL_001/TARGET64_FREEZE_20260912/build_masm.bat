@echo off
setlocal
where ml64 >nul 2>nul || exit /b 90
where link >nul 2>nul || exit /b 91

for %%F in (
  usr_core
  usr_residency
  usr_alias_budget
  usr_hot
  usr_batch_receipt
  ss_real_provider
  ss_gguf_scan
  ss_anchor_adapter
  ss_product_phase
  smoke_destub
) do (
  ml64 /nologo /c /Fo%%F.obj %%F.asm
  if errorlevel 1 exit /b 1
)

link /nologo /subsystem:console /entry:main ^
  smoke_destub.obj ss_real_provider.obj ss_gguf_scan.obj ss_anchor_adapter.obj ^
  kernel32.lib /out:ss_destub_smoke.exe
if errorlevel 1 exit /b %errorlevel%

ss_destub_smoke.exe
if errorlevel 1 exit /b %errorlevel%

echo DESTUB_FILE_PROVIDER=PASS
echo DESTUB_GGUF_SCAN=PASS
echo GGUF_ANCHOR=token_embd.weight
echo FULL_MODEL_INIT_BYPASSED=1
echo DEEP2_CONSUME_D3D12_HOT=NOT_RUN
echo TOKEN_COMMIT=NOT_RUN
echo PROMOTE=0

where cl >nul 2>nul || (
  echo DESTUB_PRODUCT_PHASE=NOT_RUN
  echo PHASE_REASON=NO_CL
  exit /b 0
)

set UR=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\UNIVERSAL_STREAMER_RESIDENCY_001
set DUO=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DOUBLEUNDEROVER_RESIDENCY_AUTHORITY_001
set ENT=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\ENTERPRISE_POST_PRODUCT_TOP15_001\RAWRXD_ENTERPRISE_POST_PRODUCT_X64_MASM_NODEP_TOP15
set VKI=G:\~dev\rawrxd\third_party\vulkan_headers
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%UR%" /I"%VKI%" /c ss_d3d12_bridge.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%UR%" /c smoke_phase.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_load.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_dev.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_import.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_import2.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_sync.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_vis.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_drop.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_consume.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_pipe.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_pipe3.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_mem.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_embd.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_block.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_block_exec.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_onorm.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_import_lm.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_lmhead.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_token.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_decode.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_gguf_find.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_tensor_roles.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_model_plan_io.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_model_plan_meta.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_model_plan_bind.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_model_plan.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_block_plan.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_plan_load.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_kv_cache.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_block_forward.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_block_fwd_result.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_full_forward.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_ops.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_block_loop.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_block_util.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_block_fwd_q.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_block_fwd_kv.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_block0.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_rope.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_attn_causal.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_rope_kv_attn_print.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_mla_qkv.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_rope_kv_witness.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_silu_host.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_topk.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_plan_load_slice.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_moe_ffn_print.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_dense_ffn.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_moe_expert.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_moe_block.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_moe_ffn_witness.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_act_hash.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_resolved_block.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_full_block_loop.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_full_block_loop_print.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_final_norm_lm.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_final_norm_lm_print.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_survive.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_survive_probe.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_op_gemv_n.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_lm_row_ladder.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_op_gemv_tile.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_vk_lm_tiled.c || exit /b 1
set DEC=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DEEP2_FULL_DECODE_TOKEN_REAL_001\RAWRXD_DEEP2_FULL_DECODE_TOKEN_REAL_X64_MASM_NODEP\DEEP2_FULL_DECODE_TOKEN_REAL_X64_MASM_NODEP
set AUTH=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DEEP2_FULL_DECODE_TOKEN_REAL_001\RAWRXD_DEEP2_AUTH_ATTEMPT_GRANT_X64_MASM_NODEP
ml64 /nologo /c /I"%DEC%" /Fodeep2_full_decode_token_real.obj "%DEC%\deep2_full_decode_token_real.asm" || exit /b 1
ml64 /nologo /c /I"%AUTH%" /Fodeep2_auth_grant.obj "%AUTH%\deep2_auth_grant.asm" || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_ar_decode_fwd.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_ar_decode_wire.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_ar_decode_print.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_tensor_id.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_barrier_seq.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_copy_acct.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_q6k_oracle.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_geo_indep.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_gate_check.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%VKI%" /c ss_rms_oracle.c || exit /b 1
cl /nologo /EHsc /O2 /W3 /MT /I"%UR%" /c "%UR%\ur_gpu_d3d12_init.cpp" || exit /b 1
cl /nologo /EHsc /O2 /W3 /MT /I"%UR%" /c "%UR%\ur_gpu_d3d12_util.cpp" || exit /b 1
cl /nologo /EHsc /O2 /W3 /MT /I"%UR%" /c "%UR%\ur_gpu_d3d12_copy.cpp" || exit /b 1
cl /nologo /EHsc /O2 /W3 /MT /I"%UR%" /c "%UR%\ur_gpu_d3d12_readback.cpp" || exit /b 1
cl /nologo /EHsc /O2 /W3 /MT /I"%UR%" /c "%UR%\ur_gpu_d3d12_shared.cpp" || exit /b 1
cl /nologo /EHsc /O2 /W3 /MT /I"%UR%" /c "%UR%\ur_gpu_d3d12_fence.cpp" || exit /b 1

link /nologo /subsystem:console smoke_phase.obj ss_d3d12_bridge.obj ss_product_phase.obj ^
  usr_core.obj usr_residency.obj usr_alias_budget.obj usr_hot.obj usr_batch_receipt.obj ^
  ss_real_provider.obj ss_gguf_scan.obj ss_anchor_adapter.obj ^
  ur_gpu_d3d12_init.obj ur_gpu_d3d12_util.obj ur_gpu_d3d12_copy.obj ur_gpu_d3d12_readback.obj ^
  ur_gpu_d3d12_shared.obj ur_gpu_d3d12_fence.obj ^
  ss_vk_load.obj ss_vk_dev.obj ss_vk_import.obj ss_vk_import2.obj ss_vk_sync.obj ss_vk_vis.obj ss_vk_drop.obj ss_vk_consume.obj ^
  ss_vk_pipe.obj ss_vk_pipe3.obj ss_vk_mem.obj ss_vk_embd.obj ss_vk_block.obj ss_vk_block_exec.obj ^
  ss_vk_onorm.obj ss_vk_import_lm.obj ss_vk_lmhead.obj ss_vk_token.obj ss_vk_decode.obj ss_gguf_find.obj ^
  ss_tensor_roles.obj ss_model_plan_io.obj ss_model_plan_meta.obj ss_model_plan_bind.obj ss_model_plan.obj ^
  ss_block_plan.obj ss_plan_load.obj ss_kv_cache.obj ss_block_forward.obj ss_block_fwd_result.obj ss_full_forward.obj ^
  ss_vk_ops.obj ss_block_loop.obj ss_vk_block_util.obj ss_vk_block_fwd_q.obj ss_vk_block_fwd_kv.obj ss_vk_block0.obj ^
  ss_rope.obj ss_attn_causal.obj ss_rope_kv_attn_print.obj ss_vk_mla_qkv.obj ss_vk_rope_kv_witness.obj ^
  ss_silu_host.obj ss_topk.obj ss_plan_load_slice.obj ss_moe_ffn_print.obj ^
  ss_vk_dense_ffn.obj ss_vk_moe_expert.obj ss_vk_moe_block.obj ss_vk_moe_ffn_witness.obj ^
  ss_vk_act_hash.obj ss_vk_resolved_block.obj ss_vk_full_block_loop.obj ss_full_block_loop_print.obj ^
  ss_vk_final_norm_lm.obj ss_final_norm_lm_print.obj ss_vk_survive.obj ss_vk_survive_probe.obj ^
  ss_vk_op_gemv_n.obj ss_vk_lm_row_ladder.obj ss_vk_op_gemv_tile.obj ss_vk_lm_tiled.obj ^
  ss_ar_decode_fwd.obj ss_ar_decode_wire.obj ss_ar_decode_print.obj deep2_full_decode_token_real.obj deep2_auth_grant.obj ^
  ss_tensor_id.obj ss_barrier_seq.obj ss_copy_acct.obj ss_q6k_oracle.obj ss_geo_indep.obj ss_gate_check.obj ss_rms_oracle.obj ^
  d3d12.lib dxgi.lib kernel32.lib /out:ss_phase_smoke.exe
if errorlevel 1 exit /b %errorlevel%

ss_phase_smoke.exe
if errorlevel 1 exit /b %errorlevel%

echo DESTUB_PRODUCT_PHASE=REACHED
echo GPU_BACKEND_MAY_MATERIALIZE_HOT=1
echo GPU_BACKEND_MAY_DEFINE_HOT_SEMANTICS=0
echo DEEP2_CONSUME_D3D12_HOT=NOT_RUN
echo TOKEN_COMMIT=NOT_RUN
echo PROMOTE=0

for %%F in (duo_uu duo_under duo_layer duo_over duo_oo duo_revoke duo_emit) do (
  cl /nologo /TC /O2 /W3 /MT /I"%DUO%" /c "%DUO%\%%F.c" || exit /b 1
)
ml64 /nologo /c /I"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\ENTERPRISE_POST_PRODUCT_TOP15_001\RAWRXD_ENTERPRISE_POST_PRODUCT_X64_MASM_NODEP_TOP15" /Foenterprise_gate.obj "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\ENTERPRISE_POST_PRODUCT_TOP15_001\RAWRXD_ENTERPRISE_POST_PRODUCT_X64_MASM_NODEP_TOP15\enterprise_gate.asm"
if errorlevel 1 exit /b 1
cl /nologo /TC /O2 /W3 /MT /I"%ENT%" /c "%ENT%\ent_product_bind.c" || exit /b 1
cl /nologo /TC /O2 /W2 /MT /D_CRT_SECURE_NO_WARNINGS /I. /I"%UR%" /I"%DUO%" /I"%ENT%" /c ss_product_e2e.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_product_main.c || exit /b 1

link /nologo /subsystem:console ss_product_main.obj ss_product_e2e.obj ss_d3d12_bridge.obj ss_product_phase.obj ^
  usr_core.obj usr_residency.obj usr_alias_budget.obj usr_hot.obj usr_batch_receipt.obj ^
  ss_real_provider.obj ss_gguf_scan.obj ss_anchor_adapter.obj ^
  ur_gpu_d3d12_init.obj ur_gpu_d3d12_util.obj ur_gpu_d3d12_copy.obj ur_gpu_d3d12_readback.obj ^
  ur_gpu_d3d12_shared.obj ur_gpu_d3d12_fence.obj ^
  ss_vk_load.obj ss_vk_dev.obj ss_vk_import.obj ss_vk_import2.obj ss_vk_sync.obj ss_vk_vis.obj ss_vk_drop.obj ss_vk_consume.obj ^
  ss_vk_pipe.obj ss_vk_pipe3.obj ss_vk_mem.obj ss_vk_embd.obj ss_vk_block.obj ss_vk_block_exec.obj ^
  ss_vk_onorm.obj ss_vk_import_lm.obj ss_vk_lmhead.obj ss_vk_token.obj ss_vk_decode.obj ss_gguf_find.obj ^
  ss_tensor_roles.obj ss_model_plan_io.obj ss_model_plan_meta.obj ss_model_plan_bind.obj ss_model_plan.obj ^
  ss_block_plan.obj ss_plan_load.obj ss_kv_cache.obj ss_block_forward.obj ss_block_fwd_result.obj ss_full_forward.obj ^
  ss_vk_ops.obj ss_block_loop.obj ss_vk_block_util.obj ss_vk_block_fwd_q.obj ss_vk_block_fwd_kv.obj ss_vk_block0.obj ^
  ss_rope.obj ss_attn_causal.obj ss_rope_kv_attn_print.obj ss_vk_mla_qkv.obj ss_vk_rope_kv_witness.obj ^
  ss_silu_host.obj ss_topk.obj ss_plan_load_slice.obj ss_moe_ffn_print.obj ^
  ss_vk_dense_ffn.obj ss_vk_moe_expert.obj ss_vk_moe_block.obj ss_vk_moe_ffn_witness.obj ^
  ss_vk_act_hash.obj ss_vk_resolved_block.obj ss_vk_full_block_loop.obj ss_full_block_loop_print.obj ^
  ss_vk_final_norm_lm.obj ss_final_norm_lm_print.obj ss_vk_survive.obj ss_vk_survive_probe.obj ^
  ss_vk_op_gemv_n.obj ss_vk_lm_row_ladder.obj ss_vk_op_gemv_tile.obj ss_vk_lm_tiled.obj ^
  ss_ar_decode_fwd.obj ss_ar_decode_wire.obj ss_ar_decode_print.obj deep2_full_decode_token_real.obj deep2_auth_grant.obj ^
  ss_tensor_id.obj ss_barrier_seq.obj ss_copy_acct.obj ss_q6k_oracle.obj ss_geo_indep.obj ss_gate_check.obj ss_rms_oracle.obj ^
  duo_uu.obj duo_under.obj duo_layer.obj duo_over.obj duo_oo.obj duo_revoke.obj duo_emit.obj ^
  enterprise_gate.obj ent_product_bind.obj ^
  d3d12.lib dxgi.lib kernel32.lib /out:deep2_benchmark.exe
if errorlevel 1 exit /b %errorlevel%

if not exist "G:\~dev\rawrxd\build-fd\bin" mkdir "G:\~dev\rawrxd\build-fd\bin"
copy /Y deep2_benchmark.exe "G:\~dev\rawrxd\build-fd\bin\deep2_benchmark.exe" >nul
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_plan_smoke.c || exit /b 1
link /nologo /subsystem:console ss_plan_smoke.obj ss_model_plan_io.obj ss_model_plan_meta.obj ^
  ss_model_plan_bind.obj ss_model_plan.obj ss_tensor_roles.obj ^
  kernel32.lib /out:ss_plan_smoke.exe
if errorlevel 1 exit /b %errorlevel%
echo SSVK_TYPE_IDENTITY=TAGGED_STRUCT_SsVk
echo PRODUCT_STUB_LINKED=OPEN
echo NOTE=residual stubs may remain off AR path; not stub-free cert yet
exit /b 0
