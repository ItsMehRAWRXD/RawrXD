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
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_model_plan.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_block_plan.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_kv_cache.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_block_forward.c || exit /b 1
cl /nologo /TC /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /I. /c ss_full_forward.c || exit /b 1
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
  ss_tensor_roles.obj ss_model_plan.obj ss_block_plan.obj ss_kv_cache.obj ss_block_forward.obj ss_full_forward.obj ^
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
  ss_tensor_roles.obj ss_model_plan.obj ss_block_plan.obj ss_kv_cache.obj ss_block_forward.obj ss_full_forward.obj ^
  ss_tensor_id.obj ss_barrier_seq.obj ss_copy_acct.obj ss_q6k_oracle.obj ss_geo_indep.obj ss_gate_check.obj ss_rms_oracle.obj ^
  duo_uu.obj duo_under.obj duo_layer.obj duo_over.obj duo_oo.obj duo_revoke.obj duo_emit.obj ^
  enterprise_gate.obj ent_product_bind.obj ^
  d3d12.lib dxgi.lib kernel32.lib /out:deep2_benchmark.exe
if errorlevel 1 exit /b %errorlevel%

if not exist "G:\~dev\rawrxd\build-fd\bin" mkdir "G:\~dev\rawrxd\build-fd\bin"
copy /Y deep2_benchmark.exe "G:\~dev\rawrxd\build-fd\bin\deep2_benchmark.exe" >nul
echo PRODUCT_STUB_LINKED=1
exit /b 0
