@echo off
REM Separate from deep2_benchmark / build_masm.bat — CERT_BINARY_TOUCHED=0
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
set I=src\endurance;src\vulkan;src\product
cl /nologo /TC /O2 /W3 /MT /I src\endurance /I src\vulkan /I src\product /c ^
  src\endurance\deep2_decode_invariant.c ^
  src\endurance\deep2_kv_guard.c ^
  src\endurance\deep2_arena_guard.c ^
  src\endurance\deep2_tensor_range_guard.c ^
  src\endurance\deep2_residency_backpressure.c ^
  src\endurance\deep2_generation_epoch.c ^
  src\endurance\deep2_progress_watch.c ^
  src\endurance\deep2_state_digest.c ^
  src\endurance\deep2_longrun_stats.c ^
  src\endurance\deep2_receipt_journal.c ^
  src\vulkan\ss_vk_lifetime.c ^
  src\vulkan\ss_vk_fence_ring.c ^
  src\vulkan\ss_vk_descriptor_ring.c ^
  src\vulkan\deep2_device_health.c ^
  src\product\deep2_product_destub.c ^
  smoke_endurance.c || exit /b 1
link /nologo /subsystem:console ^
  deep2_decode_invariant.obj deep2_kv_guard.obj deep2_arena_guard.obj ^
  deep2_tensor_range_guard.obj deep2_residency_backpressure.obj ^
  deep2_generation_epoch.obj deep2_progress_watch.obj deep2_state_digest.obj ^
  deep2_longrun_stats.obj deep2_receipt_journal.obj ^
  ss_vk_lifetime.obj ss_vk_fence_ring.obj ss_vk_descriptor_ring.obj ^
  deep2_device_health.obj deep2_product_destub.obj smoke_endurance.obj ^
  kernel32.lib /out:deep2_endurance_smoke.exe || exit /b 1
deep2_endurance_smoke.exe
echo ENDURANCE_SMOKE_EXIT=%ERRORLEVEL%
echo CERT_BINARY_TOUCHED=0
exit /b %ERRORLEVEL%
