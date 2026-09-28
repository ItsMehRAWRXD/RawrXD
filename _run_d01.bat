@echo off
set RAWRXD_GPU_FORWARD=1
set DEEP2_RESIDENT_FIRST=1
set DEEP2_DISABLE_VULKAN=0
set DEEP2_GPU_FINITE_TRACE=1
"F:\~dev\build_streaming\Release\deep2_185in30_gate.exe" "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf"
