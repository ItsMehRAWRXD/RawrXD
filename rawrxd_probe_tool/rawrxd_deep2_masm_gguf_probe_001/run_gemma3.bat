@echo off
setlocal
if not exist deep2_gguf_probe.exe call build.bat || exit /b 1
deep2_gguf_probe.exe "D:\rawrxd\gemma3-1b-Q2_K.gguf"
