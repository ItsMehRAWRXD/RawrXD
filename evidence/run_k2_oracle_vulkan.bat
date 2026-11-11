@echo off
setlocal EnableExtensions
set "ROOT=F:\rawrxd-native-agent-001"
set "BIN_DIR=F:\llama.cpp-ref\build-vulkan\bin"
set "MODEL=F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf"
set "PROMPT=%ROOT%\evidence\first_corpus_prompt.txt"
set "OUT=%ROOT%\evidence\k2_oracle_single_turn.out"
set "ERR=%ROOT%\evidence\k2_oracle_single_turn.err"
set "META=%ROOT%\evidence\k2_oracle_meta.txt"
set "DEV=%ROOT%\evidence\k2_vulkan_devices.txt"
if exist "%BIN_DIR%\llama.exe" (set "EXE=%BIN_DIR%\llama.exe") else (echo CRITICAL: llama.exe missing & exit /b 2)
echo START=%DATE% %TIME%> "%META%"
echo EXE=%EXE% cli>> "%META%"
"%EXE%" cli --list-devices > "%DEV%" 2>&1
findstr /C:"(none)" "%DEV%" >nul
if not errorlevel 1 (echo CRITICAL: no Vulkan devices & type "%DEV%" & exit /b 3)
findstr /C:"Vulkan0" "%DEV%" >nul
if errorlevel 1 (echo CRITICAL: Vulkan0 missing & type "%DEV%" & exit /b 3)
cd /d "%ROOT%"
rem Vulkan auto load-mode disables mmap; force -lm mmap so MoE experts are not resident-copied.
rem --cpu-moe --no-repack -ngl 99 --fit on --device Vulkan0,Vulkan1
"%EXE%" cli -m "%MODEL%" -f "%PROMPT%" -c 2048 -n 256 --temp 0 --top-k 1 --top-p 1.0 --min-p 0.0 --repeat-penalty 1.0 --seed 0 --single-turn --no-jinja --ignore-eos --verbose --load-mode mmap --no-repack --cpu-moe --fit on -ngl 99 --device Vulkan0,Vulkan1 1> "%OUT%" 2> "%ERR%"
set "RC=%ERRORLEVEL%"
echo EXIT=%RC% END=%DATE% %TIME%>> "%META%"
exit /b %RC%
