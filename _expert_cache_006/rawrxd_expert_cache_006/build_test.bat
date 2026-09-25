@echo off
setlocal
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 || exit /b 1
cmake --build build --config Release || exit /b 1
for %%T in (test_expert_cache_bridge test_expert_cache_packed test_expert_cache_async test_batch005 test_batch006) do (
  build\Release\%%T.exe || exit /b 1
)
endlocal
