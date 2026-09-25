@echo off
setlocal
where cl >nul 2>nul || (echo MSVC cl.exe not found & exit /b 2)
cl /nologo /std:c++20 /EHsc /O2 /I src tests\test_batch005.cpp src\Deep2StackGuard.cpp src\ExpertScheduler.cpp /Fe:test_batch005.exe || exit /b 1
test_batch005.exe
