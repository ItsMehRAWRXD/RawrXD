@echo off
setlocal
if not exist out mkdir out
cl /nologo /std:c++17 /O2 /EHsc /Iinclude src\*.cpp tests\smoke.cpp /Fe:out\d2_audit_smoke.exe
exit /b %errorlevel%
