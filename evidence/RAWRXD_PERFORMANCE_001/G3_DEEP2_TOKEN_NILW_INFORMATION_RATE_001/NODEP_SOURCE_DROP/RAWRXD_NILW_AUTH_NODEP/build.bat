@echo off
setlocal
cl /nologo /std:c++17 /O2 /EHsc- /GR- /W4 main.cpp nilw_auth.cpp /Fe:nilw_auth.exe
exit /b %errorlevel%
