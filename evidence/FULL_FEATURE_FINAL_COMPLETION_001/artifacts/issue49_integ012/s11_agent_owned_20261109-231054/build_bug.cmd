@echo off
cl /nologo /EHsc bug.cpp /Febug.exe
exit /b %ERRORLEVEL%
