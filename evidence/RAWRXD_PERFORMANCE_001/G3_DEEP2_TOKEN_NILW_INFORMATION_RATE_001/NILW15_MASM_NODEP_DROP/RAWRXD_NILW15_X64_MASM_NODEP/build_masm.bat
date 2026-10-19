@echo off
setlocal
ml64 /nologo /c /Fo nilw15_arith.obj nilw15_arith.asm
if errorlevel 1 exit /b %errorlevel%
ml64 /nologo /c /Fo nilw15_form.obj nilw15_form.asm
if errorlevel 1 exit /b %errorlevel%
ml64 /nologo /c /Fo nilw15_rates.obj nilw15_rates.asm
if errorlevel 1 exit /b %errorlevel%
ml64 /nologo /c /Fo nilw15_w014.obj nilw15_w014.asm
if errorlevel 1 exit /b %errorlevel%
ml64 /nologo /c /Fo nilw15.obj nilw15.asm
if errorlevel 1 exit /b %errorlevel%
ml64 /nologo /c /Fo harness.obj harness.asm
if errorlevel 1 exit /b %errorlevel%
link /nologo /subsystem:console /entry:main harness.obj nilw15.obj nilw15_w014.obj nilw15_form.obj nilw15_rates.obj nilw15_arith.obj kernel32.lib /out:nilw15_witness.exe
exit /b %errorlevel%
