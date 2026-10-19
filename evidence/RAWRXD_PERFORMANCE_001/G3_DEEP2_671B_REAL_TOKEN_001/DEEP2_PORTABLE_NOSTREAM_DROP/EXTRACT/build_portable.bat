@echo off
rem MSVC treats trailing .obj on cl compile-line as source; compile then link.
cl /nologo /TC /O2 /W4 /c deep2_nostream.c || exit /b 1
cl /nologo /TC /O2 /W4 /c smoke_nostream.c || exit /b 1
link /nologo smoke_nostream.obj deep2_nostream.obj /OUT:smoke_nostream.exe || exit /b 1
smoke_nostream.exe || exit /b 1
cl /nologo /TC /O2 /W4 /D_CRT_SECURE_NO_WARNINGS gguf_v3_numeric_probe.c /Fe:gguf_v3_numeric_probe.exe || exit /b 1
echo PORTABLE_BUILD_AND_SMOKE=PASS
