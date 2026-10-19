@echo off
setlocal
rem MSVC: /WX + strncpy CRT warnings need _CRT_SECURE_NO_WARNINGS for portable C11.
set CFLAGS=/nologo /std:c11 /O2 /W4 /WX /D_CRT_SECURE_NO_WARNINGS
cl %CFLAGS% /c d2u_authority.c || exit /b 1
cl %CFLAGS% /c d2u_gguf.c || exit /b 1
cl %CFLAGS% /c d2u_quant.c || exit /b 1
cl %CFLAGS% /c d2u_smoke.c || exit /b 1
link /nologo d2u_smoke.obj d2u_authority.obj d2u_gguf.obj d2u_quant.obj /OUT:d2u_smoke.exe || exit /b 1
d2u_smoke.exe || exit /b 1
cl %CFLAGS% /c d2u_inspect.c || exit /b 1
link /nologo d2u_inspect.obj d2u_gguf.obj /OUT:d2u_inspect.exe || exit /b 1
cl %CFLAGS% /c d2u_router.c || exit /b 1
cl %CFLAGS% /c d2u_mla.c || exit /b 1
cl %CFLAGS% /c d2u_expert.c || exit /b 1
cl %CFLAGS% /c d2u_runtime.c || exit /b 1
cl %CFLAGS% /c d2u_run_tokens.c || exit /b 1
link /nologo d2u_run_tokens.obj d2u_authority.obj d2u_gguf.obj d2u_quant.obj d2u_router.obj d2u_mla.obj d2u_expert.obj d2u_runtime.obj /OUT:d2u_run_tokens.exe || exit /b 1
echo PORTABLE_BUILD=PASS
