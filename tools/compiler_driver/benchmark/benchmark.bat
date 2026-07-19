@echo off
REM RAWRXD Compiler Driver Benchmark Suite
REM Measures compilation performance across languages

setlocal enabledelayedexpansion

set "DRIVER=..\bin\rawrxd-compiler.exe"
set "ITERATIONS=10"
set "TEMP_DIR=%TEMP%\rawrxd_bench_%RANDOM%"

set "C_TOTAL=0"
set "ASM_TOTAL=0"
set "CS_TOTAL=0"

echo ==========================================
echo RAWRXD Compiler Driver Benchmark
echo ==========================================
echo.

if not exist "%DRIVER%" (
    echo ERROR: Compiler driver not found
    echo Please build first: ..\build.bat
    exit /b 1
)

mkdir "%TEMP_DIR%" 2>nul

REM Create test files
echo Creating test files...

(
echo #include ^<stdio.h^>
echo #include ^<string.h^>
echo.
echo int fibonacci^(int n^) {
echo     if ^(n <= 1^) return n;
echo     return fibonacci^(n-1^) + fibonacci^(n-2^);
echo }
echo.
echo int main^(^) {
echo     char buffer^[256^];
echo     for ^(int i = 0; i < 1000; i++^) {
echo         sprintf^(buffer, "Result: %%d", fibonacci^(20^)^);
echo     }
echo     return 0;
echo }
) > "%TEMP_DIR%\bench_c.c"

(
echo .code
echo.
echo fibonacci proc
echo     cmp rcx, 1
echo     jle base_case
echo     push rbx
echo     push rdi
echo     mov rbx, rcx
echo     dec rcx
echo     call fibonacci
echo     mov rdi, rax
echo     mov rcx, rbx
echo     sub rcx, 2
echo     call fibonacci
echo     add rax, rdi
echo     pop rdi
echo     pop rbx
echo     ret
echo base_case:
echo     mov rax, rcx
echo     ret
echo fibonacci endp
echo.
echo main proc
echo     mov rcx, 20
echo     call fibonacci
echo     xor rax, rax
echo     ret
echo main endp
echo.
echo end
) > "%TEMP_DIR%\bench_asm.asm"

(
echo using System;
echo.
echo class Program {
echo     static int Fibonacci^(int n^) {
echo         if ^(n <= 1^) return n;
echo         return Fibonacci^(n-1^) + Fibonacci^(n-2^);
echo     }
echo.
echo     static void Main^(^) {
echo         for ^(int i = 0; i < 1000; i++^) {
echo             var result = Fibonacci^(20^);
echo             Console.WriteLine^($"Result: {result}"^);
echo         }
echo     }
echo }
) > "%TEMP_DIR%\bench_cs.cs"

echo.
echo Running %ITERATIONS% iterations per language...
echo.

REM Benchmark C
echo Benchmarking C compiler...
for /L %%i in (1,1,%ITERATIONS%) do (
    "%DRIVER%" compile "%TEMP_DIR%\bench_c.c" -o "%TEMP_DIR%\bench_c.exe" >nul 2>&1
    for /f "tokens=2 delims==" %%a in ('"%DRIVER%" compile "%TEMP_DIR%\bench_c.c" -v 2>^&1 ^| findstr "compile_time_ms"') do (
        set /a C_TOTAL+=%%a
    )
)
set /a C_AVG=C_TOTAL/ITERATIONS

REM Benchmark Assembly
echo Benchmarking Assembly compiler...
for /L %%i in (1,1,%ITERATIONS%) do (
    "%DRIVER%" compile "%TEMP_DIR%\bench_asm.asm" -o "%TEMP_DIR%\bench_asm.exe" >nul 2>&1
    for /f "tokens=2 delims==" %%a in ('"%DRIVER%" compile "%TEMP_DIR%\bench_asm.asm" -v 2>^&1 ^| findstr "compile_time_ms"') do (
        set /a ASM_TOTAL+=%%a
    )
)
set /a ASM_AVG=ASM_TOTAL/ITERATIONS

REM Benchmark C#
echo Benchmarking C# compiler...
for /L %%i in (1,1,%ITERATIONS%) do (
    "%DRIVER%" compile "%TEMP_DIR%\bench_cs.cs" -o "%TEMP_DIR%\bench_cs.dll" >nul 2>&1
    for /f "tokens=2 delims==" %%a in ('"%DRIVER%" compile "%TEMP_DIR%\bench_cs.cs" -v 2>^&1 ^| findstr "compile_time_ms"') do (
        set /a CS_TOTAL+=%%a
    )
)
set /a CS_AVG=CS_TOTAL/ITERATIONS

echo.
echo ==========================================
echo Benchmark Results
echo ==========================================
echo.
echo Language    Total (ms)   Average (ms)
echo ----------  -----------  ------------
echo C           %C_TOTAL%         %C_AVG%
echo Assembly    %ASM_TOTAL%         %ASM_AVG%
echo C#          %CS_TOTAL%         %CS_AVG%
echo.

REM Cleanup
rmdir /S /Q "%TEMP_DIR%" 2>nul

echo Benchmark complete.
