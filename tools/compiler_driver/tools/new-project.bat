@echo off
REM RAWRXD New Project Generator
REM Creates a new project with proper structure

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo Usage: new-project.bat <project-name> [language]
    echo.
    echo Languages: c, asm, csharp, multi
    echo.
    echo Example:
    echo   new-project.bat myapp c
    echo   new-project.bat mylib csharp
    exit /b 1
)

set "PROJECT_NAME=%~1"
set "LANGUAGE=%~2"
if "%~2"=="" set "LANGUAGE=c"

set "PROJECT_DIR=%CD%\%PROJECT_NAME%"

if exist "%PROJECT_DIR%" (
    echo ERROR: Directory %PROJECT_NAME% already exists
    exit /b 1
)

echo Creating new RAWRXD project: %PROJECT_NAME%
echo Language: %LANGUAGE%
echo.

mkdir "%PROJECT_DIR%"
mkdir "%PROJECT_DIR%\src"
mkdir "%PROJECT_DIR%\include"
mkdir "%PROJECT_DIR%\build"
mkdir "%PROJECT_DIR%\tests"

REM Create project files based on language
if /i "%LANGUAGE%"=="c" goto :create_c
if /i "%LANGUAGE%"=="asm" goto :create_asm
if /i "%LANGUAGE%"=="csharp" goto :create_csharp
if /i "%LANGUAGE%"=="multi" goto :create_multi
goto :unknown_lang

:create_c
(
echo # %PROJECT_NAME%
echo.
echo A C project built with RAWRXD Compiler Driver.
echo.
echo ## Build
echo.
echo ```batch
echo rawrxd-compiler compile src/main.c -o build/%PROJECT_NAME%.exe
echo ```
) > "%PROJECT_DIR%\README.md"

(
echo #include <stdio.h^>
echo.
echo int main^(void^) {
echo     printf^("Hello from %PROJECT_NAME%!\n"^);
echo     return 0;
echo }
) > "%PROJECT_DIR%\src\main.c"

(
echo #ifndef %PROJECT_NAME%_H
echo #define %PROJECT_NAME%_H
echo.
echo // Project header file
echo.
echo #ifdef __cplusplus
echo extern "C" {
echo #endif
echo.
echo // Add your declarations here
echo.
echo #ifdef __cplusplus
echo }
echo #endif
echo.
echo #endif // %PROJECT_NAME%_H
) > "%PROJECT_DIR%\include\%PROJECT_NAME%.h"

goto :finish

:create_asm
(
echo # %PROJECT_NAME%
echo.
echo An Assembly project built with RAWRXD Compiler Driver.
echo.
echo ## Build
echo.
echo ```batch
echo rawrxd-compiler compile src/main.asm -o build/%PROJECT_NAME%.exe
echo ```
) > "%PROJECT_DIR%\README.md"

(
echo ; %PROJECT_NAME% - Main entry point
echo.
echo extrn ExitProcess: proc
echo.
echo .code
echo main proc
echo     xor ecx, ecx        ; Exit code 0
echo     call ExitProcess
echo main endp
echo end
) > "%PROJECT_DIR%\src\main.asm"

goto :finish

:create_csharp
(
echo # %PROJECT_NAME%
echo.
echo A C# project built with RAWRXD Compiler Driver.
echo.
echo ## Build
echo.
echo ```batch
echo rawrxd-compiler compile src/Program.cs -o build/%PROJECT_NAME%.dll
echo ```
) > "%PROJECT_DIR%\README.md"

(
echo using System;
echo.
echo namespace %PROJECT_NAME%
echo {
echo     class Program
echo     {
echo         static void Main^(string[] args^)
echo         {
echo             Console.WriteLine^("Hello from %PROJECT_NAME%!"^);
echo         }
echo     }
echo }
) > "%PROJECT_DIR%\src\Program.cs"

goto :finish

:create_multi
(
echo # %PROJECT_NAME%
echo.
echo A multi-language project built with RAWRXD Compiler Driver.
echo Contains C, Assembly, and C# components.
echo.
echo ## Build
echo.
echo ```batch
echo rawrxd-compiler build
echo ```
) > "%PROJECT_DIR%\README.md"

(
echo #include <stdio.h^>
echo.
echo // External assembly function
echo extern int asm_compute^(int x, int y^);
echo.
echo int main^(void^) {
echo     int result = asm_compute^(10, 20^);
echo     printf^("Result from assembly: %%d\n", result^);
echo     return 0;
echo }
) > "%PROJECT_DIR%\src\main.c"

(
echo ; Assembly helper functions
echo.
echo .code
echo asm_compute proc
echo     mov rax, rcx
echo     add rax, rdx
echo     ret
aecho asm_compute endp
echo end
) > "%PROJECT_DIR%\src\helper.asm"

(
echo using System;
echo.
echo namespace %PROJECT_NAME%
echo {
echo     class Program
echo     {
echo         static void Main^(^)
echo         {
echo             Console.WriteLine^("C# component of %PROJECT_NAME%"^);
echo         }
echo     }
echo }
) > "%PROJECT_DIR%\src\dotnet\Program.cs"

mkdir "%PROJECT_DIR%\src\dotnet"

goto :finish

:unknown_lang
echo ERROR: Unknown language: %LANGUAGE%
echo Supported: c, asm, csharp, multi
rmdir /S /Q "%PROJECT_DIR%"
exit /b 1

:finish
(
echo # Ignore build artifacts
echo build/
echo *.exe
echo *.obj
echo *.dll
echo *.pdb
echo.
echo # IDE
echo .vscode/
echo .idea/
echo.
echo # Temp
echo *.tmp
echo *~
) > "%PROJECT_DIR%\.gitignore"

(
echo {
echo   "compiler": "rawrxd",
echo   "language": "%LANGUAGE%",
echo   "output": "build/%PROJECT_NAME%.exe",
echo   "sources": ["src"],
echo   "include": ["include"],
echo   "options": {
echo     "optimize": false,
echo     "debug": true
echo   }
echo }
) > "%PROJECT_DIR%\rawrxd.json"

echo.
echo Project created successfully!
echo.
echo Location: %PROJECT_DIR%
echo.
echo Next steps:
echo   cd %PROJECT_NAME%
echo   rawrxd-compiler compile src\main.%LANGUAGE%
