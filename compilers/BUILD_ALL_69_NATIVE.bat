@echo off
setlocal EnableDelayedExpansion

echo ============================================
echo Building All 69 Compilers with Native Toolchain
echo ============================================
echo.

set "NATIVE_ASM=d:\rawrxd\compilers\native_tools\rxd_asm.exe"
set "NATIVE_LINK=d:\rawrxd\compilers\native_tools\rxd_link.exe"
set "OUTPUT_DIR=d:\rawrxd\compilers\all_69_native"
set "SOURCE_DIR=d:\rawrxd\compilers\assembly_source"

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

set /a SUCCESS=0
set /a FAIL=0

REM List of all 69 languages
set LANGUAGES=ada algol apl assembly awk basic bash c cobol cpp csharp dart elixir erlang fortran go groovy haskell java javascript julia kotlin lisp lua matlab nim objc ocaml pascal perl php powershell prolog python r ruby rust scala scheme smalltalk swift tcl typescript vba verilog vhdl vimscript

echo Starting build process...
echo.

for %%L in (%LANGUAGES%) do (
    echo [BUILD] %%L_compiler.exe
    
    set "SRC=%SOURCE_DIR%\%%L_compiler.asm"
    set "OBJ=%OUTPUT_DIR%\%%L_compiler.obj"
    set "EXE=%OUTPUT_DIR%\%%L_compiler.exe"
    
    if exist "!SRC!" (
        "%NATIVE_ASM%" "!SRC!" /Fo:"!OBJ!" 2>nul
        if !ERRORLEVEL! equ 0 (
            "%NATIVE_LINK%" "!OBJ!" /OUT:"!EXE!" 2>nul
            if !ERRORLEVEL! equ 0 (
                echo   [OK] %%L_compiler.exe built
                set /a SUCCESS+=1
            ) else (
                echo   [FAIL] Link failed for %%L
                set /a FAIL+=1
            )
        ) else (
            echo   [FAIL] Assembly failed for %%L
            set /a FAIL+=1
        )
    ) else (
        echo   [SKIP] Source not found: %%L_compiler.asm
        set /a FAIL+=1
    )
)

echo.
echo ============================================
echo Build Complete: %SUCCESS% succeeded, %FAIL% failed
echo Output: %OUTPUT_DIR%
echo ============================================

endlocal
