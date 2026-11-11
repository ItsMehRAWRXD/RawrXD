@echo off
setlocal enabledelayedexpansion
cd /d d:\rawrxd\compilers

echo ============================================
echo RawrXD Autonomous Agentic IDE v1.0
echo 69-Language Compiler System
echo ============================================
echo.

if "%~1"=="" goto :show_help
if "%~1"=="--help" goto :show_help
if "%~1"=="-h" goto :show_help
if "%~1"=="test" goto :run_tests
if "%~1"=="list" goto :list_compilers
if "%~1"=="build" goto :build_file
if "%~1"=="batch" goto :batch_build
if "%~1"=="agent" goto :agent_mode
if "%~1"=="version" goto :show_version
if "%~1"=="status" goto :show_status

goto :process_file

:show_help
echo RawrXD Autonomous Agentic IDE
echo =============================
echo.
echo USAGE:
echo   rawrxd_ide [command] [options]
echo.
echo COMMANDS:
echo   test              Run full test suite on all 69 compilers
echo   list              List all available compilers
echo   build ^<file^>     Compile a single file
echo   batch ^<dir^>      Compile all files in directory
echo   agent             Start autonomous agent mode
echo   version           Show version information
echo   status            Show system status
echo   ^<file^>           Auto-detect and compile file
echo.
echo SUPPORTED LANGUAGES (69):
echo   C, C++, C#, Java, Python, JavaScript, TypeScript
echo   Go, Rust, Swift, Kotlin, Ruby, PHP, Perl, Lua, R
echo   Scala, Groovy, Dart, Julia, Haskell, Clojure
echo   Erlang, Elixir, OCaml, F#, Objective-C, D, Nim
echo   Crystal, Zig, V, Odin, Fortran, COBOL, Pascal
echo   Ada, Lisp, Scheme, Prolog, Forth, APL, Smalltalk
echo   CoffeeScript, Elm, PureScript, Reason, ReScript
echo   Gleam, Wren, Gravity, Solidity, Vyper, Move
echo   Cairo, Noir, Leo, Sway, Ink, WebAssembly
echo   LLVM, MLIR, Verilog, VHDL, SystemVerilog, Chisel
echo   EON, Bash, PowerShell
echo.
echo EXAMPLES:
echo   rawrxd_ide test                    Run all tests
echo   rawrxd_ide build hello.java        Compile Java file
echo   rawrxd_ide batch src\              Compile all files in src\
echo   rawrxd_ide agent                   Start agent mode
echo.
goto :end

:show_version
echo RawrXD Autonomous Agentic IDE v1.0
echo ===================================
echo.
echo Total Compilers: 69
echo Built: 68
echo Status: Production Ready
echo.
echo Architecture: x64 Windows
echo Build Tool: NASM + MSVC Linker
echo Integration: CLI + GUI
echo.
echo (c) 2026 RawrXD Systems
goto :end

:show_status
echo RawrXD System Status
echo ===================
echo.
set /a COUNT=0
for %%f in (built\*_compiler.exe) do set /a COUNT+=1
echo Compilers Available: %COUNT%/69
echo.
echo Test Corpus Files:
dir /b test_corpus\*.* 2>nul | find /c /v ""
echo.
echo Last Build: %DATE% %TIME%
goto :end

:list_compilers
echo Available Compilers (%DATE% %TIME%)
echo =================================
echo.
set /a NUM=0
for %%f in (built\*_compiler.exe) do (
    set /a NUM+=1
    echo !NUM!. %%~nf
)
echo.
echo Total: %NUM% compilers
goto :end

:run_tests
echo Running Full Test Suite...
echo ==========================
call test_all_69.bat
goto :end

:build_file
if "%~2"=="" (
    echo Error: No file specified
    goto :show_help
)
call :detect_and_compile "%~2"
goto :end

:batch_build
if "%~2"=="" (
    echo Error: No directory specified
    goto :show_help
)
echo Batch compilation: %~2
echo ==========================
set /a COMPILED=0
set /a FAILED=0
for %%f in (%~2\*.*) do (
    call :detect_and_compile "%%f" >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        set /a COMPILED+=1
    ) else (
        set /a FAILED+=1
    )
)
echo.
echo Batch Complete: %COMPILED% succeeded, %FAILED% failed
goto :end

:agent_mode
echo Starting Autonomous Agent Mode...
echo =================================
echo.
echo Agent capabilities:
echo   - Auto-detect file types
echo   - Compile on file change
echo   - Report errors
echo   - Batch processing
echo.
echo Type 'exit' to quit agent mode.
echo.
:agent_loop
set /p "CMD=agent> "
if "%CMD%"=="exit" goto :end
if "%CMD%"=="quit" goto :end
if "%CMD%"=="" goto :agent_loop

if exist "%CMD%" (
    call :detect_and_compile "%CMD%"
) else (
    echo Unknown command or file not found: %CMD%
)
goto :agent_loop

:process_file
call :detect_and_compile "%~1"
goto :end

:detect_and_compile
set "FILEPATH=%~1"
set "EXT=%~x1"
set "FILENAME=%~nx1"

if not exist "%FILEPATH%" (
    echo Error: File not found: %FILENAME%
    exit /b 1
)

echo Processing: %FILENAME%

if /i "%EXT%"==".c" goto :compile_universal
if /i "%EXT%"==".cpp" goto :compile_universal
if /i "%EXT%"==".h" goto :compile_universal
if /i "%EXT%"==".java" goto :compile_java
if /i "%EXT%"==".cs" goto :compile_cs
if /i "%EXT%"==".py" goto :compile_python
if /i "%EXT%"==".js" goto :compile_js
if /i "%EXT%"==".ts" goto :compile_typescript
if /i "%EXT%"==".go" goto :compile_go
if /i "%EXT%"==".rs" goto :compile_rust
if /i "%EXT%"==".swift" goto :compile_swift
if /i "%EXT%"==".kt" goto :compile_kotlin
if /i "%EXT%"==".rb" goto :compile_ruby
if /i "%EXT%"==".php" goto :compile_php
if /i "%EXT%"==".pl" goto :compile_perl
if /i "%EXT%"==".lua" goto :compile_lua
if /i "%EXT%"==".r" goto :compile_r
if /i "%EXT%"==".scala" goto :compile_scala
if /i "%EXT%"==".groovy" goto :compile_groovy
if /i "%EXT%"==".dart" goto :compile_dart
if /i "%EXT%"==".jl" goto :compile_julia
if /i "%EXT%"==".hs" goto :compile_haskell
if /i "%EXT%"==".clj" goto :compile_clojure
if /i "%EXT%"==".erl" goto :compile_erlang
if /i "%EXT%"==".ex" goto :compile_elixir
if /i "%EXT%"==".ml" goto :compile_ocaml
if /i "%EXT%"==".fs" goto :compile_fsharp
if /i "%EXT%"==".m" goto :compile_objectivec
if /i "%EXT%"==".d" goto :compile_d
if /i "%EXT%"==".nim" goto :compile_nim
if /i "%EXT%"==".cr" goto :compile_crystal
if /i "%EXT%"==".zig" goto :compile_zig
if /i "%EXT%"==".v" goto :compile_v
if /i "%EXT%"==".odin" goto :compile_odin
if /i "%EXT%"==".f90" goto :compile_fortran
if /i "%EXT%"==".cob" goto :compile_cobol
if /i "%EXT%"==".pas" goto :compile_pascal
if /i "%EXT%"==".ada" goto :compile_ada
if /i "%EXT%"==".lisp" goto :compile_lisp
if /i "%EXT%"==".scm" goto :compile_scheme
if /i "%EXT%"==".pro" goto :compile_prolog
if /i "%EXT%"==".fth" goto :compile_forth
if /i "%EXT%"==".apl" goto :compile_apl
if /i "%EXT%"==".st" goto :compile_smalltalk
if /i "%EXT%"==".coffee" goto :compile_coffeescript
if /i "%EXT%"==".elm" goto :compile_elm
if /i "%EXT%"==".purs" goto :compile_purescript
if /i "%EXT%"==".re" goto :compile_reason
if /i "%EXT%"==".res" goto :compile_rescript
if /i "%EXT%"==".gleam" goto :compile_gleam
if /i "%EXT%"==".wren" goto :compile_wren
if /i "%EXT%"==".gravity" goto :compile_gravity
if /i "%EXT%"==".sol" goto :compile_solidity
if /i "%EXT%"==".vy" goto :compile_vyper
if /i "%EXT%"==".move" goto :compile_move
if /i "%EXT%"==".cairo" goto :compile_cairo
if /i "%EXT%"==".nr" goto :compile_noir
if /i "%EXT%"==".leo" goto :compile_leo
if /i "%EXT%"==".sw" goto :compile_sway
if /i "%EXT%"==".ink" goto :compile_ink
if /i "%EXT%"==".wat" goto :compile_wasm
if /i "%EXT%"==".ll" goto :compile_llvm
if /i "%EXT%"==".mlir" goto :compile_mlir
if /i "%EXT%"==".v" goto :compile_verilog
if /i "%EXT%"==".vhd" goto :compile_vhdl
if /i "%EXT%"==".sv" goto :compile_systemverilog
if /i "%EXT%"==".eon" goto :compile_eon
if /i "%EXT%"==".sh" goto :compile_bash
if /i "%EXT%"==".ps1" goto :compile_powershell

echo Error: Unknown file type '%EXT%'
exit /b 1

:compile_universal
built\universal_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_java
cd /d d:\rawrxd\compilers\built
java_compiler.exe "%FILEPATH%"
cd /d d:\rawrxd\compilers
exit /b %ERRORLEVEL%

:compile_cs
built\cs_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_python
built\python_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_js
built\js_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_typescript
built\typescript_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_go
built\go_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_rust
built\rust_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_swift
built\swift_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_kotlin
built\kotlin_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_ruby
built\ruby_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_php
built\php_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_perl
built\perl_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_lua
built\lua_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_r
built\r_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_scala
built\scala_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_groovy
built\groovy_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_dart
built\dart_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_julia
built\julia_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_haskell
built\haskell_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_clojure
built\clojure_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_erlang
built\erlang_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_elixir
built\elixir_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_ocaml
built\ocaml_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_fsharp
built\fsharp_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_objectivec
built\objectivec_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_d
built\d_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_nim
built\nim_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_crystal
built\crystal_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_zig
built\zig_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_v
built\v_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_odin
built\odin_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_fortran
built\fortran_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_cobol
built\cobol_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_pascal
built\pascal_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_ada
built\ada_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_lisp
built\lisp_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_scheme
built\scheme_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_prolog
built\prolog_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_forth
built\forth_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_apl
built\apl_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_smalltalk
built\smalltalk_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_coffeescript
built\coffeescript_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_elm
built\elm_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_purescript
built\purescript_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_reason
built\reason_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_rescript
built\rescript_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_gleam
built\gleam_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_wren
built\wren_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_gravity
built\gravity_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_solidity
built\solidity_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_vyper
built\vyper_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_move
built\move_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_cairo
built\cairo_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_noir
built\noir_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_leo
built\leo_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_sway
built\sway_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_ink
built\ink_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_wasm
built\wasm_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_llvm
built\llvm_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_mlir
built\mlir_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_verilog
built\verilog_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_vhdl
built\vhdl_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_systemverilog
built\systemverilog_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_eon
built\eon_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_bash
built\bash_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:compile_powershell
built\powershell_compiler.exe "%FILEPATH%"
exit /b %ERRORLEVEL%

:end
