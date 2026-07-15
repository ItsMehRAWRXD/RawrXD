@echo off
setlocal enabledelayedexpansion
cd /d d:\rawrxd\compilers

echo ============================================
echo RawrXD 69-Language Compiler Test Suite
echo ============================================
echo.

set /a PASS=0
set /a FAIL=0
set /a TOTAL=0

if not exist "test_results" mkdir test_results

REM Test each compiler
call :test_compiler "universal" "test.c"
call :test_compiler "eon" "test.eon"
call :test_compiler "bash" "test.sh"
call :test_compiler "powershell" "test.ps1"
call :test_compiler "java" "test.java"
call :test_compiler "cs" "test.cs"
call :test_compiler "python" "test.py"
call :test_compiler "js" "test.js"
call :test_compiler "go" "test.go"
call :test_compiler "rust" "test.rs"
call :test_compiler "swift" "test.swift"
call :test_compiler "kotlin" "test.kt"
call :test_compiler "ruby" "test.rb"
call :test_compiler "php" "test.php"
call :test_compiler "typescript" "test.ts"
call :test_compiler "perl" "test.pl"
call :test_compiler "lua" "test.lua"
call :test_compiler "r" "test.r"
call :test_compiler "scala" "test.scala"
call :test_compiler "groovy" "test.groovy"
call :test_compiler "dart" "test.dart"
call :test_compiler "julia" "test.jl"
call :test_compiler "haskell" "test.hs"
call :test_compiler "clojure" "test.clj"
call :test_compiler "erlang" "test.erl"
call :test_compiler "elixir" "test.ex"
call :test_compiler "ocaml" "test.ml"
call :test_compiler "fsharp" "test.fs"
call :test_compiler "objectivec" "test.m"
call :test_compiler "d" "test.d"
call :test_compiler "nim" "test.nim"
call :test_compiler "crystal" "test.cr"
call :test_compiler "zig" "test.zig"
call :test_compiler "v" "test_v.v"
call :test_compiler "odin" "test.odin"
call :test_compiler "fortran" "test.f90"
call :test_compiler "cobol" "test.cob"
call :test_compiler "pascal" "test.pas"
call :test_compiler "ada" "test.ada"
call :test_compiler "lisp" "test.lisp"
call :test_compiler "scheme" "test.scm"
call :test_compiler "prolog" "test.pro"
call :test_compiler "forth" "test.fth"
call :test_compiler "apl" "test.apl"
call :test_compiler "smalltalk" "test.st"
call :test_compiler "coffeescript" "test.coffee"
call :test_compiler "elm" "test.elm"
call :test_compiler "purescript" "test.purs"
call :test_compiler "reason" "test.re"
call :test_compiler "rescript" "test.res"
call :test_compiler "gleam" "test.gleam"
call :test_compiler "wren" "test.wren"
call :test_compiler "gravity" "test.gravity"
call :test_compiler "solidity" "test.sol"
call :test_compiler "vyper" "test.vy"
call :test_compiler "move" "test.move"
call :test_compiler "cairo" "test.cairo"
call :test_compiler "noir" "test.nr"
call :test_compiler "leo" "test.leo"
call :test_compiler "sway" "test.sw"
call :test_compiler "ink" "test.ink"
call :test_compiler "wasm" "test.wat"
call :test_compiler "llvm" "test.ll"
call :test_compiler "mlir" "test.mlir"
call :test_compiler "verilog" "test_verilog.v"
call :test_compiler "vhdl" "test.vhd"
call :test_compiler "systemverilog" "test.sv"
call :test_compiler "chisel" "test.scala"

echo.
echo ============================================
echo Test Results: %PASS%/%TOTAL% passed, %FAIL% failed
echo ============================================

if %FAIL% gtr 0 (
    echo FAILED - Some compilers did not pass tests
    exit /b 1
) else (
    echo SUCCESS - All compilers working!
    exit /b 0
)

:test_compiler
set /a TOTAL+=1
set "COMPILER=%~1"
set "TESTFILE=%~2"

echo [%TOTAL%/69] Testing %COMPILER% compiler...

if exist "built\%COMPILER%_compiler.exe" (
    built\%COMPILER%_compiler.exe test_corpus\%TESTFILE% >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        echo   [PASS] %COMPILER%
        set /a PASS+=1
    ) else (
        echo   [FAIL] %COMPILER% - Exit code: !ERRORLEVEL!
        set /a FAIL+=1
    )
) else (
    echo   [MISSING] %COMPILER%_compiler.exe not found
    set /a FAIL+=1
)

goto :eof
