@echo off
REM ==============================================================================
REM Build Phase-29 PQC Engine (Post-Quantum Cryptography Kernels)
REM Target: 70B @ 150TPS via AVX-512 Vectorized NTT
REM ==============================================================================
setlocal EnableDelayedExpansion

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set SRCDIR=c:\RawrXD\src
set OUTDIR=c:\RawrXD\src\pqc_build

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo [Phase-29] Building PQC Engine Kernels...
echo.

REM --- Core PQC Primitives ---
echo [1/9] Montgomery Multiplication (AVX-512)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_Montgomery_Mul_AVX512.obj" "%SRCDIR%\SwarmV29_Montgomery_Mul_AVX512.asm"
if errorlevel 1 goto :error

echo [2/9] NTT Butterfly (Branchless, Constant-Time)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_NTT_Butterfly.obj" "%SRCDIR%\SwarmV29_NTT_Butterfly.asm"
if errorlevel 1 goto :error

echo [3/9] NTT Transform (Iterative Cooley-Tukey)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_NTT_Transform.obj" "%SRCDIR%\SwarmV29_NTT_Transform.asm"
if errorlevel 1 goto :error

echo [4/9] Bit-Reversal Permutation...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_BitReverse.obj" "%SRCDIR%\SwarmV29_BitReverse.asm"
if errorlevel 1 goto :error

REM --- High-Level PQC Operations ---
echo [5/9] Kyber-1024 KEM Encapsulation...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_Kyber_1024_PQC_Encapsulate.obj" "%SRCDIR%\SwarmV29_Kyber_1024_PQC_Encapsulate.asm"
if errorlevel 1 goto :error

echo [6/9] Dilithium5 Signature Generation...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_Dilithium5_PQC_Sign.obj" "%SRCDIR%\SwarmV29_Dilithium5_PQC_Sign.asm"
if errorlevel 1 goto :error

REM --- Security Primitives ---
echo [7/9] Quantum Residue Purge (Non-temporal)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_Quantum_Residue_Purge.obj" "%SRCDIR%\SwarmV29_Quantum_Residue_Purge.asm"
if errorlevel 1 goto :error

echo [8/9] AVX-512 Feature Detection...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_AVX512_Feature_Detect.obj" "%SRCDIR%\SwarmV29_AVX512_Feature_Detect.asm"
if errorlevel 1 goto :error

REM --- Quantum Sovereignty Master ---
echo [9/9] Quantum Sovereignty Master (Enhancements 130-137)...
%ML64% /c /Fo"%OUTDIR%\RawrXD_Quantum_Sovereignty_136.obj" "%SRCDIR%\RawrXD_Quantum_Sovereignty_136.asm"
if errorlevel 1 goto :error

REM --- Phase-29b: 0G Atomic Hijack System ---
echo [10/10] 0G Atomic Hijack System (Phase-29b)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_0G_Hijack.obj" "%SRCDIR%\SwarmV29_0G_Hijack.asm"
if errorlevel 1 goto :error

REM --- Phase-29c: Inverse NTT (INTT) Pipeline ---
echo [11/13] INTT Butterfly (Inverse Cooley-Tukey)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_INTT_Butterfly.obj" "%SRCDIR%\SwarmV29_INTT_Butterfly.asm"
if errorlevel 1 goto :error

echo [12/13] INTT Transform (with Final Scaling)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_INTT_Transform.obj" "%SRCDIR%\SwarmV29_INTT_Transform.asm"
if errorlevel 1 goto :error

echo [13/13] Twiddle Factor Generator (Forward + Inverse)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_Twiddle_Generator.obj" "%SRCDIR%\SwarmV29_Twiddle_Generator.asm"
if errorlevel 1 goto :error

REM --- Phase-29d: Loop-Unrolled Butterflies (Throughput Optimization) ---
echo [14/15] NTT Butterfly 2x Unrolled (Interleaved)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_NTT_Butterfly_2x.obj" "%SRCDIR%\SwarmV29_NTT_Butterfly_2x.asm"
if errorlevel 1 goto :error

echo [15/15] NTT Butterfly 4x Unrolled (Maximum Throughput)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_NTT_Butterfly_4x.obj" "%SRCDIR%\SwarmV29_NTT_Butterfly_4x.asm"
if errorlevel 1 goto :error

REM --- Phase-29e: Brutal Compression & Memory Management ---
echo [16/19] Brutal Pack (16-bit Compression)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_Brutal_Pack.obj" "%SRCDIR%\SwarmV29_Brutal_Pack.asm"
if errorlevel 1 goto :error

echo [17/19] Brutal Unpack (16-bit Expansion)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_Brutal_Unpack.obj" "%SRCDIR%\SwarmV29_Brutal_Unpack.asm"
if errorlevel 1 goto :error

echo [18/19] Pool Allocator (Slab Memory)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_Pool_Allocator.obj" "%SRCDIR%\SwarmV29_Pool_Allocator.asm"
if errorlevel 1 goto :error

echo [19/19] Verification (Round-Trip Integrity)...
%ML64% /c /Fo"%OUTDIR%\SwarmV29_Verification.obj" "%SRCDIR%\SwarmV29_Verification.asm"
if errorlevel 1 goto :error

echo.
echo [SUCCESS] All Phase-29 PQC kernels assembled successfully.
echo Output directory: %OUTDIR%
echo.
echo Kernel count: 19
echo To link into a DLL or EXE, add these .obj files to your linker input.
goto :done

:error
echo.
echo [ERROR] Assembly failed for one or more kernels.
exit /b 1

:done
endlocal
