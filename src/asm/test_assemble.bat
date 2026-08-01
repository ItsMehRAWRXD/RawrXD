@echo off
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe

echo Testing byte_search.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo byte_search.obj byte_search.asm
if %ERRORLEVEL% neq 0 (
    echo byte_search.asm FAILED
) else (
    echo byte_search.asm SUCCESS
)

echo.
echo Testing memory_patch.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo memory_patch.obj memory_patch.asm
if %ERRORLEVEL% neq 0 (
    echo memory_patch.asm FAILED
) else (
    echo memory_patch.asm SUCCESS
)

echo.
echo Testing RawrXD-AnalyzerDistiller.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo RawrXD-AnalyzerDistiller.obj RawrXD-AnalyzerDistiller.asm
if %ERRORLEVEL% neq 0 (
    echo RawrXD-AnalyzerDistiller.asm FAILED
) else (
    echo RawrXD-AnalyzerDistiller.asm SUCCESS
)

echo.
echo Testing RawrXD-StreamingOrchestrator.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo RawrXD-StreamingOrchestrator.obj RawrXD-StreamingOrchestrator.asm
if %ERRORLEVEL% neq 0 (
    echo RawrXD-StreamingOrchestrator.asm FAILED
) else (
    echo RawrXD-StreamingOrchestrator.asm SUCCESS
)

echo.
echo Testing DirectML_Bridge.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo DirectML_Bridge.obj DirectML_Bridge.asm
if %ERRORLEVEL% neq 0 (
    echo DirectML_Bridge.asm FAILED
) else (
    echo DirectML_Bridge.asm SUCCESS
)

echo.
echo Testing RawrXD_Hotpatch_Kernel.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo RawrXD_Hotpatch_Kernel.obj RawrXD_Hotpatch_Kernel.asm
if %ERRORLEVEL% neq 0 (
    echo RawrXD_Hotpatch_Kernel.asm FAILED
) else (
    echo RawrXD_Hotpatch_Kernel.asm SUCCESS
)

echo.
echo Testing RawrXD_Snapshot.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo RawrXD_Snapshot.obj RawrXD_Snapshot.asm
if %ERRORLEVEL% neq 0 (
    echo RawrXD_Snapshot.asm FAILED
) else (
    echo RawrXD_Snapshot.asm SUCCESS
)

echo.
echo Testing RawrXD_Pyre_Compute.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo RawrXD_Pyre_Compute.obj RawrXD_Pyre_Compute.asm
if %ERRORLEVEL% neq 0 (
    echo RawrXD_Pyre_Compute.asm FAILED
) else (
    echo RawrXD_Pyre_Compute.asm SUCCESS
)

echo.
echo Testing RawrXD_DualEngine_QuantumBeacon.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo RawrXD_DualEngine_QuantumBeacon.obj RawrXD_DualEngine_QuantumBeacon.asm
if %ERRORLEVEL% neq 0 (
    echo RawrXD_DualEngine_QuantumBeacon.asm FAILED
) else (
    echo RawrXD_DualEngine_QuantumBeacon.asm SUCCESS
)

echo.
echo All tests complete!
pause
