# ninja-build.ps1 — sets up MSVC environment, then runs ninja
# Usage: .\ninja-build.ps1 [target]

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$NinjaArgs
)

$vcvars = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"

if (Test-Path $vcvars) {
    # Run vcvarsall.bat and import the environment into this PowerShell session
    cmd /c "`"$vcvars`" x64 >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
    Write-Host "[OK] MSVC environment loaded" -ForegroundColor Green
} else {
    Write-Host "[WARNING] vcvarsall.bat not found at $vcvars" -ForegroundColor Yellow
    Write-Host "         Falling back to manual LIB path..." -ForegroundColor Yellow
    ${env:LIB} = @(
        "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64"
        "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\onecore\x64"
        "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
        "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
    ) -join ';'
}

# Run ninja with the provided arguments
ninja -C d:\rawrxd\build @NinjaArgs
$ninjaExit = $LASTEXITCODE

# Catch vs_link_exe silent failures and retry with direct link
$exePath = 'd:\rawrxd\build\bin\rawrxd-cli.exe'
$needsRawrxd = ($NinjaArgs -contains 'rawrxd') -or ($NinjaArgs -contains 'all') -or ($NinjaArgs.Count -eq 0)

if ($ninjaExit -eq 0 -and $needsRawrxd -and -not (Test-Path $exePath)) {
    Write-Host "[WARN] vs_link_exe failed silently, retrying with direct link.exe..." -ForegroundColor Yellow
    
    # Direct link command
    $linkCmd = '"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"'
    $objFiles = @(
        'CMakeFiles\rawrxd.dir\src\cli\cli_main.cpp.obj',
        'CMakeFiles\rawrxd.dir\src\cli\cli_stream.cpp.obj',
        'CMakeFiles\rawrxd.dir\src\cli\pipe_server_callback.cpp.obj',
        'CMakeFiles\rawrxd.dir\src\cli\hotpatch_model_manager.cpp.obj',
        'CMakeFiles\rawrxd.dir\src\cli\hotpatch_inference_integration.cpp.obj',
        'CMakeFiles\rawrxd.dir\src\masm\cli_history.asm.obj',
        'CMakeFiles\rawrxd.dir\src\masm\RawrXD_PipeServer_v2.asm.obj',
        'CMakeFiles\rawrxd.dir\src\masm\rawrxd_hotpatch_router_simple.asm.obj',
        'CMakeFiles\rawrxd.dir\src\res\Resource.rc.res'
    ) -join ' '
    $libs = 'kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib version.lib ws2_32.lib'
    $linkArgs = "/nologo $objFiles /out:bin\rawrxd-cli.exe /implib:rawrxd-cli.lib /pdb:bin\rawrxd-cli.pdb /version:0.0 /machine:x64 /INCREMENTAL:NO /subsystem:console /MANIFEST:NO $libs"
    
    Push-Location d:\rawrxd\build
    $linkOutput = & cmd /c "$linkCmd $linkArgs 2>&1"
    $linkExit = $LASTEXITCODE
    Pop-Location
    
    if ($linkExit -eq 0 -and (Test-Path $exePath)) {
        Write-Host "[OK] Direct link succeeded" -ForegroundColor Green
        $ninjaExit = 0
    } else {
        Write-Host "[FATAL] Direct link also failed:" -ForegroundColor Red
        Write-Host $linkOutput -ForegroundColor Red
        exit 1
    }
}

if ($ninjaExit -eq 0 -and $needsRawrxd -and (Test-Path $exePath)) {
    Write-Host "[OK] EXE verified: $((Get-Item $exePath).LastWriteTime)" -ForegroundColor Green
}

exit $ninjaExit
