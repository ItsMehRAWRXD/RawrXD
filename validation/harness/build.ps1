# RawrXD Validation Framework Build Script (PowerShell)
# Builds all 4 validation executables using MinGW g++

$ErrorActionPreference = "Stop"
$env:Path = "C:\ProgramData\mingw64\mingw64\bin;C:\mingw64\bin;$env:Path"

$HarnessDir = "d:\RawrXD\validation\harness"
$IncludePath = "d:\RawrXD\3rdparty"
$CXXFLAGS = "-std=c++17 -O2 -I`"$IncludePath`""
$COMMON_LIBS = "-lws2_32"

$Components = @(
    @{ Name = "ValidationHarness"; Source = "ValidationHarness.cpp"; Libs = $COMMON_LIBS },
    @{ Name = "HardwareValidator"; Source = "HardwareValidator.cpp"; Libs = $COMMON_LIBS },
    @{ Name = "RealInferenceBenchmark"; Source = "RealInferenceBenchmark.cpp"; Libs = $COMMON_LIBS },
    @{ Name = "TelemetryCollector"; Source = "TelemetryCollector.cpp"; Libs = "$COMMON_LIBS -lpdh" }
)

function Invoke-GCC {
    param($WorkingDir, $Arguments)
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "g++.exe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.WorkingDirectory = $WorkingDir
    $pinfo.Arguments = $Arguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit(120000)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    return @{ ExitCode = $p.ExitCode; Stdout = $stdout; Stderr = $stderr }
}

Write-Host "Building RawrXD Validation Harness Suite..." -ForegroundColor Cyan
Write-Host ""

$success = $true
$count = 0

foreach ($comp in $Components) {
    $count++
    $outExe = "$($comp.Name).exe"
    $args = "$CXXFLAGS $($comp.Source) -o $outExe $($comp.Libs)"
    
    Write-Host "[$count/$($Components.Count)] Building $outExe..." -ForegroundColor Yellow
    
    $result = Invoke-GCC -WorkingDir $HarnessDir -Arguments $args
    
    if ($result.ExitCode -eq 0) {
        Write-Host "  SUCCESS" -ForegroundColor Green
    } else {
        Write-Host "  FAILED (exit: $($result.ExitCode))" -ForegroundColor Red
        if ($result.Stderr) {
            Write-Host "  Errors:" -ForegroundColor Red
            $result.Stderr -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        }
        $success = $false
    }
}

Write-Host ""
if ($success) {
    Write-Host "All builds completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Executables created:" -ForegroundColor Cyan
    Get-ChildItem "$HarnessDir\*.exe" | ForEach-Object { Write-Host "  - $($_.Name) ($($_.Length) bytes)" }
} else {
    Write-Host "Some builds failed. Check errors above." -ForegroundColor Red
}
