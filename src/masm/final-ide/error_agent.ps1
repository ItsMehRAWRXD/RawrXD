param(
    [string]$Root = (Resolve-Path ".").Path,
    [string]$Config = "Release"
)

$ErrorActionPreference = 'Stop'

function Write-Section($title) {
    "`n## $title`n" | Out-File -FilePath $ReportPath -Append -Encoding UTF8
}

function Append-Line($line) {
    $line | Out-File -FilePath $ReportPath -Append -Encoding UTF8
}

$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ReportPath = Join-Path $Root "ERROR_AGENT_REPORT.md"
$BuildLog = Join-Path $Root "error_agent_build.log"
$ScanLog  = Join-Path $Root "error_agent_scan.log"
$RunLog   = Join-Path $Root "error_agent_run.log"

# Initialize report
@(
    "# RawrXD Error Agent Report",
    "Generated: $Timestamp",
    "Root: $Root",
    "Config: $Config"
) | Out-File -FilePath $ReportPath -Encoding UTF8

# Paths
$BuildScript = Join-Path $Root "BUILD.bat"
$BinDir = Join-Path $Root (Join-Path "build\bin" $Config)
$ExePath = Join-Path $BinDir "RawrXD.exe"
$PluginsDir = Join-Path $BinDir "Plugins"

# 1) Build
Write-Host "[ErrorAgent] Building project..."
Write-Section "Build"
if (Test-Path $BuildScript) {
    try {
        Push-Location $Root
        $buildOutput = cmd /c "`"$BuildScript`" & exit /b %ERRORLEVEL%" 2>&1
        Pop-Location
        $buildOutput | Out-File -FilePath $BuildLog -Encoding UTF8
        Append-Line "- Status: Completed"
        $errors = $buildOutput | Where-Object { $_ -match "error A|BUILD FAILED|unresolved" }
        $warnings = $buildOutput | Where-Object { $_ -match "warning A|warning" }
        if ($errors) { Append-Line "- Errors: present" } else { Append-Line "- Errors: none" }
        if ($warnings) { Append-Line "- Warnings: $($warnings.Count)" } else { Append-Line "- Warnings: none" }
        Append-Line "- Log: $BuildLog"
        if ($warnings) {
            Append-Line "- Warning samples:"
            $warnings | Select-Object -First 5 | ForEach-Object { Append-Line "  - $_" }
        }
    } catch {
        Append-Line "- Status: Failed to run BUILD.bat"
        Append-Line "- Error: $($_.Exception.Message)"
    } finally {
        if ($PWD.Path -ne $Root) { Pop-Location } 2>$null
    }
} else {
    Append-Line "- Status: BUILD.bat not found"
}

# 2) Source scan (TODO/FIXME/PLACEHOLDER etc.)
Write-Host "[ErrorAgent] Scanning sources..."
Write-Section "Source Scan"
$patterns = @('TODO','FIXME','PLACEHOLDER','WIP','TBD','UNIMPLEMENTED','ASSERT','abort')
$files = Get-ChildItem -Path $Root -File -Include *.asm,*.inc -ErrorAction SilentlyContinue
$findings = @()
foreach ($f in $files) {
    foreach ($p in $patterns) {
        try {
            $matches = Select-String -Path $f.FullName -Pattern $p -SimpleMatch -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($matches) {
                foreach ($m in $matches) {
                    $findings += [pscustomobject]@{ File=$f.Name; Line=$m.LineNumber; Pattern=$p; Text=$m.Line.Trim() }
                }
            }
        }
        catch {
            # ignore individual scan errors
        }
    }
}
if ($findings.Count -gt 0) {
    Append-Line "- Findings: $($findings.Count) occurrences"
    $findings | Sort-Object File,Line | Format-Table -AutoSize | Out-String | Out-File -FilePath $ScanLog -Encoding UTF8
    Append-Line "- Details: $ScanLog"
    $findings | Select-Object -First 10 | ForEach-Object { Append-Line "  - [$($_.File):$($_.Line)] $($_.Text)" }
} else {
    Append-Line "- Findings: none"
}

# 2b) Connectivity check (agentic stack presence)
Write-Host "[ErrorAgent] Checking agentic connectivity..."
Write-Section "Agentic Connectivity"
$requiredFiles = @(
    "ml_masm.asm",
    "agentic_masm.asm",
    "agentic_failure_detector.asm",
    "agentic_puppeteer.asm",
    "unified_masm_hotpatch.asm",
    "unified_hotpatch_manager.asm",
    "proxy_hotpatcher.asm",
    "gguf_server_hotpatch.asm",
    "byte_level_hotpatcher.asm",
    "model_memory_hotpatch.asm"
)
$missing = @()
foreach ($rf in $requiredFiles) {
    if (-not (Test-Path (Join-Path $Root $rf))) { $missing += $rf }
}
if ($missing.Count -gt 0) {
    Append-Line "- Missing critical sources: $($missing -join ', ')"
} else {
    Append-Line "- Critical sources: present"
}

# Check BUILD.bat for required libs (comdlg32 for file open dialog)
if (Test-Path $BuildScript) {
    $buildText = Get-Content -Path $BuildScript -Raw -ErrorAction SilentlyContinue
    $needs = @('comdlg32.lib','user32.lib','kernel32.lib')
    foreach ($n in $needs) {
        if ($buildText -notmatch [regex]::Escape($n)) {
            Append-Line "- Linker lib missing from BUILD.bat: $n"
        }
    }
}

# Check default model presence
$DefaultModel = Join-Path $Root "model.gguf"
Append-Line "- Default model: $(if (Test-Path $DefaultModel) { 'present' } else { 'missing (use File->Open to load)' })"

# 3) Artifact verification
Write-Host "[ErrorAgent] Verifying artifacts..."
Write-Section "Artifacts"
Append-Line "- Executable: $ExePath -> $(if (Test-Path $ExePath) { 'present' } else { 'missing' })"
Append-Line "- Plugins dir: $PluginsDir -> $(if (Test-Path $PluginsDir) { 'present' } else { 'missing' })"
if (Test-Path $PluginsDir) {
    $plugins = Get-ChildItem -Path $PluginsDir -File -ErrorAction SilentlyContinue
    if ($plugins.Count -eq 0) { Append-Line "- Plugins: none found" } else { Append-Line "- Plugins: $($plugins.Count) found" }
}

# 4) Runtime check + agentic plumbing probes
Write-Host "[ErrorAgent] Running executable..."
Write-Section "Runtime"
if (Test-Path $ExePath) {
    try {
        Push-Location $BinDir
        # Capture console output and exit code
        $runOutput = & cmd /c "RawrXD.exe & exit /b %ERRORLEVEL%" 2>&1
        $runOutput | Out-File -FilePath $RunLog -Encoding UTF8
        Append-Line "- ExitCode: $LASTEXITCODE"
        # Probe window handle
        $p = Start-Process -FilePath "$ExePath" -PassThru
        Start-Sleep -Seconds 2
        $procInfo = Get-Process -Id $p.Id -ErrorAction SilentlyContinue | Select-Object -Property MainWindowHandle, MainWindowTitle
        Stop-Process -Id $p.Id -ErrorAction SilentlyContinue
        if ($procInfo) {
            Append-Line "- MainWindowHandle: $($procInfo.MainWindowHandle)"
            Append-Line "- MainWindowTitle: $($procInfo.MainWindowTitle)"
        } else {
            Append-Line "- UI Probe: process not found or no window"
        }
        Pop-Location
        Append-Line "- Output: $RunLog"
        # Quick heuristics: look for known messages
        $ready = $runOutput | Where-Object { $_ -match 'Main: Initializing app' }
        if ($ready) { Append-Line "- Startup: initialization message detected" } else { Append-Line "- Startup: no known messages detected" }
        # Agentic connectivity heuristics
        $agentMsgs = @('Agent', 'Hotpatch', 'Model loaded', 'UI: Main window')
        $hits = @()
        foreach ($m in $agentMsgs) {
            if ($runOutput | Where-Object { $_ -match $m }) { $hits += $m }
        }
        if ($hits.Count -gt 0) {
            Append-Line "- Agentic signals seen: $($hits -join ', ')"
        } else {
            Append-Line "- Agentic signals: none detected in stdout"
        }
    } catch {
        Append-Line "- Run error: $($_.Exception.Message)"
    } finally {
        if ($PWD.Path -ne $BinDir) { Pop-Location } 2>$null
    }
} else {
    Append-Line "- Skipped: executable missing"
}

# 5) Recommendations
Write-Host "[ErrorAgent] Generating recommendations..."
Write-Section "Recommendations"
Append-Line "- Ensure plugin DLLs are placed under `Plugins/` if required by features."
Append-Line "- Provide a `model.gguf` or use File -> Open to load a model before chat."
Append-Line "- Review warnings in `plugin_loader.asm`; remove or reference unused locals for clarity."
Append-Line "- Consider removing or renaming temp sources (e.g., `asm_sync_temp.asm`) to avoid confusion if not used."
Append-Line "- Keep `BUILD.bat` libs (comdlg32.lib, user32.lib, kernel32.lib) in sync with UI features."
Append-Line "- If agentic signals are missing, run with a model loaded and issue a sample command to confirm agent->hotpatch->UI flow."

Write-Host "[ErrorAgent] Report generated: $ReportPath"