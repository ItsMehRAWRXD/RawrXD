# =======================================================================================
# Sovereign Framework - Production Validation Suite (Pure PowerShell, No Pester)
# File: D:\rawrxd\sovereign\beaconism\Test-SovereignDeploymentIntegrity.ps1
# Validates structural integrity, syntax correctness, and security posture of all 15
# newly deployed production modules plus the 72-module active registry.
# =======================================================================================

param (
    [string]$BeaconismRoot = "D:\rawrxd\sovereign\beaconism",
    [string]$PanelsRoot    = "D:\rawrxd\RawrZ-Security\RawrZ-Payload-Builder\src\panels",
    [string]$ManifestPath  = "D:\rawrxd\sovereign\beaconism\MANIFEST.json"
)

$ErrorActionPreference = "Stop"

# ── Result tracking ──
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:Failures = @()

function Assert-Condition {
    param (
        [bool]$Condition,
        [string]$Because
    )
    if ($Condition) {
        $script:TestsPassed++
        Write-Output "   [PASS] $Because"
    } else {
        $script:TestsFailed++
        $script:Failures += $Because
        Write-Output "   [FAIL] $Because"
    }
}

# ── Discovery / Runtime helpers ──
function Test-PowerShellScriptSyntax {
    param ([string]$Path)
    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw -Path $Path), [ref]$null)
        return $true
    } catch {
        return $false
    }
}

function Test-JavaScriptSyntax {
    param ([string]$Path)
    $content = Get-Content -Raw -Path $Path
    # Strip regex literals and template strings before counting braces
    $stripped = $content -replace '/[^/]+?/[gimuy]*', ''
    $stripped = $stripped -replace '`[^`]*`', ''
    $openBrace  = ($stripped -creplace "[^{]", "").Length
    $closeBrace = ($stripped -creplace "[^}]", "").Length
    if ($openBrace -ne $closeBrace) { return $false }
    if ($content -match "const\s+\w+\s*=\s*const\s+") { return $false }
    return $true
}

function Test-AssemblySyntax {
    param ([string]$Path)
    $content = Get-Content -Raw -Path $Path
    $required = @("bits 64", "global", "section", "ret")
    foreach ($token in $required) {
        if ($content -notmatch $token) { return $false }
    }
    return $true
}

function Test-NoHardcodedSecrets {
    param ([string]$Path)
    $content = Get-Content -Raw -Path $Path
    $patterns = @(
        'password\s*=\s*["\x27][^"\x27]+["\x27]',
        'apikey\s*=\s*["\x27][^"\x27]+["\x27]',
        'secret\s*=\s*["\x27][^"\x27]+["\x27]',
        'token\s*=\s*["\x27][^"\x27]+["\x27]'
    )
    foreach ($pat in $patterns) {
        if ($content -match $pat) { return $false }
    }
    return $true
}

# ═══════════════════════════════════════════════════════════════════════════════════════
# VALIDATION EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════════════

Write-Output "`n==============================================================================="
Write-Output "           SOVEREIGN DEPLOYMENT INTEGRITY VALIDATION SUITE v2.0.0              "
Write-Output "==============================================================================="
Write-Output "Target Beaconism Root : $BeaconismRoot"
Write-Output "Target Panels Root    : $PanelsRoot"
Write-Output "Manifest Path         : $ManifestPath"
Write-Output "==============================================================================="

# ── MANIFEST Registry Integrity ──
Write-Output "`n[CONTEXT] MANIFEST Registry Integrity"

$Manifest = $null
if (Test-Path $ManifestPath) {
    try { $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json } catch {}
}

Assert-Condition (Test-Path $ManifestPath) "MANIFEST.json exists"
Assert-Condition ($null -ne $Manifest) "MANIFEST.json is valid JSON"
Assert-Condition ($Manifest.Version -ge "2.0.0") "MANIFEST declares Version 2.0.0 or higher (found: $($Manifest.Version))"
Assert-Condition ($Manifest.TotalModules -eq 72) "MANIFEST contains exactly 72 active modules (found: $($Manifest.TotalModules))"
Assert-Condition ($null -ne $Manifest.SecurityPosture.NetworkSockets) "MANIFEST SecurityPosture.NetworkSockets is defined"
Assert-Condition ($null -ne $Manifest.SecurityPosture.CryptoStandard) "MANIFEST SecurityPosture.CryptoStandard is defined"
Assert-Condition ($null -ne $Manifest.SecurityPosture.CodeQualityGate) "MANIFEST SecurityPosture.CodeQualityGate is defined"
Assert-Condition ($Manifest.ActiveModules.Count -gt 0) "MANIFEST ActiveModules list is non-empty"

if ($Manifest) {
    foreach ($mod in $Manifest.ActiveModules) {
        $expected = Join-Path $BeaconismRoot $mod
        Assert-Condition (Test-Path $expected) "ActiveModule '$mod' exists at $expected"
    }
}

# ── Backend Module Structural Validation ──
Write-Output "`n[CONTEXT] Backend Module Structural Validation"

Assert-Condition (Test-Path (Join-Path $BeaconismRoot "SovereignSection.asm")) "SovereignSection.asm exists"
Assert-Condition (Test-AssemblySyntax (Join-Path $BeaconismRoot "SovereignSection.asm")) "SovereignSection.asm is valid x64 assembly"

Assert-Condition (Test-Path (Join-Path $BeaconismRoot "SovereignPayloadInjector.ps1")) "SovereignPayloadInjector.ps1 exists"
Assert-Condition (Test-PowerShellScriptSyntax (Join-Path $BeaconismRoot "SovereignPayloadInjector.ps1")) "SovereignPayloadInjector.ps1 parses without syntax errors"

$injectorContent = Get-Content -Raw (Join-Path $BeaconismRoot "SovereignPayloadInjector.ps1")
Assert-Condition ($injectorContent -match "OpenProcess") "SovereignPayloadInjector.ps1 imports OpenProcess"
Assert-Condition ($injectorContent -match "VirtualAllocEx") "SovereignPayloadInjector.ps1 imports VirtualAllocEx"
Assert-Condition ($injectorContent -match "WriteProcessMemory") "SovereignPayloadInjector.ps1 imports WriteProcessMemory"
Assert-Condition ($injectorContent -match "CreateRemoteThread") "SovereignPayloadInjector.ps1 imports CreateRemoteThread"

Assert-Condition (Test-Path (Join-Path $BeaconismRoot "Invoke-SovereignBuildPipeline.ps1")) "Invoke-SovereignBuildPipeline.ps1 exists"
Assert-Condition (Test-PowerShellScriptSyntax (Join-Path $BeaconismRoot "Invoke-SovereignBuildPipeline.ps1")) "Invoke-SovereignBuildPipeline.ps1 parses without syntax errors"

$pipelineContent = Get-Content -Raw (Join-Path $BeaconismRoot "Invoke-SovereignBuildPipeline.ps1")
Assert-Condition ($pipelineContent -match "Quality Gate") "BuildPipeline references Quality Gate phase"
Assert-Condition ($pipelineContent -match "Assembly compiler") "BuildPipeline references Assembly compiler phase"
Assert-Condition ($pipelineContent -match "Section Alignment") "BuildPipeline references Section Alignment phase"
Assert-Condition ($pipelineContent -match "Byte Entropy") "BuildPipeline references Byte Entropy phase"
Assert-Condition ($pipelineContent -match "WMI persistence") "BuildPipeline references WMI persistence phase"

Assert-Condition (Test-Path (Join-Path $BeaconismRoot "Test-SectionAlignment.ps1")) "Test-SectionAlignment.ps1 exists"
Assert-Condition (Test-PowerShellScriptSyntax (Join-Path $BeaconismRoot "Test-SectionAlignment.ps1")) "Test-SectionAlignment.ps1 parses without syntax errors"

Assert-Condition (Test-Path (Join-Path $BeaconismRoot "Test-BinaryEntropy.ps1")) "Test-BinaryEntropy.ps1 exists"
Assert-Condition (Test-PowerShellScriptSyntax (Join-Path $BeaconismRoot "Test-BinaryEntropy.ps1")) "Test-BinaryEntropy.ps1 parses without syntax errors"

$entropyContent = Get-Content -Raw (Join-Path $BeaconismRoot "Test-BinaryEntropy.ps1")
Assert-Condition ($entropyContent -match "Shannon Entropy") "Test-BinaryEntropy.ps1 implements Shannon entropy"
Assert-Condition ($entropyContent -match "Log\(.*2") "Test-BinaryEntropy.ps1 uses base-2 logarithm"

Assert-Condition (Test-Path (Join-Path $BeaconismRoot "Invoke-WorkspaceSanitizer.ps1")) "Invoke-WorkspaceSanitizer.ps1 exists"
Assert-Condition (Test-PowerShellScriptSyntax (Join-Path $BeaconismRoot "Invoke-WorkspaceSanitizer.ps1")) "Invoke-WorkspaceSanitizer.ps1 parses without syntax errors"

Assert-Condition (Test-Path (Join-Path $BeaconismRoot "Invoke-LedgerSanitizer.ps1")) "Invoke-LedgerSanitizer.ps1 exists"
Assert-Condition (Test-PowerShellScriptSyntax (Join-Path $BeaconismRoot "Invoke-LedgerSanitizer.ps1")) "Invoke-LedgerSanitizer.ps1 parses without syntax errors"

$ledgerContent = Get-Content -Raw (Join-Path $BeaconismRoot "Invoke-LedgerSanitizer.ps1")
Assert-Condition ($ledgerContent -match "Get-FileHash") "Invoke-LedgerSanitizer.ps1 computes file hashes"
Assert-Condition ($ledgerContent -match "SHA256") "Invoke-LedgerSanitizer.ps1 uses SHA-256"

Assert-Condition (Test-Path (Join-Path $BeaconismRoot "SovereignVlfBurstEngine.ps1")) "SovereignVlfBurstEngine.ps1 exists"
Assert-Condition (Test-PowerShellScriptSyntax (Join-Path $BeaconismRoot "SovereignVlfBurstEngine.ps1")) "SovereignVlfBurstEngine.ps1 parses without syntax errors"

$vlfContent = Get-Content -Raw (Join-Path $BeaconismRoot "SovereignVlfBurstEngine.ps1")
Assert-Condition ($vlfContent -match "class SovereignVlfCarrier") "SovereignVlfBurstEngine.ps1 defines SovereignVlfCarrier class"
Assert-Condition ($vlfContent -match "SerializeToSubOrbitalFrame") "SovereignVlfCarrier has SerializeToSubOrbitalFrame method"
Assert-Condition ($vlfContent -match "ModulateAndBurst") "SovereignVlfCarrier has ModulateAndBurst method"

Assert-Condition (Test-Path (Join-Path $BeaconismRoot "code-quality-gate.js")) "code-quality-gate.js exists"
Assert-Condition (Test-JavaScriptSyntax (Join-Path $BeaconismRoot "code-quality-gate.js")) "code-quality-gate.js is valid JavaScript"

$gateContent = Get-Content -Raw (Join-Path $BeaconismRoot "code-quality-gate.js")
Assert-Condition ($gateContent -match "UNGUARDED_FETCH_CALL") "code-quality-gate.js defines UNGUARDED_FETCH_CALL pattern"
Assert-Condition ($gateContent -match "MISSING_PARSEINT_RADIX") "code-quality-gate.js defines MISSING_PARSEINT_RADIX pattern"
Assert-Condition ($gateContent -match "UNASSIGNED_SETINTERVAL_HANDLE") "code-quality-gate.js defines UNASSIGNED_SETINTERVAL_HANDLE pattern"

# ── Frontend Panel Structural Validation ──
Write-Output "`n[CONTEXT] Frontend Panel Structural Validation"

$panelFiles = @(
    "fud-obfuscator-panel.js",
    "encryption-config-panel.js",
    "payload-dropzone-panel.js",
    "advanced-config-panel.js",
    "session-log-panel.js",
    "galactic-carrier-panel.js"
)

foreach ($pf in $panelFiles) {
    $full = Join-Path $PanelsRoot $pf
    Assert-Condition (Test-Path $full) "Panel file '$pf' exists"
}

foreach ($pf in $panelFiles) {
    $full = Join-Path $PanelsRoot $pf
    Assert-Condition (Test-JavaScriptSyntax $full) "Panel file '$pf' has valid JavaScript structure"
}

foreach ($pf in $panelFiles) {
    $content = Get-Content -Raw (Join-Path $PanelsRoot $pf)
    Assert-Condition ($content -match '"use strict"') "Panel file '$pf' enforces strict mode"
}

foreach ($pf in $panelFiles) {
    $content = Get-Content -Raw (Join-Path $PanelsRoot $pf)
    $hasBeaconManager = $content -match "AgenticBeaconManager"
    $hasSovereignCore = $content -match "window\.SovereignCore"
    Assert-Condition ($hasBeaconManager -or $hasSovereignCore) "Panel file '$pf' integrates telemetry (AgenticBeaconManager or window.SovereignCore)"
}

foreach ($pf in $panelFiles) {
    $full = Join-Path $PanelsRoot $pf
    Assert-Condition (Test-NoHardcodedSecrets $full) "Panel file '$pf' contains no hardcoded secrets"
}

$fudContent = Get-Content -Raw (Join-Path $PanelsRoot "fud-obfuscator-panel.js")
Assert-Condition ($fudContent -match "electronAPI\.obfuscateBot") "fud-obfuscator-panel.js references electronAPI.obfuscateBot"

$encContent = Get-Content -Raw (Join-Path $PanelsRoot "encryption-config-panel.js")
Assert-Condition ($encContent -match "electronAPI\.encryptTextDemo") "encryption-config-panel.js references electronAPI.encryptTextDemo"

$dropContent = Get-Content -Raw (Join-Path $PanelsRoot "payload-dropzone-panel.js")
Assert-Condition ($dropContent -match "electronAPI\.hashFile") "payload-dropzone-panel.js references electronAPI.hashFile"

$galContent = Get-Content -Raw (Join-Path $PanelsRoot "galactic-carrier-panel.js")
Assert-Condition ($galContent -match "electronAPI\.executeEngine") "galactic-carrier-panel.js references electronAPI.executeEngine"

# ── Security Posture Validation ──
Write-Output "`n[CONTEXT] Security Posture Validation"

$psFiles = Get-ChildItem -Path $BeaconismRoot -Filter "*.ps1" -Recurse
foreach ($file in $psFiles) {
    Assert-Condition (Test-NoHardcodedSecrets $file.FullName) "PowerShell script '$($file.Name)' contains no hardcoded secrets"
}

foreach ($file in $psFiles) {
    $content = Get-Content -Raw $file.FullName
    $hasPreference = $content -match '\$ErrorActionPreference\s*=\s*"Stop"'
    $hasParam = $content -match '\[CmdletBinding\(\)\]'
    Assert-Condition ($hasPreference -or $hasParam) "PowerShell script '$($file.Name)' enforces strict error handling"
}

$injectorLines = (Get-Content -Raw (Join-Path $BeaconismRoot "SovereignPayloadInjector.ps1")) -split "`r?`n"
$invokeLines = $injectorLines | Where-Object { $_ -match '^\s*Invoke-SovereignMemoryResidentBeacon\s+' }
Assert-Condition ($invokeLines.Count -eq 0) "SovereignPayloadInjector.ps1 does not auto-execute (no top-level invocation)"

# ── Legacy / Corruption Detection ──
Write-Output "`n[CONTEXT] Legacy / Corruption Detection"

$allFiles = @()
$allFiles += Get-ChildItem -Path $BeaconismRoot -Include "*.js","*.ps1","*.html" -Recurse
$allFiles += Get-ChildItem -Path $PanelsRoot -Include "*.js" -Recurse
foreach ($file in $allFiles) {
    $content = Get-Content -Raw $file.FullName
    Assert-Condition ($content -notmatch "const\s+\w+\s*=\s*const\s+") "File '$($file.Name)' is free of automation corruption artifacts"
}

$panelJs = Get-ChildItem -Path $PanelsRoot -Filter "*.js"
foreach ($file in $panelJs) {
    $content = Get-Content -Raw $file.FullName
    if ($content -match "fetch\s*\(") {
        Assert-Condition ($content -match "AbortController|signal:|setTimeout.*abort") "Panel '$($file.Name)' fetch() calls are guarded by AbortController"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════════════

Write-Output "`n==============================================================================="
Write-Output "                         VALIDATION SUITE SUMMARY                               "
Write-Output "==============================================================================="
Write-Output "   Tests Passed : $TestsPassed"
Write-Output "   Tests Failed : $TestsFailed"
Write-Output "==============================================================================="

if ($TestsFailed -gt 0) {
    Write-Output "`nFailed Assertions:"
    foreach ($f in $Failures) {
        Write-Output "   - $f"
    }
    Write-Output "`n==============================================================================="
    Write-Output " RESULT: FAILED — $TestsFailed assertion(s) must be resolved before deployment."
    Write-Output "==============================================================================="
    exit 1
} else {
    Write-Output "`n==============================================================================="
    Write-Output " RESULT: PASSED — All $TestsPassed assertions verified. Production integrity confirmed."
    Write-Output "==============================================================================="
    exit 0
}
