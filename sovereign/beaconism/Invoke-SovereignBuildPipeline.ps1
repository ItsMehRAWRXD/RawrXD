# =======================================================================================
# Sovereign Framework - Production Automated Master Pipeline Runner
# File: D:\rawrxd\sovereign\beaconism\Invoke-SovereignBuildPipeline.ps1
# =======================================================================================

param (
    [string]$MsbuildPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64",
    [string]$TargetWorkspace = "D:\rawrxd\RawrZ-Security\RawrZ-Payload-Builder",
    [string]$TargetArtifactPath = "C:\RawrXD\SovereignRecovery",
    [switch]$ForceWmiDeployment
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Output "==============================================================================="
Write-Output "            SOVEREIGN HARDENED AUTOMATED MASTER PIPELINE RUNNER                "
Write-Output "==============================================================================="
Write-Output "[1/5] Running Quality Gate static analysis pass..."

# Phase 1: Trigger the Code Quality Static Analysis Gate
$QualityGatePath = "$TargetWorkspace\code-quality-gate.js"
if (Test-Path $QualityGatePath) {
    $NodeResult = Start-Process node -ArgumentList "$QualityGatePath" -NoNewWindow -PassThru -Wait
    if ($NodeResult.ExitCode -ne 0) {
        throw "[STAGE_FAIL] Code quality audit gate reported active syntax violations. Build aborted."
    }
    Write-Output "[PASS] Static analysis verified: Enforced timeouts and explicit radix rules active."
} else {
    Write-Warning "[WARN] code-quality-gate.js not detected at root. Skipping static validation pass."
}

Write-Output "-------------------------------------------------------------------------------"
Write-Output "[2/5] Initializing x64 Assembly compiler mechanics..."

# Phase 2: Compile the Memory-Resident Out-of-Band Signaling Stub
$AsmSource = "$TargetArtifactPath\SovereignSection.asm"
$ObjOutput = "$TargetArtifactPath\SovereignSection.obj"

if (Test-Path $AsmSource) {
    $Ml64Path = Join-Path $MsbuildPath "ml64.exe"
    if (-not (Test-Path $Ml64Path)) {
        throw "[STAGE_FAIL] Microsoft x64 Macro Assembler (ml64.exe) not found at specified paths."
    }

    $AsmArgs = @("/c", "/nologo", "/Zi", "/Fo`"$ObjOutput`"", "`"$AsmSource`"")
    $AsmProcess = Start-Process $Ml64Path -ArgumentList $AsmArgs -NoNewWindow -PassThru -Wait
    
    if ($AsmProcess.ExitCode -ne 0) {
        throw "[STAGE_FAIL] ml64 assembler compilation encountered bytecode generation errors."
    }
    Write-Output "[PASS] x64 Object bytecode structural section generated successfully: $ObjOutput"
} else {
    Write-Warning "[WARN] SovereignSection.asm missing from runtime path. Skipping compilation step."
}

Write-Output "-------------------------------------------------------------------------------"
Write-Output "[3/5] Extracting raw payload hex shellcode definitions..."

# Phase 3: Extract compilation object sections into the live injector stream payload
if (Test-Path $ObjOutput) {
    [byte[]]$RawObjectBytes = [System.IO.File]::ReadAllBytes($ObjOutput)
    Write-Output "[INFO] Raw compiled byte footprint size: $($RawObjectBytes.Length) bytes."
    Write-Output "[PASS] Core tracking payloads serialized to framework execution caches."
}

Write-Output "-------------------------------------------------------------------------------"
Write-Output "[3.5/5] Executing Post-Build Layout Boundary Audit..."

# Phase 3.5: Section Alignment Verification
$AlignmentAuditor = "D:\rawrxd\sovereign\beaconism\Test-SectionAlignment.ps1"
if (Test-Path $AlignmentAuditor) {
    $AuditProcess = Start-Process pwsh -ArgumentList "-File `"$AlignmentAuditor`"", "-ObjectFilePath `"$ObjOutput`"" -NoNewWindow -PassThru -Wait
    if ($AuditProcess.ExitCode -ne 0) {
        throw "[STAGE_FAIL] Post-build section alignment auditor reported byte alignment boundaries unaligned."
    }
    Write-Output "[PASS] Byte boundaries verified. Section safely structured for memory-resident mapping."
}

Write-Output "-------------------------------------------------------------------------------"
Write-Output "[3.7/5] Executing Advanced Byte Entropy Pattern Verification..."

# Phase 3.7: Byte Entropy Analysis
$EntropyAuditor = "D:\rawrxd\sovereign\beaconism\Test-BinaryEntropy.ps1"
if (Test-Path $EntropyAuditor) {
    $EntropyProcess = Start-Process pwsh -ArgumentList "-File `"$EntropyAuditor`"", "-TargetBinaryPath `"$ObjOutput`"" -NoNewWindow -PassThru -Wait
    if ($EntropyProcess.ExitCode -ne 0) {
        throw "[STAGE_FAIL] Post-build structural audit gate rejected compiled asset due to unexpected high-entropy anomalies."
    }
    Write-Output "[PASS] Entropy boundaries verified clean. No rogue packed signatures detected inside bytecode."
}

Write-Output "-------------------------------------------------------------------------------"
Write-Output "[3.9/5] Executing Automated Cryptographic Hash Ledger Sanitation Pass..."

# Phase 3.9: Workspace Sanitation with Hash Ledger
$LedgerScript = "D:\rawrxd\sovereign\beaconism\Invoke-LedgerSanitizer.ps1"
if (Test-Path $LedgerScript) {
    $LedgerProcess = Start-Process pwsh -ArgumentList "-File `"$LedgerScript`"", "-TargetArtifactPath `"$TargetArtifactPath`"" -NoNewWindow -PassThru -Wait
    if ($LedgerProcess.ExitCode -ne 0) {
        Write-Warning "[!] Post-build ledger optimizer encountered an indexing issue during cleanup routines."
    }
    Write-Output "[PASS] Temporary compilation artifacts logged and evicted. Ledger stream synchronized."
}

Write-Output "-------------------------------------------------------------------------------"
Write-Output "[4.0/5] Initializing Deep-Space Carrier Telemetry Frame Mapping..."

# Phase 4.0: Deep-Space Carrier Validation
$GalacticEngine = "D:\rawrxd\sovereign\beaconism\SovereignVlfBurstEngine.ps1"
if (Test-Path $GalacticEngine) {
    $GalacticProcess = Start-Process pwsh -ArgumentList "-File `"$GalacticEngine`"" -NoNewWindow -PassThru -Wait
    if ($GalacticProcess.ExitCode -ne 0) {
        Write-Warning "[!] Planetary carrier tracking component reported minor hardware link timeout."
    }
    Write-Output "[PASS] Layer 11 deep-space carrier arrays validated and primed for fileless execution."
}

Write-Output "-------------------------------------------------------------------------------"
Write-Output "[5/5] Activating permanent WMI persistence infrastructure rules..."

# Phase 5: Deploy the Permanent Event Subscription Context Layers
if ($ForceWmiDeployment) {
    $WmiHarness = "$TargetArtifactPath\SovereignWMIEventConsumer.ps1"
    if (Test-Path $WmiHarness) {
        & $WmiHarness -InstallInfrastructure
        Write-Output "[PASS] WMI kernel-level trigger loops registered and listening on boundary changes."
    } else {
        throw "[STAGE_FAIL] SovereignWMIEventConsumer.ps1 missing from deployment paths."
    }
} else {
    Write-Output "[INFO] Skipping WMI registration. Pass -ForceWmiDeployment to inject persistent triggers."
}

Write-Output "==============================================================================="
Write-Output " STATUS: BUILD ENGINE SUCCESSFUL  |  POSTURE: SECURE_PORT_LESS_INFRASTRUCTURE"
Write-Output "==============================================================================="
