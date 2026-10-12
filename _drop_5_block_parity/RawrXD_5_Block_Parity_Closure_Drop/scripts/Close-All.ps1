param(
    [string]$RepoRoot = "F:\~dev\rawrxd",
    [string]$BuildDir = "build-win32ide-p1",
    [string]$Generator = "",

    [Parameter(Mandatory=$true)][string]$RuntimeSmokeScript,
    [string[]]$RuntimeSmokeArgs = @(),

    [Parameter(Mandatory=$true)][string]$Model,
    [Parameter(Mandatory=$true)][string]$PromptFile,
    [Parameter(Mandatory=$true)][string]$TokenizerReferenceIds,

    [Parameter(Mandatory=$true)][string]$Deep2DumpDir,
    [Parameter(Mandatory=$true)][string]$ReferenceDumpDir,
    [double]$AbsEps = 1e-6,

    [Parameter(Mandatory=$true)][string]$Deep2TokenIds,
    [Parameter(Mandatory=$true)][string]$ReferenceTokenIds,

    [Parameter(Mandatory=$true)][string]$AgentSmokeScript,
    [string[]]$AgentSmokeArgs = @(),
    [string]$ExpectedAgentEvidence = ""
)

$ErrorActionPreference = "Stop"

& "$PSScriptRoot\Close-1-Win32IDE.ps1" `
    -RepoRoot $RepoRoot -BuildDir $BuildDir -Generator $Generator
if ($LASTEXITCODE -ne 0) { throw "BLOCK1_FAIL" }

& "$PSScriptRoot\Close-2-P1Product.ps1" `
    -RepoRoot $RepoRoot -BuildDir $BuildDir `
    -RuntimeSmokeScript $RuntimeSmokeScript `
    -RuntimeSmokeArgs $RuntimeSmokeArgs
if ($LASTEXITCODE -ne 0) { throw "BLOCK2_FAIL" }

& "$PSScriptRoot\Close-3-Tokenizer.ps1" `
    -Model $Model -PromptFile $PromptFile `
    -ReferenceIds $TokenizerReferenceIds
if ($LASTEXITCODE -ne 0) { throw "BLOCK3_FAIL" }

& "$PSScriptRoot\Close-4-Deep2.ps1" `
    -Deep2DumpDir $Deep2DumpDir `
    -ReferenceDumpDir $ReferenceDumpDir `
    -AbsEps $AbsEps
if ($LASTEXITCODE -ne 0) { throw "BLOCK4_FAIL" }

& "$PSScriptRoot\Close-5-FinalParity.ps1" `
    -Deep2TokenIds $Deep2TokenIds `
    -ReferenceTokenIds $ReferenceTokenIds `
    -AgentSmokeScript $AgentSmokeScript `
    -AgentSmokeArgs $AgentSmokeArgs `
    -ExpectedAgentEvidence $ExpectedAgentEvidence
if ($LASTEXITCODE -ne 0) { throw "BLOCK5_FAIL" }

"================================================"
"ALL_5_PARITY_CLOSURE_BLOCKS=PASS"
"================================================"
