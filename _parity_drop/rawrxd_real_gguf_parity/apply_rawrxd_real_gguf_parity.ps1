param(
    [string]$RepoRoot = "F:\~dev\rawrxd",
    [switch]$PatchCMake = $true
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Drop=$PSScriptRoot
$Deep2=Join-Path $RepoRoot "src\deep2"
$Tools=Join-Path $RepoRoot "tools"
$CMake=Join-Path $RepoRoot "CMakeLists.txt"

if(!(Test-Path (Join-Path $Deep2 "Deep2Engine.h"))) { throw "Not a RawrXD source root: $RepoRoot" }
New-Item -ItemType Directory -Force -Path $Deep2,$Tools | Out-Null
Copy-Item (Join-Path $Drop "src\deep2\RealGGUFParity.hpp") $Deep2 -Force
Copy-Item (Join-Path $Drop "src\deep2\RealGGUFParity.cpp") $Deep2 -Force
Copy-Item (Join-Path $Drop "tools\real_gguf_parity_main.cpp") $Tools -Force
Copy-Item (Join-Path $Drop "tools\run_real_gguf_parity_matrix.ps1") $Tools -Force

if($PatchCMake) {
    if(!(Test-Path $CMake)) { throw "CMakeLists.txt missing: $CMake" }
    $text=[IO.File]::ReadAllText($CMake)
    if(!$text.Contains("RAWRXD_REAL_GGUF_PARITY_001")) {
        $stamp=Get-Date -Format "yyyyMMdd_HHmmss"
        Copy-Item $CMake "$CMake.realggufparity_$stamp.bak" -Force
        $snippet=[IO.File]::ReadAllText((Join-Path $Drop "integration\CMakeLists.snippet"))
        [IO.File]::AppendAllText($CMake,"`r`n`r`n"+$snippet+"`r`n",[Text.UTF8Encoding]::new($false))
    }
}
Write-Host "RAWRXD_REAL_GGUF_PARITY_001_INSTALL=PASS"
Write-Host "Build target: rawrxd_real_gguf_parity"
