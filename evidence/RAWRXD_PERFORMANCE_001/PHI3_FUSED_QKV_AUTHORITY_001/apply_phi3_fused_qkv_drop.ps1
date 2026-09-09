param(
    [string]$Root = "G:\~dev\rawrxd"
)

$ErrorActionPreference = "Stop"

$dstDir = Join-Path $Root "src\deep2\lavapath"
$dst = Join-Path $dstDir "Phi3FusedQkvAuthority.hpp"
New-Item -ItemType Directory -Force -Path $dstDir | Out-Null

Copy-Item -Force -LiteralPath (Join-Path $PSScriptRoot "Phi3FusedQkvAuthority.hpp") -Destination $dst

$engine = Join-Path $Root "src\deep2\Deep2Engine.cpp"
$text = Get-Content -LiteralPath $engine -Raw

if ($text -notmatch 'Phi3FusedQkvAuthority\.hpp') {
    $text = $text -replace '#include "lavapath/ProductPathSeal\.hpp"', "#include `"lavapath/ProductPathSeal.hpp`"`r`n#include `"lavapath/Phi3FusedQkvAuthority.hpp`""
    Set-Content -LiteralPath $engine -Value $text -NoNewline
    Write-Host "Inserted include into $engine"
} else {
    Write-Host "Include already present"
}

Write-Host "Header installed:"
Write-Host "  $dst"
Write-Host ""
Write-Host "Manual integration still required:"
Write-Host "  1. Replace authority ladder attn_q/attn_k/attn_v block with LayerAttentionAuthority()."
Write-Host "  2. In computeAttention(), route lw.wqkv through ProjectFusedQKV() before split-Q/K/V LinearW calls."
Write-Host "  See PHI3_FUSED_QKV_AUTHORITY_DROP.patch."
