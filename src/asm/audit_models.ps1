param([switch]$Verbose)
$ErrorActionPreference = 'Stop'
$src = 'D:\rawrxd\src\Sovereign_Main.asm'
$orig = Get-Content $src -Raw
$origPath = 'D:\codestral22b.gguf'

$models = @(
    'D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf',
    'D:\tinyllama_fresh.gguf',
    'D:\phi3mini.gguf',
    'D:\ministral3.gguf',
    'D:\codestral22b.gguf',
    'D:\Qwen3.5-40B-Q4_K_M.gguf',
    'D:\gptoss20b.gguf'
)

$results = @()
foreach ($m in $models) {
    if (-not (Test-Path -LiteralPath $m -PathType Leaf)) {
        if (-not (Test-Path -LiteralPath $m)) { Write-Host "[SKIP] $m (missing)" -Fore Yellow; continue }
    }
    # Patch path
    $patched = $orig -replace [regex]::Escape($origPath), $m
    Set-Content -LiteralPath $src -Value $patched -NoNewline

    Push-Location D:\rawrxd\src\asm
    $log = & cmd /c '.\build_sovereign.bat 2>&1' | Out-String
    Pop-Location

    $magic = if ($log -match 'magic=0x([0-9A-Fa-f]+)') { $matches[1] } else { 'N/A' }
    $ver   = if ($log -match 'version=(\d+)') { $matches[1] } else { 'N/A' }
    $tc    = if ($log -match 'tensors=(\d+)') { $matches[1] } else { 'N/A' }
    $kv    = if ($log -match 'kv=(\d+)') { $matches[1] } else { 'N/A' }
    $built = ($log -match 'Tensor Index Built Successfully')
    $err   = if ($log -match '\[ERR\][^\r\n]+') { $matches[0] } else { '' }
    $first = ($log -split "`n" | Where-Object { $_ -match '^\s+\S+\.weight\s+type=' } | Select-Object -First 1).Trim()

    $obj = [PSCustomObject]@{
        Model    = Split-Path $m -Leaf
        Magic    = $magic
        Ver      = $ver
        Tensors  = $tc
        KV       = $kv
        Built    = $built
        FirstTensor = if ($first) { ($first -split ' ')[0] } else { '' }
        Error    = $err
    }
    $results += $obj
    Write-Host ("[{0}] {1} ver={2} tensors={3} kv={4} first={5}" -f `
        $(if ($built) {'OK '} else {'!! '}), $obj.Model, $obj.Ver, $obj.Tensors, $obj.KV, $obj.FirstTensor)
    if ($Verbose -and -not $built) { Write-Host $log }
}

# Restore
Set-Content -LiteralPath $src -Value $orig -NoNewline

Write-Host "`n=== AUDIT SUMMARY ==="
$results | Format-Table -AutoSize
