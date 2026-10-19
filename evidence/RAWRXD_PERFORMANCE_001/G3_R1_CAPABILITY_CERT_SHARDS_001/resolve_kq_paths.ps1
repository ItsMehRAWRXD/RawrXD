# Resolve K–Q stretch models for G3_R1_CAPABILITY_CERT_SHARDS_001
$ErrorActionPreference = 'Continue'
$outDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$roots = @('G:\~dev\rawrxd\_r1_iso','G:\~dev\rawrxd\models','G:\~dev\rawrxd','F:\OllamaModels')
function Find-Gguf([string[]]$Patterns) {
  foreach ($r in $roots) {
    if (-not (Test-Path -LiteralPath $r)) { continue }
    foreach ($pat in $Patterns) {
      $hit = Get-ChildItem -LiteralPath $r -Recurse -Filter $pat -File -EA SilentlyContinue |
        Select-Object -First 1
      if ($hit) { return $hit.FullName }
    }
  }
  # dirs for shards
  foreach ($r in $roots) {
    if (-not (Test-Path -LiteralPath $r)) { continue }
    foreach ($pat in $Patterns) {
      $hit = Get-ChildItem -LiteralPath $r -Recurse -Directory -Filter $pat -EA SilentlyContinue |
        Select-Object -First 1
      if ($hit) { return $hit.FullName }
    }
  }
  return $null
}
$ladder = @(
  [pscustomobject]@{ Stage='K'; Id='K_qwen14'; Arch='qwen2'; Family='Qwen2.5-Coder-14B'; Patterns=@('*qwen2.5-coder-14b*.gguf','*Qwen2.5-Coder-14B*.gguf') },
  [pscustomobject]@{ Stage='L'; Id='L_qwen27'; Arch='qwen2'; Family='Qwen2.5-27B'; Patterns=@('*qwen*27b*.gguf','*Qwen2.5-32B*.gguf','*qwen2.5-coder-32b*.gguf') },
  [pscustomobject]@{ Stage='M'; Id='M_glm'; Arch='glm'; Family='GLM-4.7-Flash'; Patterns=@('GLM-4.7-Flash-Q4_K_M.gguf','*GLM-4.7*.gguf') },
  [pscustomobject]@{ Stage='N'; Id='N_gemma31'; Arch='gemma3'; Family='Gemma3-31B'; Patterns=@('*gemma*31b*.gguf','*Gemma3*27B*.gguf','*gemma-3-27b*.gguf') },
  [pscustomobject]@{ Stage='O'; Id='O_qwen_moe'; Arch='moe'; Family='Qwen35B-A3B-MoE'; Patterns=@('*A3B*.gguf','*35B-A3B*.gguf','*Qwen*MoE*.gguf') },
  [pscustomobject]@{ Stage='P'; Id='P_ds_shards'; Arch='deepseek-r1'; Family='DeepSeek-R1-shards'; Patterns=@('*DeepSeek-R1*','*deepseek*r1*') },
  [pscustomobject]@{ Stage='Q'; Id='Q_kimi_k2'; Arch='kimi'; Family='Kimi-K2-shards'; Patterns=@('*Kimi*K2*','*kimi*k2*','*moonshot*') }
)
$rows = @()
foreach ($m in $ladder) {
  $p = Find-Gguf $m.Patterns
  $ok = [bool]$p
  $sz = 0
  if ($ok -and (Test-Path -LiteralPath $p -PathType Leaf)) {
    $sz = [math]::Round((Get-Item -LiteralPath $p).Length/1MB,1)
  }
  $rows += [pscustomobject]@{ Stage=$m.Stage; Id=$m.Id; Arch=$m.Arch; Family=$m.Family; Path=$(if($ok){$p}else{''}); SizeMB=$sz; Found=$ok }
  Write-Host ("{0} Found={1} {2}" -f $m.Stage, $ok, $(if($ok){$p}else{'MISSING'}))
}
$rows | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $outDir 'models_kq.json')
exit 0
