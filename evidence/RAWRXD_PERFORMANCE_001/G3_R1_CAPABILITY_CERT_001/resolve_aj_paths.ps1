# Resolve A-J ladder GGUF paths for G3_R1_CAPABILITY_CERT_001
$ErrorActionPreference = 'Continue'
$outDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$roots = @(
  'G:\~dev\rawrxd\_r1_iso',
  'G:\~dev\rawrxd\models',
  'G:\~dev\rawrxd',
  'F:\OllamaModels'
)

function Find-Gguf([string[]]$Patterns) {
  foreach ($r in $roots) {
    if (-not (Test-Path -LiteralPath $r)) { continue }
    foreach ($pat in $Patterns) {
      $hit = Get-ChildItem -LiteralPath $r -Recurse -Filter $pat -File -EA SilentlyContinue |
        Where-Object { $_.Extension -eq '.gguf' -or $_.Name -match 'sha256-' } |
        Select-Object -First 1
      if ($hit) { return $hit.FullName }
    }
  }
  return $null
}

$ladder = @(
  [pscustomobject]@{ Stage='A'; Id='A_tinyllama'; Arch='llama'; Family='TinyLlama-1.1B'; Patterns=@('tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf','*tinyllama*Q4_K_M*.gguf') },
  [pscustomobject]@{ Stage='B'; Id='B_gemma3_1b'; Arch='gemma3'; Family='Gemma3-1B'; Patterns=@('gemma3-1b-Q2_K.gguf','*gemma3*1b*.gguf','*gemma-3-1b*.gguf') },
  [pscustomobject]@{ Stage='C'; Id='C_llama32_3b'; Arch='llama'; Family='Llama-3.2-3B'; Patterns=@('llama3.2-3b-Q3_K_S.gguf','*llama3.2*3b*.gguf','*Llama-3.2-3B*.gguf') },
  [pscustomobject]@{ Stage='D'; Id='D_phi3_mini'; Arch='phi3'; Family='Phi-3-mini'; Patterns=@('Phi-3-mini-4k-instruct-q8_0.gguf','*Phi-3-mini*.gguf') },
  [pscustomobject]@{ Stage='E'; Id='E_nemotron'; Arch='nemotron'; Family='Nemotron-4B'; Patterns=@('*Nemotron*4B*.gguf','*nemotron*nano*.gguf','*Nemotron*.gguf') },
  [pscustomobject]@{ Stage='F'; Id='F_mistral'; Arch='mistral'; Family='Mistral-7B'; Patterns=@('mistral*.gguf','sha256-f5074b1221da0f5a2910d33b642efa5b9eb58cfdddca1c79e16d7ad28aa2b31f') },
  [pscustomobject]@{ Stage='G'; Id='G_ds_r1_8b'; Arch='deepseek-r1'; Family='DeepSeek-R1-8B'; Patterns=@('DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf','*DeepSeek-R1*8B*.gguf') },
  [pscustomobject]@{ Stage='H'; Id='H_gemma4_e4b'; Arch='gemma4'; Family='Gemma4-E4B'; Patterns=@('gemma-4-E4B-it-Q4_K_M.gguf','*gemma-4-E4B*.gguf') },
  [pscustomobject]@{ Stage='I'; Id='I_phi3_med'; Arch='phi3'; Family='Phi-3-medium-14B'; Patterns=@('*Phi-3-medium*.gguf','*phi-3-medium*.gguf') },
  [pscustomobject]@{ Stage='J'; Id='J_codestral'; Arch='codestral'; Family='Codestral-22B'; Patterns=@('Codestral-22B-v0.1-Q4_K_M.gguf','*Codestral*22B*.gguf') }
)

$rows = @()
foreach ($m in $ladder) {
  $p = Find-Gguf $m.Patterns
  $ok = [bool]$p
  $sz = 0
  if ($ok) { $sz = [math]::Round((Get-Item -LiteralPath $p).Length / 1MB, 1) }
  $rows += [pscustomobject]@{
    Stage = $m.Stage; Id = $m.Id; Arch = $m.Arch; Family = $m.Family
    Path = $(if ($ok) { $p } else { '' }); SizeMB = $sz; Found = $ok
  }
  Write-Host ("{0} Found={1} {2}" -f $m.Stage, $ok, $(if ($ok) { $p } else { 'MISSING' }))
}
$rows | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outDir 'models_aj.json')
$missing = @($rows | Where-Object { -not $_.Found })
if ($missing.Count -gt 0) {
  Write-Host ("MISSING_COUNT=" + $missing.Count)
  $missing | ForEach-Object { Write-Host ("MISSING " + $_.Stage + " " + $_.Id) }
  exit 2
}
Write-Host 'ALL_AJ_PATHS_RESOLVED=1'
exit 0
