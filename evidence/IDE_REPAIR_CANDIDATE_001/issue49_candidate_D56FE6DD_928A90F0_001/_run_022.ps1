$ErrorActionPreference = 'Continue'
$harness = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\harness\Invoke-Issue49Live74aa.ps1'
$outDir = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\issue49_gui_ollama_qwen3_022'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$tip = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\bin\RawrXD-Win32IDE-Native-Ext.exe'
$expect = 'D56FE6DD5FADF45F1E475740BFBC348415DDE0B44C33D2790B93E5B9EA023635'
$loopSha = (Get-FileHash -LiteralPath 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\bin\deep2_agentic_loop.exe' -Algorithm SHA256).Hash
"PRE_LOOP_SHA=$loopSha" | Set-Content (Join-Path $outDir 'PRE_RUN.txt')
& $harness `
  -TipExe $tip `
  -ExpectSha $expect `
  -OutDir $outDir `
  -LogDir (Join-Path $outDir 'logs_live') `
  -UserData (Join-Path $outDir 'userdata') `
  -OllamaAgentModel 'qwen3:8b' `
  -AgentWaitSec 600
$code = $LASTEXITCODE
"HARNESS_EXIT=$code" | Add-Content (Join-Path $outDir 'PRE_RUN.txt')
# Capture whether type_error.316 still appears
$ledger = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\bin\.rawrxd\ledger\agent_session.json'
if (Test-Path $ledger) {
  $raw = Get-Content -Raw -LiteralPath $ledger
  $has316 = $raw.Contains('type_error.316')
  $has97 = $raw.Contains('0x97')
  $verdictIdx = $raw.IndexOf('OLLAMA_AGENT_VERDICT')
  $verdict = if ($verdictIdx -ge 0) { $raw.Substring($verdictIdx, [Math]::Min(80, $raw.Length - $verdictIdx)) } else { 'NONE' }
  @(
    "TYPE_ERROR_316=$has316"
    "HAS_0x97_TEXT=$has97"
    "VERDICT_SNIP=$verdict"
  ) | Set-Content (Join-Path $outDir 'POST_LOOP_LEDGER_SCAN.txt')
}
exit $code
