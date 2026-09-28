param(
  [Parameter(Mandatory=$true)][string]$Probe,
  [Parameter(Mandatory=$true)][string]$Root,
  [string]$OutDir = ".\model_capability_manifests"
)
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$Probe=(Resolve-Path -LiteralPath $Probe).Path; $Root=(Resolve-Path -LiteralPath $Root).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null; $OutDir=(Resolve-Path $OutDir).Path
$rows=[System.Collections.Generic.List[object]]::new()
Get-ChildItem -LiteralPath $Root -Recurse -File -Filter *.gguf -ErrorAction SilentlyContinue | ForEach-Object {
  $safe=$_.BaseName -replace '[^A-Za-z0-9._-]','_'; $manifest=Join-Path $OutDir ($safe+'.capability.txt')
  Write-Host "SCAN $($_.FullName)"; $text=& $Probe $_.FullName 2>&1; $exit=$LASTEXITCODE
  $text | Set-Content -Encoding UTF8 -LiteralPath $manifest
  $kv=@{}; foreach($line in $text){$s=[string]$line;$i=$s.IndexOf('=');if($i -gt 0){$kv[$s.Substring(0,$i)]=$s.Substring($i+1)}}
  $rows.Add([pscustomobject]@{Model=$_.FullName;Bytes=$_.Length;ExitCode=$exit;Architecture=$kv['MODEL_ARCH'];Context=$kv['CONTEXT_LENGTH'];Embedding=$kv['EMBEDDING_LENGTH'];Blocks=$kv['BLOCK_COUNT'];Heads=$kv['ATTENTION_HEADS'];KVHeads=$kv['ATTENTION_KV_HEADS'];Vocab=$kv['VOCAB_SIZE'];MoE=$kv['MOE_STRUCTURE_PRESENT'];Experts=$kv['EXPERT_COUNT'];ExpertsUsed=$kv['EXPERTS_USED_PER_TOKEN'];SSM=$kv['SSM_STRUCTURE_PRESENT'];MLA=$kv['MLA_METADATA_PRESENT'];GQA=$kv['GQA_PRESENT'];ChatTemplate=$kv['CHAT_TEMPLATE_PRESENT'];Manifest=$manifest}) | Out-Null
}
$csv=Join-Path $OutDir 'MODEL_CAPABILITY_FLEET.csv'; $rows | Export-Csv $csv -NoTypeInformation -Encoding UTF8
@("GATE=RAWRXD_MODEL_CAPABILITY_FLEET_001","AUTHORITY=MODEL_FILES_ONLY","RUNTIME_CAPABILITY_JUDGMENT=0","MODEL_COUNT=$($rows.Count)","CSV=$csv","VERDICT=COMPLETE") | Set-Content (Join-Path $OutDir 'MODEL_CAPABILITY_FLEET.txt') -Encoding UTF8
Write-Host "WROTE $csv"
