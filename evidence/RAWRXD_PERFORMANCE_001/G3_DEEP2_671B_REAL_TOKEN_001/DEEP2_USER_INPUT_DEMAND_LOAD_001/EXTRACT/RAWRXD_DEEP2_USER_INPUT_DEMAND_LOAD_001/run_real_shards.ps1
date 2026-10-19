param(
  [string]$ModelDir='F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE',
  [UInt32[]]$Tokens=@()
)
$ErrorActionPreference='Stop'
$shards=Get-ChildItem (Join-Path $ModelDir '*.gguf') | Sort-Object Name | ForEach-Object FullName
if($shards.Count -ne 11){ throw "Expected 11 GGUF shards, found $($shards.Count)" }
& "$PSScriptRoot\d2u_inspect.exe" $shards
if($LASTEXITCODE -ne 0){ throw "d2u_inspect failed: $LASTEXITCODE" }
if($Tokens.Count){
  $args=@(); $args += $shards; $args += '--'; $args += ($Tokens | ForEach-Object { $_.ToString() })
  & "$PSScriptRoot\d2u_run_tokens.exe" $args
  if($LASTEXITCODE -ne 0){ throw "d2u_run_tokens failed: $LASTEXITCODE" }
}
