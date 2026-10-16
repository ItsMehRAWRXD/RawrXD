param([string]$Root='F:\rawrxd',[string]$Model='nemotron-bolt.gguf',[string]$Exe='',[switch]$Build)
$ErrorActionPreference='Stop'
$buildDir=Join-Path $Root 'build_cmake'
if ($Build) {
  & cmake --build $buildDir --config Release --target RawrXD-CLI-V2 --parallel 8
  if ($LASTEXITCODE -ne 0) { throw 'BUILD=FAIL' }
}
if (-not $Exe) {
  $candidates=@(Get-ChildItem $buildDir -Recurse -Filter rawr.exe -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
  if ($candidates.Count -ne 1) { throw "Specify -Exe explicitly: discovered $($candidates.Count) candidate(s)" }
  $Exe=$candidates[0].FullName
}
if (!(Test-Path $Exe)) { throw "Executable not found: $Exe" }
$resolved=(Resolve-Path $Exe).Path
$hash=(Get-FileHash $resolved -Algorithm SHA256).Hash
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
$evidence=Join-Path $Root "evidence\bolt_forward_$stamp"
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
"EXE=$resolved`nSHA256=$hash`nMODEL=$Model" | Set-Content (Join-Path $evidence 'identity.txt')
Push-Location $Root
try {
  $output=& $resolved run $Model --backend deep2 --task 'Reply with READY' 2>&1 | Out-String
  $exit=$LASTEXITCODE
} finally { Pop-Location }
$output | Set-Content (Join-Path $evidence 'run.log')
$tokens=[regex]::Match($output,'(?m)^GENERATED_TOKENS\s*=\s*(\d+)\s*$')
$tokenCount=if($tokens.Success){[int64]$tokens.Groups[1].Value}else{0}
$pass=($exit -eq 0 -and $tokens.Success -and $tokenCount -gt 0 -and $output -notmatch 'MODEL_LOAD=FAIL|RAWR_RUN_STREAM_001=FAIL')
"EXIT=$exit`nGENERATED_TOKENS=$tokenCount`nGATE=$(if($pass){'PASS'}else{'FAIL'})" | Set-Content (Join-Path $evidence 'verdict.txt')
Write-Host "EVIDENCE=$evidence"
Get-Content (Join-Path $evidence 'verdict.txt')
if (-not $pass) { exit 1 }
