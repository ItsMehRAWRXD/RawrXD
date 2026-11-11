# RawrXD production evidence gate. Read-only with respect to source and models.
[CmdletBinding()]
param(
 [string]$Root = 'F:\rawrxd',
 [string]$Model = 'nemotron-bolt.gguf',
 [string]$Task = 'Reply with READY',
 [int]$TimeoutSeconds = 900,
 [switch]$Build
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$evidence=Join-Path $Root "evidence\bolt-gate-$stamp"
New-Item -ItemType Directory -Force -Path $evidence | Out-Null
function Write-Receipt($key,$value) { "$key=$value" | Tee-Object -FilePath (Join-Path $evidence 'receipt.txt') -Append }
function Fail($why) { Write-Receipt 'VERDICT' 'FAIL'; Write-Receipt 'REASON' $why; throw $why }
$targets=@(
 (Join-Path $Root 'build_cmake\bin-msvc\Release\rawr.exe'),
 (Join-Path $Root 'build_cmake\bin\Release\rawr.exe'),
 (Join-Path $Root 'build_cmake\Release\rawr.exe')
)
if ($Build) {
 $buildLog=Join-Path $evidence 'build.log'
 & cmake --build (Join-Path $Root 'build_cmake') --config Release --target RawrXD-CLI-V2 --parallel 8 *> $buildLog
 if ($LASTEXITCODE -ne 0) { Fail "BUILD_FAILED; see $buildLog" }
}
$found=@($targets | Where-Object {Test-Path -LiteralPath $_})
if ($found.Count -ne 1) {
 $found=@(Get-ChildItem -LiteralPath (Join-Path $Root 'build_cmake') -Filter 'rawr.exe' -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.FullName -match 'Release'} | Select-Object -ExpandProperty FullName)
}
if ($found.Count -ne 1) { Fail "EXPECTED_ONE_RELEASE_BINARY_FOUND_$($found.Count): $($found -join ', ')" }
$exe=$found[0]
$hash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
Write-Receipt 'EXECUTABLE' $exe
Write-Receipt 'SHA256' $hash
Write-Receipt 'TIMESTAMP' (Get-Date -Format o)
Write-Receipt 'MODEL_ARGUMENT' $Model
$git=& git -C $Root rev-parse HEAD 2>$null
if ($LASTEXITCODE -eq 0) {Write-Receipt 'GIT_COMMIT' $git}
$stdout=Join-Path $evidence 'stdout.log'; $stderr=Join-Path $evidence 'stderr.log'
$arguments=@('run',$Model,'--backend','deep2','--task',$Task)
$p=Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $Root -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden
try {
 if (-not $p.WaitForExit($TimeoutSeconds*1000)) {
  & taskkill /PID $p.Id /T /F *> $null
  Fail 'TIMEOUT'
 }
 $p.Refresh(); $code=$p.ExitCode
} finally { $p.Dispose() }
Write-Receipt 'EXIT_CODE' $code
$log=((Get-Content $stdout -Raw -ErrorAction SilentlyContinue) + "`n" + (Get-Content $stderr -Raw -ErrorAction SilentlyContinue))
if ($code -ne 0) {Fail 'NONZERO_EXIT'}
$matches=[regex]::Matches($log,'(?m)^GENERATED_TOKENS\s*=\s*(\d+)\s*$')
if ($matches.Count -eq 0) {Fail 'NO_GENERATED_TOKENS_RECEIPT'}
$tokens=[int]$matches[$matches.Count-1].Groups[1].Value
Write-Receipt 'GENERATED_TOKENS' $tokens
if ($tokens -lt 1) {Fail 'ZERO_TOKENS'}
if ($log -match '(?m)^(?:RAWR_RUN_STREAM_001|GEN_EXIT)\s*=\s*(?:FAIL|[1-9]\d*)\s*$') {Fail 'INFERENCE_RECEIPT_FAILURE'}
Write-Receipt 'VERDICT' 'PASS_BASIC_TOKEN_GENERATION'
Write-Host "Basic generation gate passed. Evidence: $evidence"
Write-Host 'Note: this does not certify numerical parity, task correctness, or agent authority.'
