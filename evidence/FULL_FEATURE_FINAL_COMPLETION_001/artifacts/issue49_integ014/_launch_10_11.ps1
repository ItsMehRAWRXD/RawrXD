$ErrorActionPreference = 'Stop'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$tip014 = Join-Path $root 'candidates\tip_final_integ_014'
$builtLoop = 'F:\rawrxd\build\bin\RelWithDebInfo\deep2_agentic_loop.exe'
Copy-Item -LiteralPath $builtLoop -Destination (Join-Path $tip014 'deep2_agentic_loop.exe') -Force
$loopSha = (Get-FileHash -LiteralPath (Join-Path $tip014 'deep2_agentic_loop.exe') -Algorithm SHA256).Hash
$tipSha = (Get-FileHash -LiteralPath (Join-Path $tip014 'RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash
$loopSha | Set-Content -LiteralPath (Join-Path $tip014 'LOOP_SHA256.txt') -Encoding ASCII
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@"
tip_final_integ_014
REASON=IDE_WATCHDOG_WALL_7B + LOOP_MSVC_VERIFY_WITHMSVCENV
FROM_TIP=tip_final_integ_013
TIP013_SHA=1BACCED694A98F39C9A5147CA6AEE1A86D1E87EF134691B28FF6BD9B463844C9
TIP014_SHA=$tipSha
LOOP_SHA256=$loopSha
LOOP_FIX=WithMsvcEnv on native write verify path
WATCHDOG_DEFAULT_STARTUP_MS=180000
WATCHDOG_DEFAULT_WALL_MS=2400000
FORCE_LOCAL_MAX_WALL_SEC=2400
HOST_SEED=OFF
PROMOTE=0
TIP_MOVE=0
CONTROLLING=CC79
ASOF_UTC=$asof
"@ | Set-Content -LiteralPath (Join-Path $tip014 'CANDIDATE.txt') -Encoding ASCII
Write-Output "TIP014_SHA=$tipSha"
Write-Output "LOOP_SHA=$loopSha"

$proj = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp'
$canonical = "/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.`r`n * Do not pre-fix - agent (or measured blocker) must own the repair.`r`n */`r`nint undeclared_fn(int a);`r`n`r`nint main() {`r`n  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */`r`n  return x;`r`n}`r`n"
[IO.File]::WriteAllBytes($proj, [Text.Encoding]::ASCII.GetBytes($canonical))
$before = (Get-FileHash -LiteralPath $proj -Algorithm SHA256).Hash
Write-Output "BEFORE=$before"
Write-Output "MATCH_HIST=$([int]($before -eq '716604C86C7A65754B78B0C5F359A4380D5899D0BFF34AB9C8FAFBEED8AC85C3'))"

cmd.exe /c "taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1" | Out-Null
Start-Sleep 1

$ev = Join-Path $root 'artifacts\issue49_integ014\step08_11_evidence'
New-Item -ItemType Directory -Force -Path $ev,(Join-Path $root 'artifacts\issue49_integ014') | Out-Null
$log = Join-Path $ev 'tip014_loop_exclusive_10_11.log'
$err = "$log.err"
$loop = Join-Path $tip014 'deep2_agentic_loop.exe'
$model = 'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
$workdir = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project'

@"
ASOF_UTC=$asof
LANE=TIP014_LOOP_EXCLUSIVE_10_11
TIP=tip_final_integ_014
TIP_SHA=$tipSha
LOOP_SHA=$loopSha
MODEL=$model
HOST_SEED=OFF
PROJECT_SHA_BEFORE=$before
PROJECT=$proj
MSVC_VERIFY_FIX=1
SHORT_FIXTURE_MOTD=1
"@ | Set-Content -LiteralPath (Join-Path $ev 'before_hashes.txt') -Encoding ASCII

Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue
$env:RAWRXD_ISSUE49_HOST_SEED = '0'
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'

$task = 'Fix bug.cpp so it compiles and links with MSVC. After TOOL read_motd and TOOL read bug.cpp, TOOL write bug.cpp with a COMPLETE fixed file that defines undeclared_fn and calls it with one argument, then TOOL build. HOST_SEED=OFF.'
$argList = @(
  '--model', $model,
  '--workdir', $workdir,
  '--target-file', 'bug.cpp',
  '--task', $task,
  '--max-steps', '12',
  '--max-new', '512',
  '--max-wall-time-sec', '7200',
  '--prefill-chunk', '128',
  '--batched-prefill', '1'
)
$p = Start-Process -FilePath $loop -ArgumentList $argList -WorkingDirectory $workdir -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -NoNewWindow
Write-Output "LAUNCHED_PID=$($p.Id)"
Write-Output "LOG=$log"
Start-Sleep 8
Select-String -LiteralPath $log -Pattern 'MOTD_WORKSPACE|MOTD_SHA256|\[env\] compiler' | Select-Object -First 8 | ForEach-Object { $_.Line }
