# tip012 same-SHA loop-exclusive: close S09 reinjection + S11 agent-owned build recovery.
# SHA 6191E58E / LOOP CEB66901. HOST_SEED=OFF. Logs to files (no hung interactive shell).
$ErrorActionPreference = 'Stop'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$tip012 = Join-Path $root 'candidates\tip_final_integ_012'
$expect = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247'
$tipSha = (Get-FileHash -LiteralPath (Join-Path $tip012 'RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash
if ($tipSha -ne $expect) { throw "SHA_DRIFT tip=$tipSha expect=$expect" }
$loopSha = (Get-FileHash -LiteralPath (Join-Path $tip012 'deep2_agentic_loop.exe') -Algorithm SHA256).Hash
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$proj = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp'
$canonical = "/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.`r`n * Do not pre-fix - agent (or measured blocker) must own the repair.`r`n */`r`nint undeclared_fn(int a);`r`n`r`nint main() {`r`n  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */`r`n  return x;`r`n}`r`n"
[IO.File]::WriteAllBytes($proj, [Text.Encoding]::ASCII.GetBytes($canonical))
$before = (Get-FileHash -LiteralPath $proj -Algorithm SHA256).Hash
Write-Output "BEFORE=$before"
Write-Output "MATCH_HIST=$([int]($before -eq '716604C86C7A65754B78B0C5F359A4380D5899D0BFF34AB9C8FAFBEED8AC85C3'))"
Write-Output "TIP_SHA=$tipSha"
Write-Output "LOOP_SHA=$loopSha"

cmd.exe /c "taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1" | Out-Null
Start-Sleep 2

$ev = Join-Path $root 'artifacts\issue49_integ012\step08_11_evidence'
New-Item -ItemType Directory -Force -Path $ev,(Join-Path $root 'artifacts\issue49_integ012') | Out-Null
$log = Join-Path $ev 'tip012_loop_exclusive_09_11.log'
$err = "$log.err"
if (Test-Path -LiteralPath $log) { Move-Item -LiteralPath $log -Destination ($log + ".bak_$((Get-Date).ToString('yyyyMMdd-HHmmss'))") -Force -EA SilentlyContinue }
if (Test-Path -LiteralPath $err) { Move-Item -LiteralPath $err -Destination ($err + ".bak_$((Get-Date).ToString('yyyyMMdd-HHmmss'))") -Force -EA SilentlyContinue }

@"
ASOF_UTC=$asof
LANE=TIP012_LOOP_EXCLUSIVE_09_11_RECOVERY
TIP=tip_final_integ_012
TIP_SHA=$tipSha
LOOP_SHA=$loopSha
MODEL=F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf
HOST_SEED=OFF
PROJECT_SHA_BEFORE=$before
PROJECT=$proj
"@ | Set-Content -LiteralPath (Join-Path $ev 'before_hashes.txt') -Encoding ASCII

Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue
$env:RAWRXD_ISSUE49_HOST_SEED = '0'
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'

$loop = Join-Path $tip012 'deep2_agentic_loop.exe'
$model = 'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
$workdir = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project'
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
"LAUNCHED_PID=$($p.Id)" | Set-Content -LiteralPath (Join-Path $ev 'loop_pid.txt') -Encoding ASCII
Write-Output "LAUNCHED_PID=$($p.Id)"
Write-Output "LOG=$log"
Start-Sleep 8
Select-String -LiteralPath $log -Pattern 'MOTD_WORKSPACE|MOTD_SHA256|\[env\] compiler|Vulkan initialized' -EA SilentlyContinue |
  Select-Object -First 8 | ForEach-Object { $_.Line }
