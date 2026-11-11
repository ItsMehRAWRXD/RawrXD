$ErrorActionPreference = 'Continue'
$out = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\live_issue49_loop527_agent'
if (Test-Path $out) { Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $out,(Join-Path $out '.cursor\rules') | Out-Null
Copy-Item 'g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc' (Join-Path $out '.cursor\rules\PassiveRoleNotRoleplay.mdc') -Force
$bug = "#include <cstdio>`nint add(int a, int b) { return a - b; }`nint main() { std::printf(`"AGENT_RESULT=%d`n`", add(2, 3)); return 0; }`n"
[IO.File]::WriteAllText((Join-Path $out 'bug.cpp'), $bug)
$loop = 'F:\rawrxd\build_tip_debug_rel\bin\deep2_agentic_loop.exe'
$build = "cl /nologo /EHsc /std:c++20 /Fe:`"$out\bug.exe`" `"$out\bug.cpp`""
$run = "$out\bug.exe"
$stdout = Join-Path $out 'agent.stdout.log'
$stderr = Join-Path $out 'agent.stderr.log'
$arg = @(
  '--provider','ollama',
  '--model','bigdaddyg-productivity-local:latest',
  '--workdir',$out,
  '--target-file','bug.cpp',
  '--build-command',$build,
  '--run-command',$run,
  '--max-steps','12',
  '--max-wall-time-sec','600',
  '--expected-output','AGENT_RESULT=5'
)
$p = Start-Process -FilePath $loop -ArgumentList $arg -WorkingDirectory $out `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
"PID=$($p.Id)" | Set-Content (Join-Path $out 'pid.txt')
Write-Host "STARTED_PID=$($p.Id) OUT=$out"
