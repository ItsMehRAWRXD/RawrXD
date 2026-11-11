$ErrorActionPreference = 'Continue'
$loop = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe'
$work = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\work_ds_probe'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$motdDir = Join-Path $work '.cursor\rules'
New-Item -ItemType Directory -Force -Path $motdDir | Out-Null
Copy-Item 'g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc' (Join-Path $motdDir 'PassiveRoleNotRoleplay.mdc') -Force
$bug = @(
  'int undeclared_fn(int a) { return a; }',
  'int main() {',
  '  return undeclared_fn(1, 2);',
  '}',
  ''
)
[IO.File]::WriteAllLines((Join-Path $work 'bug.cpp'), $bug)
$before = (Get-FileHash (Join-Path $work 'bug.cpp') -Algorithm SHA256).Hash
$task = 'Never hyphenate TOOL. Order: TOOL read bug.cpp then TOOL write fixing undeclared_fn(1, 2) to undeclared_fn(1) keeping the function definition and main, then TOOL build, then TOOL finish.'
& $loop --provider ollama --model deepseek-coder-v2:16b --task $task --workdir $work --target-file bug.cpp --build-command 'cl /nologo /EHsc bug.cpp' --run-command 'cmd /c echo PASS' --expected-output PASS --max-steps 10 --max-new 512 --context-size 4096 --temperature 0.1 --max-wall-time 900
$ec = $LASTEXITCODE
$after = (Get-FileHash (Join-Path $work 'bug.cpp') -Algorithm SHA256).Hash
$txt = [IO.File]::ReadAllText((Join-Path $work 'bug.cpp'))
$sem = [int](($after -ne $before) -and ($txt -notmatch 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)') -and ($txt -match 'undeclared_fn\s*\(\s*1\s*\)'))
$bok = [int](Test-Path (Join-Path $work 'bug.exe'))
Write-Output '====SUMMARY===='
Write-Output ('EXIT=' + $ec)
Write-Output ('BEFORE=' + $before)
Write-Output ('AFTER=' + $after)
Write-Output ('SEM=' + $sem)
Write-Output ('EXE=' + $bok)
Write-Output '====BUG===='
Write-Output $txt
exit 0
