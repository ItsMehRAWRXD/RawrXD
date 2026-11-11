$ErrorActionPreference = 'Continue'
$loop = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe'
$work = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\work_exact_write'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$motdDir = Join-Path $work '.cursor\rules'
New-Item -ItemType Directory -Force -Path $motdDir | Out-Null
Copy-Item 'g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc' (Join-Path $motdDir 'PassiveRoleNotRoleplay.mdc') -Force
$bugPath = Join-Path $work 'bug.cpp'
$bug = @(
  'int undeclared_fn(int a) { return a; }',
  'int main() {',
  '  return undeclared_fn(1, 2);',
  '}',
  ''
)
[IO.File]::WriteAllLines($bugPath, $bug)
$before = (Get-FileHash $bugPath -Algorithm SHA256).Hash
# Exact write payload the model must emit (arity fix only).
$payload = "int undeclared_fn(int a) { return a; }`nint main() {`n  return undeclared_fn(1);`n}`n"
$exact = 'TOOL write bug.cpp @@' + $payload + '@@'
$task = @"
Never hyphenate TOOL. Follow this exact sequence with no prose:
1) TOOL read bug.cpp
2) On the next turn emit EXACTLY these characters and nothing else:
$exact
3) TOOL build
4) TOOL finish
"@
Write-Output 'TASK_BYTES=' $task.Length
& $loop --provider ollama --model llama3.1:8b --task $task --workdir $work --target-file bug.cpp --build-command 'cl /nologo /EHsc bug.cpp' --run-command 'cmd /c echo PASS' --expected-output PASS --max-steps 8 --max-new 400 --context-size 4096 --temperature 0.0 --max-wall-time 600
$ec = $LASTEXITCODE
$after = (Get-FileHash $bugPath -Algorithm SHA256).Hash
$txt = [IO.File]::ReadAllText($bugPath)
$sem = [int](($after -ne $before) -and ($txt -notmatch 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)') -and ($txt -match 'undeclared_fn\s*\(\s*1\s*\)'))
$bok = [int]((Test-Path (Join-Path $work 'bug.exe')))
Write-Output '====SUMMARY===='
Write-Output ('EXIT=' + $ec)
Write-Output ('BEFORE=' + $before)
Write-Output ('AFTER=' + $after)
Write-Output ('SEM=' + $sem)
Write-Output ('EXE=' + $bok)
Write-Output '====BUG===='
Write-Output $txt
exit 0
