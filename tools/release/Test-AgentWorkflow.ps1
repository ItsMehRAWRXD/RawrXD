#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$PackageDirectory,
      [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
      [string]$Model = 'llama3.1:8b',
      [switch]$ProtocolFixture)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseHash.ps1')
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'A new evidence directory is required.' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$workspace = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
$source = Join-Path $workspace 'bug.cpp'
$before = "#include <cstdio>`nint add(int a, int b) { return a - b; }`nint main() { std::printf(`"AGENT_RESULT=%d\n`", add(2, 3)); return 0; }`n"
[IO.File]::WriteAllText($source, $before, [Text.UTF8Encoding]::new($false))
if ($ProtocolFixture) {
    [IO.File]::WriteAllBytes((Join-Path $workspace 'payload.bin'), [byte[]]@(77, 90, 0, 1))
}
$policyDirectory = Join-Path $workspace '.cursor\rules'
New-Item -ItemType Directory -Path $policyDirectory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\..\.cursor\rules\PassiveRoleNotRoleplay.mdc') -Destination $policyDirectory
$exe = Join-Path $PackageDirectory 'deep2_agentic_loop.exe'
$stdout = Join-Path $workspace 'agent.stdout.log'
$stderr = Join-Path $workspace 'agent.stderr.log'
$task = 'Your FIRST reply must be exactly TOOL read bug.cpp. After reading, use TOOL write bug.cpp @@complete corrected source@@ to change return a - b to return a + b. Emit REAL newlines inside @@...@@ (byte 0x0A), never the two characters \n. Keep #include on its own line. Preserve main and AGENT_RESULT. Do not call build, test, or finish until the corrected file has been written and verified.'
$arguments = @('--provider', 'ollama', '--model', $Model, '--workdir', $workspace,
    '--target-file', 'bug.cpp', '--task', $task, '--build-command',
    'cl /nologo /W4 /WX /EHsc bug.cpp /Fe:bug.exe', '--run-command', 'bug.exe',
    '--expected-output', 'AGENT_RESULT=5', '--max-steps', '8', '--max-new', '512',
    '--context-size', '4096', '--temperature', '0', '--max-wall-time-sec', '180')
$argumentLine = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
$process = Start-Process -FilePath $exe -ArgumentList $argumentLine -WorkingDirectory $workspace `
    -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
$exited = $process.WaitForExit(240000)
if (-not $exited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue; $process.WaitForExit() }
else { $process.WaitForExit() | Out-Null }
$process.Refresh()
function Read-TextWithRetry([string]$Path) {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try { return [IO.File]::ReadAllText($Path) }
        catch [IO.IOException] { Start-Sleep -Milliseconds 200 }
    }
    return [IO.File]::ReadAllText($Path)
}
$text = (Read-TextWithRetry $stdout) + (Read-TextWithRetry $stderr)
$after = [IO.File]::ReadAllText($source)
$runOutput = ''; $runExit = -1
if (Test-Path -LiteralPath (Join-Path $workspace 'bug.exe')) {
    $runOutput = (& (Join-Path $workspace 'bug.exe') | Out-String).Trim()
    $runExit = $LASTEXITCODE
}
# Start-Process ExitCode can remain $null even after a timed WaitForExit; drain
# above, then fall back to the loop's authoritative stdout verdict marker.
$exitCode = $process.ExitCode
if ($null -eq $exitCode) {
    if ($text -match 'OLLAMA_AGENT_VERDICT PASS') { $exitCode = 0 }
    elseif ($text -match 'OLLAMA_AGENT_VERDICT FAIL') { $exitCode = 1 }
    else { $exitCode = -1 }
}
$passed = $exited -and ([int]$exitCode -eq 0) -and $before -ne $after -and
    $runExit -eq 0 -and $runOutput -eq 'AGENT_RESULT=5' -and
    $text -match 'OLLAMA_AGENT_VERDICT PASS'
$receipt = [ordered]@{ tested_utc = [DateTime]::UtcNow.ToString('o');
    scope = $(if ($ProtocolFixture) { 'Deterministic mock protocol regression; not real model inference.' }
              else { 'Packaged agent subprocess; GUI dispatch requires separate evidence.' });
    ide_sha256 = (Get-FileHash -LiteralPath (Join-Path $PackageDirectory 'RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash;
    agent_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash;
    model = $Model; process_id = $process.Id; process_exit = [int]$exitCode;
    timed_out = -not $exited; source_changed = $before -ne $after;
    source_after_sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash;
    independent_run_exit = $runExit; independent_run_output = $runOutput;
    verdict = $(if ($passed) { 'PASS' } else { 'FAIL' }); stdout = $stdout; stderr = $stderr }
$receipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $workspace 'agent-workflow.json') -Encoding UTF8
$receipt
if (-not $passed) { exit 1 }
