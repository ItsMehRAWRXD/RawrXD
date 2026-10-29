[CmdletBinding()]
param(
    [string]$Root = 'F:\rawrxd',
    [string[]]$Models = @(
        'nemotron-3-nano:4b',
        'nemotron-3.5-bolt:latest',
        'nemotron-3.5-lightning:30b',
        'flint:latest'
    ),
    [int]$TimeoutSeconds = 900,
    [string]$EvidenceRoot = 'F:\rawrxd\evidence\RAWRXD_AGENTIC_MODEL_READINESS_20261028'
)

$ErrorActionPreference = 'Stop'
$cli = Join-Path $Root 'build_ide\bin-msvc\rawr.exe'
if (-not (Test-Path -LiteralPath $cli)) { throw "Missing CLI: $cli" }
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

function Get-ModelSpec([string]$Name) {
    try {
        Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/show' -Method Post `
            -ContentType 'application/json' -Body (@{ model = $Name } | ConvertTo-Json -Compress) `
            -TimeoutSec 30
    } catch { $null }
}

function Invoke-Model([string]$Name, [string]$RunDir, [string]$Fixture) {
    $prompt = @"
Use the real workspace tools to edit exactly this source file: $Fixture
1. Call readFile on the file.
2. Call editFiles once, changing only `return 0;` to `return 1;`.
3. Call readFile again and verify the exact change.
Do not answer with prose instead of tool calls. Do not touch any other file.
Finish with RAWRXD_AGENTIC_EDIT_COMPLETE.
"@
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $cli
    $psi.WorkingDirectory = $Root
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    $psi.Environment['RAWRXD_OLLAMA_ENDPOINT'] = 'http://127.0.0.1:11434'
    # Windows PowerShell 5.1/.NET Framework does not expose the modern
    # ProcessStartInfo.ArgumentList property. Build one quoted command line
    # so the same harness works in both Windows PowerShell and pwsh.
    $safePrompt = ($prompt -replace '"', '\\"' -replace "`r?`n", ' ')
    $psi.Arguments = 'run "' + $Name + '" --backend ollama --workspace "' +
        $Root + '" --mode agent --fresh-session --approve-mutations ' +
        '--tool-scope source-edit --max-tokens 512 --prompt "' + $safePrompt + '"'

    # Snapshot the ledger boundary before launching this process.  Timestamps
    # are not a safe run delimiter when another worker appends concurrently;
    # the append-only line boundary is the authoritative isolation boundary.
    $espPath = Join-Path $Root '.rawrxd\ledger\agent_esp.jsonl'
    $espBeforeCount = 0
    if (Test-Path -LiteralPath $espPath) {
        $espBeforeCount = @(Get-Content -LiteralPath $espPath -ErrorAction SilentlyContinue).Count
    }

    $p = [Diagnostics.Process]::new()
    $p.StartInfo = $psi
    $watch = [Diagnostics.Stopwatch]::StartNew()
    [void]$p.Start()
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $timedOut = -not $p.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) { try { $p.Kill($true) } catch {} ; $p.WaitForExit() }
    $watch.Stop()
    $stdout = $outTask.GetAwaiter().GetResult()
    $stderr = $errTask.GetAwaiter().GetResult()
    $combined = ($stdout + "`n" + $stderr).Trim()
    $exitCode = if ($timedOut) { -1 } else { $p.ExitCode }

    # The persisted session ledger is the authoritative tool ledger.  The
    # process may emit only model prose on stdout/stderr, and ESP is a useful
    # fallback event stream but not sufficient to prove tool arguments or
    # success.  Prefer a session whose model and workspace match this run.
    $eventMessages = @()
    $sessionToolLines = @()
    $sessionPath = Join-Path $Root '.rawrxd\ledger\agent_session.json'
    $session = $null
    if (Test-Path -LiteralPath $sessionPath) {
        try { $session = Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json } catch { $session = $null }
    }
    $sessionMatches = $null -ne $session -and
        [string]$session.workspace_root -eq $Root -and
        [string]$session.model_identity -match ('(^|/)' + [regex]::Escape($Name) + '$')
    if ($sessionMatches) {
        foreach ($call in @($session.tool_calls)) {
            $toolName = [string]$call.tool
            $status = if ([bool]$call.ok) { 'PASS' } else { 'FAIL' }
            $target = [string]$call.args.path
            $sessionToolLines += ('TOOL_RESULT name={0} status={1} target={2}' -f $toolName, $status, $target)
        }
        $eventMessages = @($session.tool_calls | ForEach-Object {
            'tool={0} ok={1}' -f ([string]$_.tool), ([bool]$_.ok)
        })
    }

    # Agent ESP is a run-delimited fallback when the session ledger is not
    # available.  Use the append boundary captured before process launch;
    # never scan historical records by timestamp.
    if (Test-Path -LiteralPath $espPath) {
        $espAfterLines = @(Get-Content -LiteralPath $espPath -ErrorAction SilentlyContinue)
        $newEspLines = @()
        if ($espAfterLines.Count -gt $espBeforeCount) {
            $newEspLines = @($espAfterLines[$espBeforeCount..($espAfterLines.Count - 1)])
        }
        $events = @($newEspLines |
            ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
            Where-Object { $null -ne $_ })
        if (-not $sessionMatches) {
            $eventMessages = @($events | ForEach-Object { [string]$_.message })
        }
    }
    $toolLines = if ($sessionMatches) {
        @($sessionToolLines)
    } else {
        @($eventMessages | Where-Object { $_ -match 'TOOL_RESULT' })
    }
    if ($toolLines.Count -eq 0) {
        $toolLines = @([regex]::Matches($combined, '(?m)^.*TOOL_RESULT.*$') | ForEach-Object Value)
    }
    $toolNames = @($toolLines | ForEach-Object {
        $m = [regex]::Match($_, 'name=([^ ]+)')
        if ($m.Success) { $m.Groups[1].Value }
    })
    $readPass = @($toolLines | Where-Object { $_ -match 'name=readFile.*status=PASS' }).Count
    $editPass = @($toolLines | Where-Object { $_ -match 'name=editFiles.*status=PASS' }).Count
    $toolFailures = @($toolLines | Where-Object { $_ -match 'status=FAIL' }).Count
    [pscustomobject]@{
        stdout = $stdout
        stderr = $stderr
        combined = $combined
        exit_code = $exitCode
        timed_out = $timedOut
        elapsed_ms = $watch.ElapsedMilliseconds
        tool_lines = $toolLines
        esp_messages = $eventMessages
        esp_lines_added = if (Test-Path -LiteralPath $espPath) {
            $espAfterLines.Count - $espBeforeCount
        } else { 0 }
        tool_names = $toolNames
        read_pass_count = $readPass
        edit_pass_count = $editPass
        tool_failure_count = $toolFailures
    }
}

$results = [System.Collections.Generic.List[object]]::new()
foreach ($model in $Models) {
    $safe = ($model -replace '[^A-Za-z0-9_.-]', '_')
    $runDir = Join-Path $EvidenceRoot $safe
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null
    $fixture = Join-Path $runDir 'fixture.cpp'
    $baseline = @'
#include <cstdio>
int main() { std::puts("RAWRXD_AGENTIC_BEFORE"); return 0; }
'@
    $baseline = $baseline.Replace("`n", "`r`n")
    $expected = $baseline.Replace('return 0;', 'return 1;')
    Set-Content -LiteralPath $fixture -Value $baseline -Encoding utf8
    $beforeHash = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
    $spec = Get-ModelSpec $model
    $caps = @()
    if ($null -ne $spec) { $caps = @($spec.capabilities | ForEach-Object { [string]$_ }) }

    $rec = [ordered]@{
        schema = 'RAWRXD_AGENTIC_MODEL_READINESS_001'
        model = $model
        workspace_root = $Root
        fixture = $fixture
        capabilities = $caps
        family = if ($null -ne $spec) { $spec.details.family } else { $null }
        parameter_size = if ($null -ne $spec) { $spec.details.parameter_size } else { $null }
        real_model_inference = $false
        motd_gate = $false
        read_tool = $false
        edit_tool = $false
        readback_tool = $false
        file_changed_count = 0
        diff_verified = $false
        synthetic_success = 0
        status = 'PENDING'
    }

    if ($null -eq $spec) {
        $rec.status = 'MODEL_METADATA_UNAVAILABLE'
    } elseif (-not ($caps -contains 'completion')) {
        $rec.status = 'UNSUPPORTED_COMPLETION'
    } elseif (-not ($caps -contains 'tools')) {
        $rec.status = 'UNSUPPORTED_TOOL_CALLING'
    } else {
        $run = Invoke-Model $model $runDir $fixture
        $run.stdout | Set-Content -LiteralPath (Join-Path $runDir 'stdout.txt') -Encoding utf8
        $run.stderr | Set-Content -LiteralPath (Join-Path $runDir 'stderr.txt') -Encoding utf8
        $after = Get-Content -LiteralPath $fixture -Raw
        $afterHash = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
        $afterNorm = ($after -replace "`r`n", "`n").TrimEnd()
        $baselineNorm = ($baseline -replace "`r`n", "`n").TrimEnd()
        $expectedNorm = ($expected -replace "`r`n", "`n").TrimEnd()
        $rec.real_model_inference = $run.combined -match 'Backend:\s+ollama|backend=ollama|OLLAMA'
        $rec.motd_gate = $run.combined -match 'MOTD_ACK=1'
        $rec.read_tool = $run.read_pass_count -ge 1
        $rec.edit_tool = $run.edit_pass_count -eq 1
        $rec.readback_tool = $run.read_pass_count -ge 2
        $rec.file_changed_count = if ($afterNorm -ne $baselineNorm) { 1 } else { 0 }
        $rec.diff_verified = ($afterNorm -eq $expectedNorm) -and ($afterHash -ne $beforeHash)
        $rec.synthetic_success = 0
        $rec.exit_code = $run.exit_code
        $rec.elapsed_ms = $run.elapsed_ms
        $rec.tool_names = $run.tool_names
        $rec.tool_failure_count = $run.tool_failure_count
        $rec.before_sha256 = $beforeHash
        $rec.after_sha256 = $afterHash
        $rec.status = if ($run.exit_code -eq 0 -and $rec.real_model_inference -and
                          $rec.motd_gate -and $rec.read_tool -and $rec.edit_tool -and
                          $rec.readback_tool -and $rec.file_changed_count -eq 1 -and
                          $rec.diff_verified -and $rec.synthetic_success -eq 0 -and
                          $run.tool_failure_count -eq 0) { 'PASS' } else { 'FAIL' }
    }
    $rec.timestamp_utc = [DateTime]::UtcNow.ToString('o')
    $rec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runDir 'receipt.json') -Encoding utf8
    # Restore the fixture after every model; the receipt retains the hashes.
    Set-Content -LiteralPath $fixture -Value $baseline -Encoding utf8
    $results.Add([pscustomobject]$rec)
    Write-Output ("{0} | {1}" -f $model, $rec.status)
}

$summary = [ordered]@{
    schema = 'RAWRXD_AGENTIC_MODEL_READINESS_001'
    cli = $cli
    cli_sha256 = (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    results = @($results)
    pass = @($results | Where-Object status -eq 'PASS').Count
    nonpass = @($results | Where-Object status -ne 'PASS').Count
    promotion = 'DISABLED'
}
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $EvidenceRoot 'SUMMARY.json') -Encoding utf8
Write-Output ("SUMMARY=$($EvidenceRoot)\SUMMARY.json PASS=$($summary.pass) NONPASS=$($summary.nonpass)")
