# compare_parity_trace.ps1 — Structural diff of CLI vs UI inference traces
#
# Usage:
#   .\compare_parity_trace.ps1 -Cli cli.json -Ui ui.json [-IgnoreTiming]
#
# Compares two trace envelopes emitted by:
#   rawrxd.exe run <model> --prompt "..." --emit-json-trace cli.json
#   $env:RAWRXD_PIPELINE_TRACE="ui.json"; RawrXD-Win32IDE.exe ...
#
# Exit code 0 = structural match, 1 = mismatch.

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$Cli,
    [Parameter(Mandatory=$true)] [string]$Ui,
    [switch]$IgnoreTiming
)

if (!(Test-Path $Cli)) { Write-Error "CLI trace not found: $Cli"; exit 2 }
if (!(Test-Path $Ui))  { Write-Error "UI  trace not found: $Ui";  exit 2 }

$a = Get-Content $Cli -Raw | ConvertFrom-Json
$b = Get-Content $Ui  -Raw | ConvertFrom-Json

$mismatches = @()

if ($a.model  -ne $b.model)  { $mismatches += "model: '$($a.model)' vs '$($b.model)'" }
if ($a.prompt -ne $b.prompt) { $mismatches += "prompt mismatch" }
if ($a.error  -ne $b.error)  { $mismatches += "error: '$($a.error)' vs '$($b.error)'" }
if ($a.token_count -ne $b.token_count) {
    $mismatches += "token_count: $($a.token_count) vs $($b.token_count)"
}

# Token-by-token comparison (the most important parity signal).
$min = [Math]::Min($a.tokens.Count, $b.tokens.Count)
$divergeAt = -1
for ($i = 0; $i -lt $min; $i++) {
    if ($a.tokens[$i] -ne $b.tokens[$i]) { $divergeAt = $i; break }
}
if ($divergeAt -ge 0) {
    $mismatches += "tokens diverge at index ${divergeAt}: cli=[$($a.tokens[$divergeAt])] ui=[$($b.tokens[$divergeAt])]"
}

# Joined-text equality (catches whitespace/encoding drift even if token splits differ).
$cliText = ($a.tokens -join '')
$uiText  = ($b.tokens -join '')
if ($cliText -ne $uiText) {
    $mismatches += "joined text differs (cli=$($cliText.Length) chars, ui=$($uiText.Length) chars)"
}

# Timing report (informational unless -IgnoreTiming is off and they diverge wildly).
$cliFt = $a.first_token_ms; $uiFt = $b.first_token_ms
$cliTot = $a.completed_ms;  $uiTot = $b.completed_ms
Write-Host ""
Write-Host "=== Parity Trace Comparison ==="
Write-Host ("  source       : {0,-12} {1,-12}" -f $a.source, $b.source)
Write-Host ("  model        : {0,-12} {1,-12}" -f $a.model,  $b.model)
Write-Host ("  token_count  : {0,-12} {1,-12}" -f $a.token_count, $b.token_count)
Write-Host ("  first_token  : {0,-12} {1,-12} ms" -f $cliFt, $uiFt)
Write-Host ("  completed    : {0,-12} {1,-12} ms" -f $cliTot, $uiTot)
Write-Host ("  joined_chars : {0,-12} {1,-12}" -f $cliText.Length, $uiText.Length)
Write-Host ""

if ($mismatches.Count -eq 0) {
    Write-Host "[PARITY OK] CLI and UI traces match structurally." -ForegroundColor Green
    exit 0
}

Write-Host "[PARITY FAIL] $($mismatches.Count) mismatch(es):" -ForegroundColor Red
$mismatches | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
exit 1
