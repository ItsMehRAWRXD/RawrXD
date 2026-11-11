[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string[]]$Refs = @('b004-validate-isolated', 'origin/main', 'final/main')
)

$ErrorActionPreference = 'Stop'
Set-Location $Root

function GitText([string[]]$GitArgs) {
    $value = & git @GitArgs 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return (($value | Out-String).Trim())
}

$current = @(
    'src/codex', 'src/win32app', 'src/ide', 'src/ghost_text_renderer.cpp',
    'src/ghost_text_renderer.h', 'CMakeLists.txt'
)
$patterns = '(?i)(codex|ghost.?text|qt.?removal|qt.?free|win32.*ghost|webview)'
$records = [System.Collections.Generic.List[object]]::new()

foreach ($ref in $Refs) {
    $exists = GitText @('rev-parse', '--verify', $ref)
    if (-not $exists) {
        $records.Add([ordered]@{ ref = $ref; state = 'REF_UNAVAILABLE' })
        continue
    }
    $files = GitText @('ls-tree', '-r', '--name-only', $ref)
    $matches = @($files -split "`r?`n" | Where-Object { $_ -match $patterns })
    $records.Add([ordered]@{
        ref = $ref
        commit = GitText @('rev-parse', $ref)
        matching_files = $matches.Count
        notable_files = @($matches | Where-Object {
            $_ -match '(?i)(src/win32app/Win32IDE_GhostText|src/codex/|src/ghost_text_renderer|src/codex_integration|QT_REMOVAL)'
        } | Select-Object -First 80)
        state = 'SCANNED'
    })
}

$sourceFiles = Get-ChildItem (Join-Path $Root 'src') -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '(?i)(codex|ghost.?text)' } |
    ForEach-Object { $_.FullName.Substring($Root.Length + 1).Replace('\','/') }
$cmake = Get-Content (Join-Path $Root 'CMakeLists.txt') -Raw
$nativeWired = @(
    'src/win32app/Win32IDE_GhostText.cpp',
    'src/win32app/Win32IDE_CodexCommands.cpp',
    'src/codex/CodexCommandHandlers.cpp'
) | ForEach-Object { [ordered]@{ path = $_; exists = Test-Path (Join-Path $Root $_); cmake_reference = $cmake.Contains($_) } }

$qtMarkers = @(rg -l -i 'Q_OBJECT|QWidget|QPlainTextEdit|QTimer|Qt6::' src 2>$null | Where-Object { $_ -notmatch '\.bak$' })
$report = [ordered]@{
    schema = 'RAWRXD_LEGACY_CODEX_GHOST_AUDIT_001'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    git_revision = GitText @('rev-parse', 'HEAD')
    current_source_files = $sourceFiles
    native_integration_points = $nativeWired
    qt_marker_files = $qtMarkers.Count
    historical_refs = $records
    verdict = if (($nativeWired | Where-Object { -not $_.exists -or -not $_.cmake_reference }).Count -gt 0) { 'RECOVERY_CANDIDATES_FOUND' } else { 'NATIVE_WIRING_PRESENT' }
    certification = 'NOT_CERTIFIED'
}
$out = Join-Path $Root 'evidence/rawr_legacy_codex_ghost_audit.json'
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
$report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $out
Write-Output "AUDIT=$out"
Write-Output "NATIVE_INTEGRATION_GAPS=$(($nativeWired | Where-Object { -not $_.exists -or -not $_.cmake_reference }).Count)"
Write-Output "QT_MARKER_FILES=$($qtMarkers.Count)"
Write-Output "VERDICT=$($report.verdict)"
