param(
    [string]$HexmagPath = "$PSScriptRoot/../hexmag.sqlite",
    [string]$SourceDir = "$PSScriptRoot/..",
    [string]$OutDir = "$PSScriptRoot/../bin/hexmag",
    [string]$GraphDot = "$PSScriptRoot/../bin/reverse-cmake/fallback_graph.dot",
    [switch]$WhatIf
)

# Hexmag Orchestrator: chains micro-agents to progress C++→MASM conversion.
# - Initializes outputs, optional hexmag DB tasks, and emits MASM stub files per folder.
# - Non-intrusive: safe to run repeatedly; logs and JSON summaries for review.

$ErrorActionPreference = 'Stop'
function Log([string]$msg) {
    $global:LogPath = Join-Path $OutDir 'hexmag-orchestrator.log'
    $ts = (Get-Date).ToString('s')
    $line = "[$ts] $msg"
    Write-Host $line
    Add-Content -Path $global:LogPath -Value $line -Encoding UTF8
}

function Ensure-OutDir {
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
}

function Find-Sqlite3 {
    $cmd = Get-Command sqlite3 -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Hexmag-Init([string]$sqlite3) {
    if (-not (Test-Path $HexmagPath)) {
        Log "Hexmag DB not found at $HexmagPath; continuing without DB tasks."
        return $false
    }
    if (-not $sqlite3) {
        Log "sqlite3.exe not found; skipping DB task writes (will emit JSON tasks)."
        return $false
    }
    $schema = @'
CREATE TABLE IF NOT EXISTS tasks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS logs(
  ts TEXT DEFAULT CURRENT_TIMESTAMP,
  msg TEXT
);
'@
    & $sqlite3 $HexmagPath "$schema" | Out-Null
    Log "Hexmag schema ensured."
    return $true
}

function Scan-CppFiles([string]$root) {
    Get-ChildItem -Path $root -Recurse -Include *.cpp,*.hpp,*.h -File |
        Where-Object { $_.FullName -notmatch "\\src\\masm\\" }
}

function Emit-Tasks([array]$files, [string]$sqlite3, [bool]$dbOk) {
    $tasksJson = @()
    foreach ($f in $files) {
        $kind = if ($f.Extension -match 'hpp|h') { 'header-stub' } else { 'source-port' }
        $tasksJson += @{ path=$f.FullName; kind=$kind; status='queued' }
        if ($dbOk) {
            $sql = "INSERT INTO tasks(path,kind,status) VALUES('" + $f.FullName.Replace("'","''") + "','" + $kind + "','queued');"
            & $sqlite3 $HexmagPath $sql | Out-Null
        }
    }
    $tasksPath = Join-Path $OutDir 'tasks.json'
    $tasksJson | ConvertTo-Json -Depth 4 | Set-Content -Path $tasksPath -Encoding UTF8
    Log "Wrote task list: $tasksPath ($($tasksJson.Count) items)."
}

function Run-MasmStubGen([string]$inputDir, [string]$outputFile) {
    $exe = Join-Path $SourceDir 'bin/Release/masm_source_stub_gen.exe'
    if (Test-Path $exe) {
        if ($WhatIf) { Log "[WhatIf] Would run: $exe `"$inputDir`" `"$outputFile`""; return }
        Log "Generating MASM stubs from $inputDir → $outputFile"
        & $exe $inputDir $outputFile
        if (Test-Path $outputFile) { return }
        Log "masm_source_stub_gen did not produce output; falling back to PS stub generator."
    } else {
        Log "masm_source_stub_gen.exe not found at $exe; using PS stub generator."
    }
    # Fallback: quick-and-dirty header scan
    $headers = Get-ChildItem -Path $inputDir -Recurse -Include *.h,*.hpp -File -ErrorAction SilentlyContinue
    $names = New-Object System.Collections.Generic.HashSet[string]
    foreach($h in $headers){
        $text = Get-Content -Path $h.FullName -ErrorAction SilentlyContinue
        foreach($line in $text){
            if($line -match '\)\s*;\s*$' -and $line -match '\('){
                if($line -match '([A-Za-z_][A-Za-z0-9_]*)\s*\('){
                    [void]$names.Add($Matches[1])
                }
            }
        }
    }
    $content = @()
    $content += '; Generated stubs (fallback)'
    $content += '.code'
    foreach($n in $names){
        $content += "PUBLIC $n"
        $content += "$n PROC"
        $content += '  ret'
        $content += "$n ENDP"
        $content += ''
    }
    $content += 'END'
    $dir = Split-Path -Path $outputFile -Parent
    if(-not (Test-Path $dir)){ New-Item -ItemType Directory -Path $dir | Out-Null }
    $content -join "`n" | Set-Content -Path $outputFile -Encoding ASCII
    Log "Fallback stubs written: $outputFile (count=$($names.Count))"
}

try {
    Ensure-OutDir
    Log "Hexmag orchestrator starting…"

    $sqlite3 = Find-Sqlite3
    $dbOk = Hexmag-Init $sqlite3

    # 1) Scan sources and emit tasks
    $files = Scan-CppFiles -root $SourceDir
    Emit-Tasks -files $files -sqlite3 $sqlite3 -dbOk $dbOk

    # 2) Generate MASM stubs for key header roots
    $stubRootPairs = @(
        @{ In = (Join-Path $SourceDir 'include'); Out = (Join-Path $OutDir 'include_stubs.asm') },
        @{ In = (Join-Path $SourceDir 'src/qtapp'); Out = (Join-Path $OutDir 'qtapp_stubs.asm') },
        @{ In = (Join-Path $SourceDir 'src'); Out = (Join-Path $OutDir 'src_stubs.asm') }
    )
    foreach ($p in $stubRootPairs) {
        if (Test-Path $p.In) { Run-MasmStubGen -inputDir $p.In -outputFile $p.Out }
    }

    # 3) Save a small summary markdown for quick review
    $md = @()
    $md += "# Hexmag Orchestrator Summary"
    $md += "- SourceDir: $SourceDir"
    $md += "- OutDir: $OutDir"
    $md += "- DB: " + ($(if ($dbOk) { 'OK (sqlite3 available)' } else { 'Unavailable or no sqlite3' }))
    $md += "- Tasks: $(Join-Path $OutDir 'tasks.json')"
    $md += "- Stubs:"
    $md += "  - include → include_stubs.asm"
    $md += "  - src/qtapp → qtapp_stubs.asm"
    $md += "  - src (fallback) → src_stubs.asm"
    $mdPath = Join-Path $OutDir 'SUMMARY.md'
    $md -join "`n" | Set-Content -Path $mdPath -Encoding UTF8
    Log "Wrote summary: $mdPath"

    Log "Hexmag orchestrator complete."
}
catch {
    Log ("ERROR: " + $_.Exception.Message)
    exit 1
}