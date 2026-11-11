#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only RawrXD full-audit collector (compact package, not full source upload).
.NOTES
  - Does not rebuild, modify, promote, or replace release binaries.
  - Preserves certified 4DE0… package untouched.
  - Excludes model weights, secrets, and generated build trees from the ZIP payload
    (build trees may be scanned lightly for compile_commands / target names only).
#>
[CmdletBinding()]
param(
    [string]$Root = 'F:\rawrxd',
    [string]$OutDir = 'F:\rawrxd\evidence\RAWRXD_FULL_AUDIT_001',
    [string]$Rc4Exe = 'F:\rawrxd\release\RawrXD-readiness-rc4\RawrXD-Win32IDE-Native-Ext.exe',
    [string]$CertifiedExe = 'F:\rawrxd\release\RawrXD-4DE06F9F-rc1\RawrXD-Win32IDE-Native-Ext.exe',
    [switch]$SkipFullHash
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

function Write-Utf8([string]$Path, [string]$Text) {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Esc-Csv([string]$s) {
    if ($null -eq $s) { return '' }
    $t = $s.Replace('"','""')
    if ($t -match '[,"\r\n]') { return '"' + $t + '"' }
    return $t
}

function Test-ExcludedDir([string]$full) {
    $n = $full.ToLowerInvariant().Replace('/','\')
    $parts = $n -split '\\'
    foreach ($p in $parts) {
        if ($p -in @(
            'node_modules','.git','build','build_tip_chat_ctrl_enter_002','build_tip_debug_rel',
            'build_computer_use_ide','build_daily_use_candidate','build_tip_ext_host_001',
            '_deps','_e2e','_final_build','web-test','models','gguf','weights','.cache',
            'obj','bin','x64','debug','release\obj'
        )) { return $true }
        if ($p -like 'build_*' -or $p -like '.build_*' -or $p -like '*_build') { return $true }
    }
    # Keep F:\rawrxd\release for SHA text only; do not walk huge binaries into manifest hash loop beyond known exes
    if ($n -match '\\release\\rawrxd-v' ) { return $true }
    if ($n -match '\\3rdparty\\ggml\\' -and $n -match '\\build') { return $true }
    return $false
}

function Test-SourceExt([string]$ext) {
    $e = $ext.ToLowerInvariant()
    return $e -in @(
        '.c','.cc','.cpp','.cxx','.h','.hh','.hpp','.hxx','.inl','.inc',
        '.asm','.s','.cmake','.py','.ps1','.json','.md','.txt','.rc','.def',
        '.idl','.proto','.yml','.yaml','.toml','.ini','.shader','.hlsl','.glsl','.comp'
    )
}

function Test-SecretName([string]$name) {
    $n = $name.ToLowerInvariant()
    return ($n -match '(^|\.)env$' -or $n -match 'credential|secret|password|\.pem$|\.pfx$|\.key$|token\.json')
}

Write-Host "=== RAWRXD_FULL_AUDIT_001 collector ==="
Write-Host "Root=$Root"
Write-Host "OutDir=$OutDir"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$cfgDir = Join-Path $OutDir 'config_snapshots'
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null

# --- RC4 / 4DE0 identity ---
$rc4Sha = 'MISSING'
$certSha = 'MISSING'
if (Test-Path -LiteralPath $Rc4Exe) {
    $rc4Sha = (Get-FileHash -LiteralPath $Rc4Exe -Algorithm SHA256).Hash
}
if (Test-Path -LiteralPath $CertifiedExe) {
    $certSha = (Get-FileHash -LiteralPath $CertifiedExe -Algorithm SHA256).Hash
}
$expectedRc4 = '78E187AA9A4C95A4282A862A2D76E8B24DCD03BF6F57E036B2C463FB22418596'
$expectedCert = '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6'
$rc4Lines = @(
    "RC4_EXE=$Rc4Exe",
    "RC4_SHA256=$rc4Sha",
    "RC4_SHA_MATCH_EXPECTED=$($rc4Sha -eq $expectedRc4)",
    "EXPECTED_RC4_SHA256=$expectedRc4",
    "CERTIFIED_EXE=$CertifiedExe",
    "CERTIFIED_SHA256=$certSha",
    "CERTIFIED_SHA_MATCH_EXPECTED=$($certSha -eq $expectedCert)",
    "EXPECTED_CERTIFIED_SHA256=$expectedCert",
    "PROMOTE=0",
    "TIP_CLIMB=HOLD",
    "COLLECTOR_UTC=$((Get-Date).ToUniversalTime().ToString('o'))",
    "NOTE=Discovery package only; not runtime proof of every feature."
) -join "`n"
Write-Utf8 (Join-Path $OutDir 'RC4_SHA256.txt') $rc4Lines

# Snapshot key config / cmake entrypoints (text only)
$snapList = @(
    'CMakeLists.txt',
    'CMakePresets.json',
    'config\chat_model_routes.json',
    'src\computer_use\CMakeLists.txt',
    'evidence\IDE_RELEASE_READINESS_001\computer_use_001\DISPOSITION.txt',
    'evidence\IDE_RELEASE_READINESS_001\computer_use_001\CANDIDATE_STATUS.txt',
    'evidence\IDE_RELEASE_READINESS_001\computer_use_001\FINAL_STATUS.txt',
    'evidence\IDE_RELEASE_READINESS_001\G01_G15_RC4_DELTA.txt',
    'release\RawrXD-readiness-rc4\manifest.json'
)
foreach ($rel in $snapList) {
    $src = Join-Path $Root $rel
    if (Test-Path -LiteralPath $src) {
        $dest = Join-Path $cfgDir ($rel -replace '\\','__')
        Copy-Item -LiteralPath $src -Destination $dest -Force
    }
}

# --- Walk inventory (scoped roots for depth + whole-tree shallow for structure) ---
$scanRoots = @(
    (Join-Path $Root 'src'),
    (Join-Path $Root 'include'),
    (Join-Path $Root 'tools'),
    (Join-Path $Root 'scripts'),
    (Join-Path $Root 'config'),
    (Join-Path $Root 'cmake'),
    (Join-Path $Root 'evidence\IDE_RELEASE_READINESS_001'),
    (Join-Path $Root 'evidence\RAWRXD_PERFORMANCE_001'),
    (Join-Path $Root '~dev\rawrxd\src')
)

$manifestPath = Join-Path $OutDir 'FILE_MANIFEST.csv'
$manifest = New-Object System.Collections.Generic.List[string]
$manifest.Add('rel_path,abs_path,size_bytes,sha256,extension,directory,hashed') | Out-Null

$symbolPath = Join-Path $OutDir 'SOURCE_SYMBOLS.csv'
$symbols = New-Object System.Collections.Generic.List[string]
$symbols.Add('rel_path,kind,name,line,snippet') | Out-Null

$flagsPath = Join-Path $OutDir 'FEATURE_FLAGS.csv'
$flags = New-Object System.Collections.Generic.List[string]
$flags.Add('rel_path,flag,line,context') | Out-Null

$cmdPath = Join-Path $OutDir 'COMMAND_REGISTRY.csv'
$cmds = New-Object System.Collections.Generic.List[string]
$cmds.Add('rel_path,kind,name,line,snippet') | Out-Null

$backendsPath = Join-Path $OutDir 'MODEL_BACKENDS.csv'
$backends = New-Object System.Collections.Generic.List[string]
$backends.Add('rel_path,kind,name,line,snippet') | Out-Null

$deep2Path = Join-Path $OutDir 'DEEP2_FEATURES.csv'
$deep2 = New-Object System.Collections.Generic.List[string]
$deep2.Add('rel_path,family_hint,name,line,snippet') | Out-Null

$stubsPath = Join-Path $OutDir 'STUBS_AND_TODOS.csv'
$stubs = New-Object System.Collections.Generic.List[string]
$stubs.Add('rel_path,kind,line,snippet') | Out-Null

$fileIndex = @{}  # basename -> list of rel paths (dup detect)
$filesScanned = 0
$filesHashed = 0

$rxClass = [regex]'(?m)^\s*(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\b'
$rxFunc = [regex]'(?m)^\s*(?:[\w:<>\*&~\s]+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*(?:const\s*)?(?:override\s*)?(?:noexcept\s*)?\{?'
$rxFlag = [regex]'(?:#\s*(?:ifdef|ifndef|if)\s+([A-Za-z0-9_]+)|(?:option|cmake_dependent_option)\s*\(\s*([A-Za-z0-9_]+)|RAWRXD_[A-Z0-9_]+|ENABLE_[A-Z0-9_]+|HAVE_[A-Z0-9_]+|RAWR_[A-Z0-9_]+)'
$rxCmd = [regex]'(?:WM_COMMAND|IDM_|IDS_|on[A-Z][A-Za-z0-9_]+|RegisterCommand|AddMenu|computer_use\.[a-z_]+|runInTerminal|writeFile|readFile)'
$rxBackend = [regex]'(?:Ollama|Deep2|GGUF|Vulkan|CPUInference|Medusa|MoE|Mamba|SSM|Agentic|Native-Ext|Win32IDE)'
$rxDeep2 = [regex]'(?:Deep2Engine|Speculative|Cyclone|Toroidal|Plasma|OutOfCore|GpuForward|GpuMoE|MLA|KVCache|Residency|Sovereign)'
$rxStub = [regex]'(?i)\b(TODO|FIXME|STUB|NOT[_ ]IMPLEMENTED|UNIMPLEMENTED|placeholder|experimental)\b'

function Add-SymbolRow([string]$rel,[string]$kind,[string]$name,[int]$line,[string]$snip) {
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    if ($name.Length -gt 120) { $name = $name.Substring(0,120) }
    if ($snip.Length -gt 200) { $snip = $snip.Substring(0,200) }
    $symbols.Add( ((Esc-Csv $rel)+','+(Esc-Csv $kind)+','+(Esc-Csv $name)+','+$line+','+(Esc-Csv $snip)) ) | Out-Null
}

foreach ($scanRoot in $scanRoots) {
    if (-not (Test-Path -LiteralPath $scanRoot)) { continue }
    Write-Host "Scanning $scanRoot ..."
    Get-ChildItem -LiteralPath $scanRoot -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $full = $_.FullName
        if (Test-ExcludedDir $full) { return }
        if (Test-SecretName $_.Name) { return }
        $rel = $full.Substring($Root.Length).TrimStart('\')
        $ext = $_.Extension
        $dir = Split-Path $rel -Parent
        $size = $_.Length
        # Skip huge files in inventory content parse (>8MB)
        $hash = ''
        $hashed = '0'
        if (-not $SkipFullHash -and (Test-SourceExt $ext) -and $size -gt 0 -and $size -le 2MB) {
            try {
                $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
                $hashed = '1'
                $filesHashed++
            } catch { $hash = 'ERROR' }
        } elseif ($SkipFullHash) {
            $hash = 'SKIPPED'
        }
        $manifest.Add( ((Esc-Csv $rel)+','+(Esc-Csv $full)+','+$size+','+$hash+','+(Esc-Csv $ext)+','+(Esc-Csv $dir)+','+$hashed) ) | Out-Null
        $bn = $_.Name.ToLowerInvariant()
        if (-not $fileIndex.ContainsKey($bn)) { $fileIndex[$bn] = New-Object System.Collections.Generic.List[string] }
        $fileIndex[$bn].Add($rel) | Out-Null
        $filesScanned++

        if (-not (Test-SourceExt $ext)) { return }
        if ($size -le 0 -or $size -gt 4MB) { return }
        if ($ext -in '.md','.txt','.json','.yml','.yaml','.toml','.ini') {
            # still scan for stubs/flags lightly
        }
        $text = $null
        try { $text = [System.IO.File]::ReadAllText($full) } catch { return }
        if ([string]::IsNullOrEmpty($text)) { return }

        $lineMap = $text -split "`n"
        for ($i=0; $i -lt [Math]::Min($lineMap.Count, 20000); $i++) {
            $line = $lineMap[$i]
            $ln = $i + 1
            if ($rxStub.IsMatch($line)) {
                $stubs.Add( ((Esc-Csv $rel)+',stub_or_todo,'+$ln+','+(Esc-Csv $line.Trim())) ) | Out-Null
            }
        }

        foreach ($m in $rxClass.Matches($text)) {
            $before = $text.Substring(0, $m.Index)
            $ln = ([regex]::Matches($before, "`n")).Count + 1
            Add-SymbolRow $rel 'class_or_struct' $m.Groups[1].Value $ln $m.Value.Trim()
        }

        # Feature flags / cmake options
        foreach ($m in $rxFlag.Matches($text)) {
            $name = $m.Groups[1].Value
            if (-not $name) { $name = $m.Groups[2].Value }
            if (-not $name) { $name = $m.Value }
            $before = $text.Substring(0, [Math]::Min($m.Index, $text.Length))
            $ln = ([regex]::Matches($before, "`n")).Count + 1
            $flags.Add( ((Esc-Csv $rel)+','+(Esc-Csv $name)+','+$ln+','+(Esc-Csv ($m.Value.Trim()))) ) | Out-Null
        }

        if ($rxCmd.IsMatch($text)) {
            foreach ($m in $rxCmd.Matches($text)) {
                $before = $text.Substring(0, $m.Index)
                $ln = ([regex]::Matches($before, "`n")).Count + 1
                $cmds.Add( ((Esc-Csv $rel)+',command_or_handler,'+(Esc-Csv $m.Value)+','+$ln+','+(Esc-Csv $lineMap[[Math]::Min($ln-1,$lineMap.Count-1)].Trim())) ) | Out-Null
            }
        }
        if ($rxBackend.IsMatch($text)) {
            foreach ($m in $rxBackend.Matches($text)) {
                $before = $text.Substring(0, $m.Index)
                $ln = ([regex]::Matches($before, "`n")).Count + 1
                $backends.Add( ((Esc-Csv $rel)+',backend_hint,'+(Esc-Csv $m.Value)+','+$ln+','+(Esc-Csv $m.Value)) ) | Out-Null
            }
        }
        if ($rel -match '(?i)deep2|moe|mamba|medusa|sovereign|vulkan' -or $rxDeep2.IsMatch($text)) {
            foreach ($m in $rxDeep2.Matches($text)) {
                $before = $text.Substring(0, $m.Index)
                $ln = ([regex]::Matches($before, "`n")).Count + 1
                $deep2.Add( ((Esc-Csv $rel)+',deep2_hint,'+(Esc-Csv $m.Value)+','+$ln+','+(Esc-Csv $m.Value)) ) | Out-Null
            }
        }
    }
}

Write-Host "Writing CSV outputs (filesScanned=$filesScanned hashed=$filesHashed) ..."
Write-Utf8 $manifestPath ($manifest -join "`n")
Write-Utf8 $symbolPath ($symbols -join "`n")
Write-Utf8 $flagsPath ($flags -join "`n")
Write-Utf8 $cmdPath ($cmds -join "`n")
Write-Utf8 $backendsPath ($backends -join "`n")
Write-Utf8 $deep2Path ($deep2 -join "`n")
Write-Utf8 $stubsPath ($stubs -join "`n")

# Duplicates by basename
$dupPath = Join-Path $OutDir 'DUPLICATE_IMPLEMENTATIONS.csv'
$dup = New-Object System.Collections.Generic.List[string]
$dup.Add('basename,count,paths') | Out-Null
foreach ($k in ($fileIndex.Keys | Sort-Object)) {
    $list = $fileIndex[$k]
    if ($list.Count -gt 1) {
        $dup.Add( ((Esc-Csv $k)+','+$list.Count+','+(Esc-Csv ($list -join ' | '))) ) | Out-Null
    }
}
Write-Utf8 $dupPath ($dup -join "`n")

# CMake target graph (text extract from root CMakeLists + include globs)
$cmakeGraph = Join-Path $OutDir 'CMAKE_TARGET_GRAPH.txt'
$cmakeFiles = @()
$cmakeFiles += Get-ChildItem -LiteralPath $Root -Filter 'CMakeLists.txt' -File -ErrorAction SilentlyContinue
$cmakeFiles += Get-ChildItem -LiteralPath (Join-Path $Root 'src') -Filter 'CMakeLists.txt' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { -not (Test-ExcludedDir $_.FullName) }
$cmakeLines = New-Object System.Collections.Generic.List[string]
$cmakeLines.Add("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))") | Out-Null
$cmakeLines.Add('NOTE=Text extraction of add_executable/add_library/target_link_libraries; not a configured cmake graph dump.') | Out-Null
$rxTarget = [regex]'(?m)^\s*(add_executable|add_library|target_link_libraries|target_sources|option)\s*\(([^)\r\n]{0,400})'
foreach ($cf in $cmakeFiles) {
    $rel = $cf.FullName.Substring($Root.Length).TrimStart('\')
    $cmakeLines.Add("--- FILE $rel ---") | Out-Null
    try {
        $t = [System.IO.File]::ReadAllText($cf.FullName)
        foreach ($m in $rxTarget.Matches($t)) {
            $cmakeLines.Add( ($m.Groups[1].Value + ' ( ' + ($m.Groups[2].Value -replace '\s+',' ').Trim() + ' )') ) | Out-Null
        }
    } catch {
        $cmakeLines.Add("READ_ERROR=$($_.Exception.Message)") | Out-Null
    }
}
# Highlight RC4-related targets
$cmakeLines.Add('--- RC4_RELATED_HINTS ---') | Out-Null
$cmakeLines.Add('RawrXD-Win32IDE-Native / RawrXD-Win32IDE-Native-Ext / rawrxd_computer_use / deep2_engine_lib / deep2_agentic_loop') | Out-Null
Write-Utf8 $cmakeGraph ($cmakeLines -join "`n")

# compile_commands.json if present in known build trees (copy path reference only / small extract)
$ccOut = Join-Path $OutDir 'COMPILE_COMMANDS.json'
$ccCandidates = @(
    'F:\rawrxd\build_tip_debug_rel\compile_commands.json',
    'F:\rawrxd\build_tip_chat_ctrl_enter_002\compile_commands.json',
    'F:\rawrxd\build\compile_commands.json'
)
$ccFound = $false
foreach ($cc in $ccCandidates) {
    if (Test-Path -LiteralPath $cc) {
        # Copy truncated: first 200KB or filter Ext-related entries
        $raw = [System.IO.File]::ReadAllText($cc)
        if ($raw.Length -gt 500000) {
            # Filter lines mentioning Native-Ext or computer_use or deep2
            $kept = New-Object System.Collections.Generic.List[string]
            $kept.Add('[') | Out-Null
            $parts = $raw -split '\},\{'
            $n = 0
            foreach ($p in $parts) {
                if ($p -match 'Win32IDE|computer_use|deep2|Deep2|agentic') {
                    if ($n -gt 0) { $kept.Add(',') | Out-Null }
                    if (-not $p.TrimStart().StartsWith('{')) { $kept.Add('{') | Out-Null }
                    $kept.Add($p.Trim().TrimStart('{').TrimEnd(']').TrimEnd('}')) | Out-Null
                    $kept.Add('}') | Out-Null
                    $n++
                    if ($n -ge 400) { break }
                }
            }
            $kept.Add(']') | Out-Null
            Write-Utf8 $ccOut ("{`"source`":`"$(Esc-Csv $cc)`",`"note`":`"filtered subset`",`"entries_approx`":$n,`"data`":" + ($kept -join '') + "}")
        } else {
            Copy-Item -LiteralPath $cc -Destination $ccOut -Force
        }
        $ccFound = $true
        break
    }
}
if (-not $ccFound) {
    Write-Utf8 $ccOut (@'
{
  "note": "compile_commands.json not found in known RC4 build trees",
  "searched": [
    "F:\\rawrxd\\build_tip_debug_rel\\compile_commands.json",
    "F:\\rawrxd\\build_tip_chat_ctrl_enter_002\\compile_commands.json",
    "F:\\rawrxd\\build\\compile_commands.json"
  ],
  "rc4_build_tree_hint": "F:\\rawrxd\\build_tip_debug_rel",
  "status": "NOT_FOUND"
}
'@)
}

# Evidence index
$evPath = Join-Path $OutDir 'EVIDENCE_INDEX.csv'
$ev = New-Object System.Collections.Generic.List[string]
$ev.Add('rel_path,size_bytes,sha256,kind_hint') | Out-Null
$evRoots = @(
    (Join-Path $Root 'evidence\IDE_RELEASE_READINESS_001'),
    (Join-Path $Root 'evidence\RAWRXD_PERFORMANCE_001'),
    (Join-Path $Root 'evidence\RELEASE_FREEZE_001')
)
foreach ($er in $evRoots) {
    if (-not (Test-Path -LiteralPath $er)) { continue }
    Get-ChildItem -LiteralPath $er -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension -match '\.(txt|md|json|csv|log)$' -and $_.Length -le 2MB -and -not (Test-ExcludedDir $_.FullName)
        } | ForEach-Object {
            $rel = $_.FullName.Substring($Root.Length).TrimStart('\')
            $h = ''
            try { $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } catch { $h = 'ERROR' }
            $kind = 'evidence'
            if ($rel -match 'G0[0-9]|G1[0-5]') { $kind = 'gate_receipt' }
            elseif ($rel -match 'computer_use') { $kind = 'computer_use' }
            elseif ($rel -match 'PERF|benchmark|TPS') { $kind = 'performance' }
            elseif ($rel -match 'FAIL|failure|NOT_RUN') { $kind = 'failure_or_open' }
            $ev.Add( ((Esc-Csv $rel)+','+$_.Length+','+$h+','+$kind) ) | Out-Null
        }
}
Write-Utf8 $evPath ($ev -join "`n")

# Summary
$summary = @"
# RAWRXD_FULL_AUDIT_001 — Compact discovery package

## Identity
- Generated UTC: $((Get-Date).ToUniversalTime().ToString('o'))
- Workspace: ``$Root``
- RC4 exe: ``$Rc4Exe``
- RC4 SHA-256: ``$rc4Sha`` (expected ``$expectedRc4``; match=$($rc4Sha -eq $expectedRc4))
- Certified 4DE0 exe: ``$CertifiedExe``
- Certified SHA-256: ``$certSha`` (expected ``$expectedCert``; match=$($certSha -eq $expectedCert))
- PROMOTE=0 · TIP_CLIMB=HOLD · CERTIFIED_4DE0=IMMUTABLE

## Collector scope
- Read-only scan of ``src``, ``include``, ``tools``, ``scripts``, ``config``, ``cmake``, selected evidence trees, and ``~dev/rawrxd/src`` if present.
- Excluded: node_modules, most ``build_*`` trees, model/weight dirs, secrets by name heuristic.
- Files scanned (inventory rows): $filesScanned
- Files hashed: $filesHashed
- This package supports **discovery / build-inclusion mapping**. It does **not** by itself prove runtime PASS for every feature.

## Outputs
- FILE_MANIFEST.csv
- SOURCE_SYMBOLS.csv
- FEATURE_FLAGS.csv
- COMMAND_REGISTRY.csv
- MODEL_BACKENDS.csv
- DEEP2_FEATURES.csv
- CMAKE_TARGET_GRAPH.txt
- COMPILE_COMMANDS.json
- STUBS_AND_TODOS.csv
- DUPLICATE_IMPLEMENTATIONS.csv
- EVIDENCE_INDEX.csv
- RC4_SHA256.txt
- config_snapshots/

## Audit law
``SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS``
``NOT_RUN != PASS``

## Next verification (not performed by this collector)
1. Map which files from FILE_MANIFEST / CMAKE_TARGET_GRAPH / COMPILE_COMMANDS actually link into RC4 ``78E187…``.
2. Classify each Deep2/IDE feature: verified / unverified / unreachable / stub / experimental / duplicate / broken.
3. Run RC4 runtime gates (Computer Use GUI E2E, G02–G14, agent repair, G15) against the exact SHA.
"@
Write-Utf8 (Join-Path $OutDir 'AUDIT_SUMMARY.md') $summary

# ZIP (exclude nothing inside OutDir except we don't include binaries)
$zipPath = Join-Path (Split-Path $OutDir -Parent) 'RAWRXD_FULL_AUDIT_001.zip'
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($OutDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $true)
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
$zipSize = (Get-Item -LiteralPath $zipPath).Length
Write-Host "ZIP=$zipPath"
Write-Host "ZIP_SHA256=$zipHash"
Write-Host "ZIP_BYTES=$zipSize"
Write-Utf8 (Join-Path $OutDir 'PACKAGE_ZIP.txt') "ZIP_PATH=$zipPath`nZIP_SHA256=$zipHash`nZIP_BYTES=$zipSize`n"
Write-Host "DONE"
