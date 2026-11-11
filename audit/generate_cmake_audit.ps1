$ErrorActionPreference = 'Stop'

$Root = 'd:\rawrxd'
$CMakeFile = Join-Path $Root 'CMakeLists.txt'
$OutDir = Join-Path $Root 'audit'

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

function Strip-Comment {
    param([string]$Line)
    $inQuote = $false
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Line.Length; $i++) {
        $ch = $Line[$i]
        if ($ch -eq '"') {
            $inQuote = -not $inQuote
            [void]$sb.Append($ch)
            continue
        }
        if ($ch -eq '#' -and -not $inQuote) {
            break
        }
        [void]$sb.Append($ch)
    }
    return $sb.ToString()
}

function Get-CMakeBlocks {
    param([string[]]$Lines)

    $blocks = New-Object System.Collections.Generic.List[object]
    $ifDepth = 0
    $inBlock = $false
    $startLine = 0
    $depth = 0
    $cmd = ''
    $conditional = $false
    $buf = New-Object System.Collections.Generic.List[string]

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $lineNum = $i + 1
        $line = Strip-Comment $Lines[$i]

        if (-not $inBlock) {
            if ($line -match '^\s*endif\s*\(') {
                if ($ifDepth -gt 0) { $ifDepth-- }
            }

            if ($line -match '^\s*(set|list|add_executable|add_library|target_sources|set_target_properties|if|elseif|else|endif)\s*\(') {
                $inBlock = $true
                $startLine = $lineNum
                $cmd = $Matches[1].ToLowerInvariant()
                $conditional = ($ifDepth -gt 0)
                $buf.Clear()
                $depth = 0
            }

            if ($line -match '^\s*if\s*\(') {
                $ifDepth++
            }
        }

        if ($inBlock) {
            $buf.Add($line)
            $openCount = ([regex]::Matches($line, '\(')).Count
            $closeCount = ([regex]::Matches($line, '\)')).Count
            $depth += ($openCount - $closeCount)

            if ($depth -le 0) {
                $text = ($buf -join "`n").Trim()
                $blocks.Add([pscustomobject]@{
                    Cmd = $cmd
                    Line = $startLine
                    Conditional = $conditional
                    Text = $text
                })

                if ($cmd -eq 'if') {
                    $ifDepth++
                } elseif ($cmd -eq 'endif') {
                    if ($ifDepth -gt 0) { $ifDepth-- }
                }

                $inBlock = $false
                $startLine = 0
                $depth = 0
                $cmd = ''
                $conditional = $false
                $buf.Clear()
            }
        }
    }

    return $blocks
}

function Get-ArgsFromBlock {
    param([string]$Text)
    $m = [regex]::Match($Text, '\((.*)\)\s*$', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $m.Success) { return @() }
    $body = $m.Groups[1].Value
    $matches = [regex]::Matches($body, '"(?:\\.|[^"])*"|\$\{[^}]+\}|[^\s\r\n\t]+')
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($match in $matches) {
        $t = $match.Value.Trim()
        if (-not $t) { continue }
        if ($t.StartsWith('"') -and $t.EndsWith('"') -and $t.Length -ge 2) {
            $t = $t.Substring(1, $t.Length - 2)
        }
        $out.Add($t)
    }
    return $out
}

function Normalize-PathToken {
    param([string]$Token)
    $t = $Token.Replace('\\', '/').Trim()
    if ($t.StartsWith('./')) { $t = $t.Substring(2) }
    return $t
}

function Is-SourceLike {
    param([string]$Token)
    $t = Normalize-PathToken $Token
    if (-not $t) { return $false }
    if ($t.StartsWith('${') -and $t.EndsWith('}')) { return $false }
    if ($t.StartsWith('$<')) { return $false }
    $ext = [System.IO.Path]::GetExtension($t).ToLowerInvariant()
    $sourceExts = @('.c','.cc','.cpp','.cxx','.h','.hpp','.hh','.asm','.rc')
    return (($sourceExts -contains $ext) -and $t.Contains('/'))
}

function Classify-Target {
    param([string]$Name, [bool]$Exclude)
    $lname = $Name.ToLowerInvariant()
    if ($lname -match 'bench|benchmark|tps') { return 'benchmark' }
    if ($lname -match 'test|validation|smoke|witness|verify|cert') { return 'test' }
    if ($Name -in @('RawrXD-Win32IDE','RawrEngine','RawrXD_Gold')) { return 'shipped/product' }
    if (-not $Exclude) { return 'supporting production' }
    return 'excluded/experimental'
}

$lines = Get-Content -Path $CMakeFile -Encoding UTF8
$blocks = Get-CMakeBlocks -Lines $lines

$varMap = @{}
$targets = @{}
$targetSources = @{}
$addExeCount = 0
$addLibCount = 0

function Add-VarItem {
    param([string]$Var, [string]$Token, [bool]$Conditional, [int]$Line)
    if (-not $varMap.ContainsKey($Var)) {
        $varMap[$Var] = New-Object System.Collections.Generic.List[object]
    }
    $varMap[$Var].Add([pscustomobject]@{ Token = $Token; Conditional = $Conditional; Line = $Line })
}

function Add-TargetSource {
    param([string]$Target, [string]$PathToken, [bool]$Conditional, [int]$Line)
    if (-not $targetSources.ContainsKey($Target)) {
        $targetSources[$Target] = New-Object System.Collections.Generic.List[object]
    }
    $targetSources[$Target].Add([pscustomobject]@{ Path = (Normalize-PathToken $PathToken); Conditional = $Conditional; Line = $Line })
}

function Expand-AndAddToken {
    param([string]$Target, [string]$Token, [bool]$Conditional, [int]$Line)
    if ($Token.StartsWith('${') -and $Token.EndsWith('}')) {
        $var = $Token.Substring(2, $Token.Length - 3)
        if ($varMap.ContainsKey($var)) {
            foreach ($entry in $varMap[$var]) {
                if (Is-SourceLike $entry.Token) {
                    Add-TargetSource -Target $Target -PathToken $entry.Token -Conditional ($Conditional -or $entry.Conditional) -Line $Line
                }
            }
        }
    } else {
        if (Is-SourceLike $Token) {
            Add-TargetSource -Target $Target -PathToken $Token -Conditional $Conditional -Line $Line
        }
    }
}

foreach ($b in $blocks | Sort-Object Line) {
    $args = Get-ArgsFromBlock -Text $b.Text
    if ($args.Count -eq 0) { continue }

    switch ($b.Cmd) {
        'set' {
            if ($args.Count -ge 2) {
                $var = $args[0]
                $varMap[$var] = New-Object System.Collections.Generic.List[object]
                for ($i = 1; $i -lt $args.Count; $i++) {
                    Add-VarItem -Var $var -Token $args[$i] -Conditional $b.Conditional -Line $b.Line
                }
            }
        }
        'list' {
            if ($args.Count -ge 3) {
                $op = $args[0].ToUpperInvariant()
                $var = $args[1]
                $rest = $args[2..($args.Count - 1)]
                if (-not $varMap.ContainsKey($var)) {
                    $varMap[$var] = New-Object System.Collections.Generic.List[object]
                }
                if ($op -eq 'APPEND') {
                    foreach ($tok in $rest) {
                        Add-VarItem -Var $var -Token $tok -Conditional $b.Conditional -Line $b.Line
                    }
                } elseif ($op -eq 'REMOVE_ITEM') {
                    $remove = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                    foreach ($tok in $rest) { [void]$remove.Add($tok) }
                    $kept = New-Object System.Collections.Generic.List[object]
                    foreach ($entry in $varMap[$var]) {
                        if (-not $remove.Contains($entry.Token)) { $kept.Add($entry) }
                    }
                    $varMap[$var] = $kept
                } elseif ($op -eq 'FILTER' -and $rest.Count -ge 3) {
                    $mode = $rest[0].ToUpperInvariant()
                    $kind = $rest[1].ToUpperInvariant()
                    if ($mode -eq 'EXCLUDE' -and $kind -eq 'REGEX') {
                        $pattern = $rest[2]
                        $kept = New-Object System.Collections.Generic.List[object]
                        foreach ($entry in $varMap[$var]) {
                            $norm = $entry.Token.Replace('\\', '/')
                            if ($norm -notmatch $pattern) {
                                $kept.Add($entry)
                            }
                        }
                        $varMap[$var] = $kept
                    }
                }
            }
        }
        'add_executable' {
            $addExeCount++
            $target = $args[0]
            $decl = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }
            $exclude = ($decl -contains 'EXCLUDE_FROM_ALL')

            if (-not $targets.ContainsKey($target)) {
                $targets[$target] = [pscustomobject]@{
                    Name = $target
                    Type = 'executable'
                    Exclude = $exclude
                    Lines = New-Object System.Collections.Generic.List[int]
                }
            }
            $targets[$target].Lines.Add($b.Line)
            if ($exclude) { $targets[$target].Exclude = $true }

            $skip = @('WIN32','MACOSX_BUNDLE','EXCLUDE_FROM_ALL')
            foreach ($tok in $decl) {
                if ($skip -contains $tok) { continue }
                Expand-AndAddToken -Target $target -Token $tok -Conditional $b.Conditional -Line $b.Line
            }
        }
        'add_library' {
            $addLibCount++
            $target = $args[0]
            $decl = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }
            $exclude = ($decl -contains 'EXCLUDE_FROM_ALL')

            if (-not $targets.ContainsKey($target)) {
                $targets[$target] = [pscustomobject]@{
                    Name = $target
                    Type = 'library'
                    Exclude = $exclude
                    Lines = New-Object System.Collections.Generic.List[int]
                }
            }
            $targets[$target].Lines.Add($b.Line)
            if ($exclude) { $targets[$target].Exclude = $true }

            $skip = @('STATIC','SHARED','MODULE','OBJECT','INTERFACE','EXCLUDE_FROM_ALL','IMPORTED','ALIAS')
            foreach ($tok in $decl) {
                if ($skip -contains $tok) { continue }
                Expand-AndAddToken -Target $target -Token $tok -Conditional $b.Conditional -Line $b.Line
            }
        }
        'target_sources' {
            if ($args.Count -ge 2) {
                $target = $args[0]
                $decl = $args[1..($args.Count - 1)]
                foreach ($tok in $decl) {
                    if ($tok -in @('PRIVATE','PUBLIC','INTERFACE')) { continue }
                    Expand-AndAddToken -Target $target -Token $tok -Conditional $b.Conditional -Line $b.Line
                }
            }
        }
        'set_target_properties' {
            if ($args.Count -ge 1) {
                $target = $args[0]
                if (($args -contains 'EXCLUDE_FROM_ALL') -and ($args -contains 'TRUE')) {
                    if (-not $targets.ContainsKey($target)) {
                        $targets[$target] = [pscustomobject]@{
                            Name = $target
                            Type = 'unknown'
                            Exclude = $true
                            Lines = New-Object System.Collections.Generic.List[int]
                        }
                    }
                    $targets[$target].Exclude = $true
                    $targets[$target].Lines.Add($b.Line)
                }
            }
        }
    }
}

$rows = New-Object System.Collections.Generic.List[object]
$sourceToTargets = @{}
foreach ($targetName in $targetSources.Keys) {
    $meta = if ($targets.ContainsKey($targetName)) { $targets[$targetName] } else { [pscustomobject]@{ Name=$targetName; Type='unknown'; Exclude=$false; Lines=(New-Object System.Collections.Generic.List[int]) } }
    $family = Classify-Target -Name $targetName -Exclude $meta.Exclude
    $production = ($family -eq 'shipped/product' -or $family -eq 'supporting production')
    $isTest = ($family -eq 'test')
    $isBench = ($family -eq 'benchmark')
    $isWin32IDE = ($targetName -eq 'RawrXD-Win32IDE')

    foreach ($rec in $targetSources[$targetName]) {
        $src = $rec.Path
        if (-not $sourceToTargets.ContainsKey($src)) {
            $sourceToTargets[$src] = New-Object System.Collections.Generic.HashSet[string]
        }
        [void]$sourceToTargets[$src].Add($targetName)

        $rows.Add([pscustomobject]@{
            source = $src
            target = $targetName
            target_type = $meta.Type
            exclude_from_all = ($meta.Exclude.ToString().ToLowerInvariant())
            target_family = $family
            production = ($production.ToString().ToLowerInvariant())
            win32ide = ($isWin32IDE.ToString().ToLowerInvariant())
            deep2 = (($src -match '/deep2/').ToString().ToLowerInvariant())
            test = ($isTest.ToString().ToLowerInvariant())
            benchmark = ($isBench.ToString().ToLowerInvariant())
            conditional = ($rec.Conditional.ToString().ToLowerInvariant())
            duplicate_family = ''
            stub_risk = ''
            line = $rec.Line
        })
    }
}

$rows = $rows | Sort-Object source,target -Unique

$byBase = @{}
foreach ($r in $rows) {
    $base = [System.IO.Path]::GetFileName($r.source).ToLowerInvariant()
    if (-not $byBase.ContainsKey($base)) {
        $byBase[$base] = New-Object System.Collections.Generic.HashSet[string]
    }
    [void]$byBase[$base].Add($r.source)
}

$duplicateBases = New-Object System.Collections.Generic.HashSet[string]
foreach ($base in $byBase.Keys) {
    if ($byBase[$base].Count -gt 1) {
        [void]$duplicateBases.Add($base)
    }
}

$stubPattern = '(stub|stubs|shim|shims|fallback|mock|fake|compat|missing_impl|link_stub)'
foreach ($r in $rows) {
    $base = [System.IO.Path]::GetFileName($r.source).ToLowerInvariant()
    if ($duplicateBases.Contains($base)) {
        $r.duplicate_family = $base
    }
    $r.stub_risk = (($base -match $stubPattern).ToString().ToLowerInvariant())
}

$srcRoot = Join-Path $Root 'src'
$fsSources = Get-ChildItem -Path $srcRoot -Recurse -File -Include *.c,*.cc,*.cpp,*.cxx,*.asm,*.rc |
    ForEach-Object { ($_.FullName.Substring($Root.Length + 1)) -replace '\\','/' -replace '\\','/' }

$referencedSet = New-Object System.Collections.Generic.HashSet[string]
foreach ($r in $rows) { [void]$referencedSet.Add($r.source) }

$orphans = @()
foreach ($s in $fsSources) {
    if (-not $referencedSet.Contains($s)) {
        $orphans += $s
    }
}
$orphans = $orphans | Sort-Object -Unique

$deep2Cpp = Get-ChildItem -Path (Join-Path $srcRoot 'deep2') -Recurse -File -Filter *.cpp |
    ForEach-Object { ($_.FullName.Substring($Root.Length + 1)) -replace '\\','/' -replace '\\','/' }

$deep2Rows = New-Object System.Collections.Generic.List[object]
foreach ($s in ($deep2Cpp | Sort-Object)) {
    $targetsFor = @()
    if ($sourceToTargets.ContainsKey($s)) {
        $targetsFor = @($sourceToTargets[$s]) | Sort-Object
    }
    $inCMake = ($targetsFor.Count -gt 0)
    $inWin32IDE = ($targetsFor -contains 'RawrXD-Win32IDE')
    $deep2Rows.Add([pscustomobject]@{
        source = $s
        referenced_in_root_cmake = ($inCMake.ToString().ToLowerInvariant())
        targets = ($targetsFor -join ';')
        win32ide = ($inWin32IDE.ToString().ToLowerInvariant())
        status = $(if ($inCMake) { 'built' } else { 'cmake-orphan' })
    })
}

$dupRows = New-Object System.Collections.Generic.List[object]
foreach ($base in (@($duplicateBases) | Sort-Object)) {
    $paths = @($byBase[$base]) | Sort-Object
    $targetMap = @()
    foreach ($p in $paths) {
        $ts = @()
        if ($sourceToTargets.ContainsKey($p)) {
            $ts = @($sourceToTargets[$p]) | Sort-Object
        }
        $targetMap += ($p + '=>' + ($ts -join ';'))
    }
    $dupRows.Add([pscustomobject]@{
        family = $base
        path_count = $paths.Count
        paths = ($paths -join ' | ')
        targets = ($targetMap -join ' | ')
    })
}

$targetRows = New-Object System.Collections.Generic.List[object]
foreach ($t in ($targets.Keys | Sort-Object)) {
    $m = $targets[$t]
    $fam = Classify-Target -Name $t -Exclude $m.Exclude
    $targetRows.Add([pscustomobject]@{
        target = $t
        target_type = $m.Type
        exclude_from_all = ($m.Exclude.ToString().ToLowerInvariant())
        target_family = $fam
        production = (($fam -eq 'shipped/product' -or $fam -eq 'supporting production').ToString().ToLowerInvariant())
        line = (($m.Lines | Sort-Object -Unique) -join ',')
    })
}

$matrixCsv = Join-Path $OutDir 'cmake_source_target_matrix.csv'
$matrixJson = Join-Path $OutDir 'cmake_source_target_matrix.json'
$deep2Csv = Join-Path $OutDir 'deep2_audit.csv'
$dupCsv = Join-Path $OutDir 'duplicate_implementation_families.csv'
$orphCsv = Join-Path $OutDir 'orphan_sources.csv'
$summaryMd = Join-Path $OutDir 'AUDIT_SUMMARY.md'
$targetCsv = Join-Path $OutDir 'target_inventory.csv'

$rows | Export-Csv -Path $matrixCsv -NoTypeInformation -Encoding UTF8
$rows | ConvertTo-Json -Depth 6 | Set-Content -Path $matrixJson -Encoding UTF8
$deep2Rows | Export-Csv -Path $deep2Csv -NoTypeInformation -Encoding UTF8
$dupRows | Export-Csv -Path $dupCsv -NoTypeInformation -Encoding UTF8
$targetRows | Export-Csv -Path $targetCsv -NoTypeInformation -Encoding UTF8

'"source"' | Set-Content -Path $orphCsv -Encoding UTF8
$orphans | Add-Content -Path $orphCsv -Encoding UTF8

$uniqueSources = ($rows | Select-Object -ExpandProperty source | Sort-Object -Unique).Count
$stubRiskCount = ($rows | Where-Object { $_.stub_risk -eq 'true' }).Count
$deep2Total = $deep2Rows.Count
$deep2Built = ($deep2Rows | Where-Object { $_.referenced_in_root_cmake -eq 'true' }).Count
$deep2Orphans = $deep2Total - $deep2Built

$summary = @()
$summary += '# RawrXD CMake Source-to-Target Audit'
$summary += ''
$summary += 'Scope: static parse of root CMake graph in d:/rawrxd/CMakeLists.txt.'
$summary += ''
$summary += '## Outputs'
$summary += '- cmake_source_target_matrix.csv'
$summary += '- cmake_source_target_matrix.json'
$summary += '- target_inventory.csv'
$summary += '- deep2_audit.csv'
$summary += '- duplicate_implementation_families.csv'
$summary += '- orphan_sources.csv'
$summary += ''
$summary += '## Counts'
$summary += "- add_executable declarations: $addExeCount"
$summary += "- add_library declarations: $addLibCount"
$summary += "- targets discovered: $($targets.Count)"
$summary += "- source-target edges: $($rows.Count)"
$summary += "- unique referenced sources: $uniqueSources"
$summary += "- duplicate implementation families: $($dupRows.Count)"
$summary += "- stub-risk edges (name heuristic): $stubRiskCount"
$summary += "- filesystem source files under src/: $($fsSources.Count)"
$summary += "- source files present but unreferenced in root CMake: $($orphans.Count)"
$summary += ''
$summary += '## Deep2 Slice'
$summary += "- total deep2 .cpp files scanned: $deep2Total"
$summary += "- referenced by root CMake: $deep2Built"
$summary += "- cmake-orphan deep2 files: $deep2Orphans"
$summary += ''
$summary += '## Notes'
$summary += '- Root CMake is treated as authoritative audit boundary.'
$summary += '- Conditional column is inferred from if/endif nesting in static parse.'
$summary += '- Duplicate and stub risk are heuristic and require review before deletion.'

$summary | Set-Content -Path $summaryMd -Encoding UTF8

Write-Output "Generated audit artifacts in $OutDir"
