$ErrorActionPreference = 'Stop'

$Root = 'd:\rawrxd'
$AuditDir = Join-Path $Root 'audit'

$matrixCsv = Join-Path $AuditDir 'cmake_source_target_matrix.csv'
$deep2Csv = Join-Path $AuditDir 'deep2_audit.csv'
$dupCsv = Join-Path $AuditDir 'duplicate_implementation_families.csv'
$orphCsv = Join-Path $AuditDir 'orphan_sources.csv'
$targetCsv = Join-Path $AuditDir 'target_inventory.csv'

if (-not (Test-Path $matrixCsv)) { throw "Missing $matrixCsv" }
if (-not (Test-Path $deep2Csv)) { throw "Missing $deep2Csv" }
if (-not (Test-Path $dupCsv)) { throw "Missing $dupCsv" }
if (-not (Test-Path $orphCsv)) { throw "Missing $orphCsv" }
if (-not (Test-Path $targetCsv)) { throw "Missing $targetCsv" }

$matrix = Import-Csv -Path $matrixCsv
$deep2 = Import-Csv -Path $deep2Csv
$dups = Import-Csv -Path $dupCsv
$orphans = Import-Csv -Path $orphCsv
$targets = Import-Csv -Path $targetCsv

function Normalize([string]$p) {
    if (-not $p) { return '' }
    return ($p -replace '\\','/').Trim()
}

function First-NonEmpty([string[]]$vals) {
    foreach ($v in $vals) {
        if ($v -and $v.Trim().Length -gt 0) { return $v }
    }
    return ''
}

# Build map: source -> targets from matrix
$srcToTargets = @{}
foreach ($row in $matrix) {
    $src = Normalize $row.source
    if (-not $srcToTargets.ContainsKey($src)) {
        $srcToTargets[$src] = New-Object System.Collections.Generic.HashSet[string]
    }
    [void]$srcToTargets[$src].Add($row.target)
}

# Collect non-root CMake references to source files (nested-build detection)
$allCmake = Get-ChildItem -Path $Root -Recurse -File -Filter CMakeLists.txt |
    Where-Object { $_.FullName -ne (Join-Path $Root 'CMakeLists.txt') }

$nestedRefs = New-Object System.Collections.Generic.HashSet[string]
$nestedByBase = @{}
foreach ($cm in $allCmake) {
    $text = Get-Content -Path $cm.FullName -Raw -Encoding UTF8
    $matches = [regex]::Matches($text, 'src[\\/][A-Za-z0-9_./\\-]+\.(c|cc|cpp|cxx|asm|rc|h|hpp)', 'IgnoreCase')
    foreach ($m in $matches) {
        $p = Normalize $m.Value
        [void]$nestedRefs.Add($p)
        $base = [System.IO.Path]::GetFileName($p).ToLowerInvariant()
        if (-not $nestedByBase.ContainsKey($base)) {
            $nestedByBase[$base] = New-Object System.Collections.Generic.HashSet[string]
        }
        [void]$nestedByBase[$base].Add($cm.FullName.Substring($Root.Length + 1).Replace('\\','/'))
    }
}

# Stage 2 orphan decisions
$orphanDecisionRows = New-Object System.Collections.Generic.List[object]
foreach ($row in $orphans) {
    $src = Normalize $row.source
    if (-not $src) { continue }
    $base = [System.IO.Path]::GetFileName($src)
    $l = $src.ToLowerInvariant()

    $bucket = 'REQUIRES_INVESTIGATION'
    $decision = 'ORPHAN'
    $reason = ''

    $inNestedByPath = $nestedRefs.Contains($src)
    $inNestedByBase = $nestedByBase.ContainsKey($base.ToLowerInvariant())

    if ($l -match 'generated|_generated|autogen|fileregistry_generated|sourcefileregistry|\.g\.cpp') {
        $bucket = 'KEEP'
        $decision = 'generated/runtime'
        $reason = 'Generated or registry-style source file.'
    } elseif ($l -match '\.archived_dead_code|/archive|/archived|/history|/reconstructed|/legacy') {
        $bucket = 'DEPRECATE'
        $decision = 'obsolete-likely'
        $reason = 'Archived/legacy style location.'
    } elseif ($l -match 'test|tests|bench|benchmark|smoke|validation|cert|demo|example|experimental|prototype|stress') {
        $bucket = 'AUXILIARY'
        $decision = 'test/bench/validation'
        $reason = 'Naming/location indicates auxiliary usage.'
    } elseif ($inNestedByPath -or $inNestedByBase) {
        $bucket = 'KEEP'
        $decision = 'nested-build'
        $reason = 'Referenced by non-root CMakeLists.'
    } elseif ($l -match '^src/deep2/') {
        $bucket = 'PROMOTE'
        $decision = 'deep2-unreferenced'
        $reason = 'Deep2 implementation outside root graph; requires explicit product decision.'
    } elseif ($l -match 'shim|stubs?|fallback|compat|missing_impl|mock|fake') {
        $bucket = 'AUXILIARY'
        $decision = 'compat/shim'
        $reason = 'Compatibility/stub pattern in filename.'
    }

    $nestedRefEvidence = ''
    if ($inNestedByBase) {
        $nestedRefEvidence = ((@($nestedByBase[$base.ToLowerInvariant()]) | Sort-Object) -join ';')
    }

    $orphanDecisionRows.Add([pscustomobject]@{
        source = $src
        bucket = $bucket
        decision = $decision
        nested_build_ref = (($inNestedByPath -or $inNestedByBase).ToString().ToLowerInvariant())
        reason = $reason
        nested_cmake_evidence = $nestedRefEvidence
    })
}

# Deep2 Stage-2 decisions (more specific)
$deep2DecisionRows = New-Object System.Collections.Generic.List[object]
foreach ($r in $deep2) {
    $src = Normalize $r.source
    $base = [System.IO.Path]::GetFileName($src)
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($src)
    $lower = $src.ToLowerInvariant()
    $targetsList = @()
    if ($r.targets) {
        $targetsList = ($r.targets -split ';') | Where-Object { $_ -and $_.Trim().Length -gt 0 }
    }

    $isRootBuilt = ($r.referenced_in_root_cmake -eq 'true')
    $inWin32IDE = ($r.win32ide -eq 'true')

    $nested = $nestedRefs.Contains($src) -or ($nestedByBase.ContainsKey($base.ToLowerInvariant()))

    # Approximate include/call relationship signal inside src tree.
    $refCount = 0
    $pattern = [regex]::Escape($stem)
    $hits = Select-String -Path (Join-Path $Root 'src\**\*.*') -Pattern $pattern -CaseSensitive:$false -ErrorAction SilentlyContinue
    foreach ($h in $hits) {
        $p = Normalize ($h.Path.Substring($Root.Length + 1))
        if ($p -ne $src) { $refCount++ }
    }

    $bucket = 'requires-investigation'
    $decision = 'unresolved'
    $why = ''

    if ($isRootBuilt) {
        if ($inWin32IDE -or ($targetsList -contains 'RawrEngine')) {
            $bucket = 'retain-production'
            $decision = 'confirmed'
            $why = 'Compiled in root graph and included in product/supporting targets.'
        } elseif (($targetsList | Where-Object { $_ -match 'Bench|Benchmark|Test|Smoke|Validation|Cert' }).Count -gt 0) {
            $bucket = 'retain-auxiliary'
            $decision = 'bench/test'
            $why = 'Compiled in root graph but auxiliary family targets.'
        } else {
            $bucket = 'retain-supporting'
            $decision = 'supporting-production'
            $why = 'Compiled by non-benchmark/non-test target in root graph.'
        }
    } else {
        if ($lower -match 'apiserver|inferenceendpoint|inferencegateway|localserver|integration|discovery|http_gateway|server_main') {
            $bucket = 'promote-candidate'
            $decision = 'unfinished-product-surface'
            $why = 'API/server/integration class appears outside root graph.'
        } elseif ($lower -match 'bench|benchmark|smoketest|smoke|test|validation|cert|phase|gateway_runtime_certification|productiontest') {
            $bucket = 'retain-auxiliary'
            $decision = 'auxiliary-not-root'
            $why = 'Bench/test/cert style deep2 source not in root graph.'
        } elseif ($nested) {
            $bucket = 'keep-nested-build'
            $decision = 'nested-build-reference'
            $why = 'Referenced in non-root CMake scope.'
        } elseif ($refCount -gt 0) {
            $bucket = 'promote-candidate'
            $decision = 'referenced-by-code-not-targeted'
            $why = 'Has references from source files but no root CMake target wiring.'
        } else {
            $bucket = 'deprecate-candidate'
            $decision = 'isolated-orphan'
            $why = 'No root target and no observed cross-source references.'
        }
    }

    $deep2DecisionRows.Add([pscustomobject]@{
        source = $src
        root_cmake_referenced = ($isRootBuilt.ToString().ToLowerInvariant())
        targets = ($targetsList -join ';')
        bucket = $bucket
        decision = $decision
        win32ide = ($inWin32IDE.ToString().ToLowerInvariant())
        reference_hits_excluding_self = $refCount
        nested_build_ref = ($nested.ToString().ToLowerInvariant())
        reason = $why
    })
}

# Duplicate family decisions (root-matrix families + explicit ai_model family probe)
$dupDecisionRows = New-Object System.Collections.Generic.List[object]
foreach ($d in $dups) {
    $family = $d.family
    $paths = @()
    if ($d.paths) {
        $paths = ($d.paths -split ' \| ') | ForEach-Object { Normalize $_ }
    }

    $canonical = ''
    if (($paths | Where-Object { $_ -match '^src/inference/' }).Count -gt 0) {
        $canonical = First-NonEmpty (($paths | Where-Object { $_ -match '^src/inference/' }))
    } elseif (($paths | Where-Object { $_ -match '^src/deep2/' }).Count -gt 0) {
        $canonical = First-NonEmpty (($paths | Where-Object { $_ -match '^src/deep2/' }))
    } elseif (($paths | Where-Object { $_ -match '^src/win32app/' }).Count -gt 0) {
        $canonical = First-NonEmpty (($paths | Where-Object { $_ -match '^src/win32app/' }))
    } else {
        $canonical = First-NonEmpty $paths
    }

    $alternates = ($paths | Where-Object { $_ -ne $canonical }) -join ';'

    $status = 'unresolved'
    if ($paths.Count -eq 2 -and $family -match 'deep2bridge|deep2engine') {
        $status = 'parallel-impl-in-use'
    }

    $dupDecisionRows.Add([pscustomobject]@{
        family = $family
        canonical_candidate = $canonical
        alternates = $alternates
        status = $status
        notes = 'Requires symbol/API ownership review before merge.'
    })
}

# Explicit ai_model_caller_real family check (not captured by basename-only matrix duplicates)
$aiFamilyFiles = Get-ChildItem -Path (Join-Path $Root 'src') -Recurse -File -Filter 'ai_model_caller_real.cpp' |
    ForEach-Object { Normalize ($_.FullName.Substring($Root.Length + 1)) }

if ($aiFamilyFiles.Count -gt 0) {
    $canonicalAi = First-NonEmpty (($aiFamilyFiles | Where-Object { $_ -eq 'src/inference/ai_model_caller_real.cpp' }))
    if (-not $canonicalAi) { $canonicalAi = First-NonEmpty $aiFamilyFiles }
    $altAi = ($aiFamilyFiles | Where-Object { $_ -ne $canonicalAi }) -join ';'

    $dupDecisionRows.Add([pscustomobject]@{
        family = 'ai_model_caller_real.cpp'
        canonical_candidate = $canonicalAi
        alternates = $altAi
        status = 'unresolved'
        notes = 'Parallel copies detected in repo; root CMake wiring favors src/inference variant.'
    })
}

# Persist Stage-2 artifacts
$orphanOut = Join-Path $AuditDir 'orphan_stage2_decisions.csv'
$deep2Out = Join-Path $AuditDir 'deep2_stage2_decisions.csv'
$dupOut = Join-Path $AuditDir 'duplicate_stage2_decisions.csv'
$stage2Md = Join-Path $AuditDir 'AUDIT_STAGE_2.md'

$orphanDecisionRows | Export-Csv -Path $orphanOut -NoTypeInformation -Encoding UTF8
$deep2DecisionRows | Export-Csv -Path $deep2Out -NoTypeInformation -Encoding UTF8
$dupDecisionRows | Export-Csv -Path $dupOut -NoTypeInformation -Encoding UTF8

# Summary stats for report
$prodTargets = $targets | Where-Object { $_.production -eq 'true' }
$questionableTargets = $targets | Where-Object { $_.target_family -eq 'excluded/experimental' }

$deep2Promote = ($deep2DecisionRows | Where-Object { $_.bucket -eq 'promote-candidate' }).Count
$deep2Aux = ($deep2DecisionRows | Where-Object { $_.bucket -eq 'retain-auxiliary' }).Count
$deep2Dep = ($deep2DecisionRows | Where-Object { $_.bucket -eq 'deprecate-candidate' }).Count
$deep2Prod = ($deep2DecisionRows | Where-Object { $_.bucket -eq 'retain-production' -or $_.bucket -eq 'retain-supporting' }).Count

$orphanKeep = ($orphanDecisionRows | Where-Object { $_.bucket -eq 'KEEP' }).Count
$orphanAux = ($orphanDecisionRows | Where-Object { $_.bucket -eq 'AUXILIARY' }).Count
$orphanPromote = ($orphanDecisionRows | Where-Object { $_.bucket -eq 'PROMOTE' }).Count
$orphanMerge = ($orphanDecisionRows | Where-Object { $_.bucket -eq 'MERGE' }).Count
$orphanDep = ($orphanDecisionRows | Where-Object { $_.bucket -eq 'DEPRECATE' }).Count
$orphanInvestigate = ($orphanDecisionRows | Where-Object { $_.bucket -eq 'REQUIRES_INVESTIGATION' }).Count

$summary = @()
$summary += '# Stage-2 Product Decision Report'
$summary += ''
$summary += 'Baseline: root CMake declared graph from audit Stage-1 artifacts.'
$summary += ''
$summary += '## Production'
$summary += "- confirmed production/supporting targets: $($prodTargets.Count)"
$summary += "- questionable excluded/experimental targets: $($questionableTargets.Count)"
$summary += "- root graph remains static-declared, not compiler-confirmed for all option sets"
$summary += ''
$summary += '## Deep2'
$summary += "- retain production/supporting: $deep2Prod"
$summary += "- promote candidates: $deep2Promote"
$summary += "- retain auxiliary: $deep2Aux"
$summary += "- deprecate candidates: $deep2Dep"
$summary += '- detailed file decisions: deep2_stage2_decisions.csv'
$summary += ''
$summary += '## Duplicates'
$summary += "- duplicate families reviewed: $($dupDecisionRows.Count)"
$summary += '- canonical candidates are provisional pending symbol ownership and runtime parity checks'
$summary += '- detailed decisions: duplicate_stage2_decisions.csv'
$summary += ''
$summary += '## Orphans'
$summary += "- KEEP: $orphanKeep"
$summary += "- AUXILIARY: $orphanAux"
$summary += "- PROMOTE: $orphanPromote"
$summary += "- MERGE: $orphanMerge"
$summary += "- DEPRECATE: $orphanDep"
$summary += "- REQUIRES_INVESTIGATION: $orphanInvestigate"
$summary += '- detailed decisions: orphan_stage2_decisions.csv'
$summary += ''
$summary += '## Decision Notes'
$summary += '- Classifications combine path semantics, non-root CMake references, root target wiring, and basic code-reference signals.'
$summary += '- No deletion is performed; this report is a triage/roadmap artifact.'
$summary += '- Deep2 API/server files are treated as promote candidates or auxiliary depending on naming and reference signals.'

$summary | Set-Content -Path $stage2Md -Encoding UTF8

Write-Output "Generated Stage-2 artifacts in $AuditDir"
