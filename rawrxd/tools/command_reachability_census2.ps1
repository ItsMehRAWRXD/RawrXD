# ============================================================================
# tools/command_reachability_census2.ps1
# RAWRXD_COMMAND_REACHABILITY_CENSUS_002
#
# CENSUS_001 found 673 SIMPLE-NAME collisions out of 927 handler names. A
# simple-name collision is only a warning: it can be a namespace difference, an
# overload, a static helper, or a test-only copy. Only a collision where MORE
# THAN ONE definition is product-path reachable is a release blocker.
#
# This census therefore tracks, per name:
#   QUALIFIED_SYMBOL  namespace-scoped, so namespace/signature/overload
#                     differences can retire a collision before adjudication
#   LINKAGE           external / static / member / anonymous-namespace
#   per-surface       menu, accel, palette, registry, command bus,
#                     agent tool, test harness
# and only then emits a DISPOSITION.
#
# CENSUS_001's reachability pass reported NAMES_REACHABLE=0, which is a
# detector artifact, not a finding: it matched handleX( and "handleX" but not
# the function-pointer form &handleX, which is how these are actually bound.
# That pattern is matched here.
#
# Read-only. Emits a CSV and a gate summary. Edits nothing.
# ============================================================================
param(
    [string]$Root = "F:\~dev\rawrxd",
    [string]$CensusCsv = "",
    [string]$OutCsv = ""
)

$ErrorActionPreference = "Stop"

$srcRoot = Join-Path $Root "src"
if (-not (Test-Path $srcRoot)) { throw "no src under $Root" }
if ([string]::IsNullOrEmpty($CensusCsv)) { $CensusCsv = Join-Path $Root "audit\command_authority_census.csv" }
if (-not (Test-Path $CensusCsv)) { throw "run command_authority_census.ps1 first" }
if ([string]::IsNullOrEmpty($OutCsv)) { $OutCsv = Join-Path $Root "audit\command_reachability_census2.csv" }
New-Item -ItemType Directory -Force -Path (Split-Path $OutCsv) | Out-Null

$defRe = '^\s*((?:static|extern|inline|virtual|static\s+inline)\s+)*CommandResult\s+(\w+)\s*\(([^)]*)\)'

# ---------------------------------------------------------------------------
# Pass 1 -- definitions with namespace, signature and linkage.
# ---------------------------------------------------------------------------
$files = Get-ChildItem -Path $srcRoot -Recurse -Include *.cpp -ErrorAction SilentlyContinue |
         Where-Object { $_.FullName -notmatch '\\build\\' }

$defs = @{}

foreach ($f in $files) {
    $lines = [System.IO.File]::ReadAllLines($f.FullName)
    $nsStack = New-Object System.Collections.Generic.List[string]
    $anonDepth = -1
    $depth = 0
    $rel = $f.FullName.Substring($Root.Length + 1).Replace('\', '/')
    $isTest = ($rel -match 'test|Test|_test|smoke|harness|bench|demo')

    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]

        # Track namespace nesting so a collision can be retired as
        # NAMESPACE_NOT_COLLISION.
        $nsMatches = [regex]::Matches($line, '^\s*namespace\s+(\w+)\s*\{')
        foreach ($m in $nsMatches) { $nsStack.Add($m.Groups[1].Value) }
        if ($line -match '^\s*namespace\s*\{') { $nsStack.Add('') }
        if ($line -match '^\s*\}\s*//\s*namespace') {
            if ($nsStack.Count -gt 0) { $nsStack.RemoveAt($nsStack.Count - 1) }
        }

        if ($line -notmatch $defRe) { continue }
        $specs  = $Matches[1]
        $name   = $Matches[2]
        $sig    = $Matches[3]

        $ns = ($nsStack -join '::')
        $qual = if ($ns) { "$ns::$name" } else { "::$name" }
        $linkage = 'external'
        if ($specs -match 'static') { $linkage = 'static' }

        # Body capture for fiction / fake-ok detection.
        $start = $i
        $d = 0
        $open = $false
        $body = New-Object System.Collections.Generic.List[string]
        for ($j = $i; $j -lt $lines.Length; $j++) {
            $body.Add($lines[$j])
            foreach ($ch in $lines[$j].ToCharArray()) {
                if ($ch -eq '{') { $d++; $open = $true } elseif ($ch -eq '}') { $d-- }
            }
            $i = $j
            if ($open -and $d -le 0) { break }
        }
        $bt = $body -join "`n"

        $key = $name
        if (-not $defs.ContainsKey($key)) {
            $defs[$key] = New-Object System.Collections.Generic.List[object]
        }
        $defs[$key].Add([pscustomobject]@{
            Name       = $name
            Qual       = $qual
            Ns         = $ns
            Sig        = $sig
            Linkage    = $linkage
            File       = $rel
            Line       = $start + 1
            IsTest     = $isTest
            IsFiction  = ($bt -match 'FEATURE_FICTION=1')
            IsFakeOk   = (($bt -notmatch 'FEATURE_FICTION=1') -and ($bt -match 'CommandResult::ok\s*\(\s*\)'))
        })
    }
}

# ---------------------------------------------------------------------------
# Pass 2 -- per-surface reachability over the whole of src/, not just win32app.
# Surfaces are detected by construct, then the name is matched in the binding
# forms actually used in this tree:
#     &handleX          function pointer / registry entry   (CENSUS_001 missed this)
#     handleX(          direct call
#     "handleX"         string-keyed table
#     IDM_ / CMD_       numeric menu id paired in the same file
# ---------------------------------------------------------------------------
$surfaceDefs = @(
    @{ Name = 'MENU';         Re = 'AppendMenu|CreatePopupMenu|SetMenuItemInfo|WM_COMMAND' },
    @{ Name = 'ACCELERATOR'; Re = 'TranslateAccelerator|ACCEL|VK_F12|Ctrl\+P|F12' },
    @{ Name = 'PALETTE';      Re = 'CommandPalette|command_palette|QuickOpen|RegisterCommand|BindCommand|AddCommand|CommandSpec|CommandDescriptor|CommandHandler' },
    @{ Name = 'REGISTRY';     Re = 'RegisterCommand|registry\.Register|ToolRegistry::Instance\(\)\.Register' },
    @{ Name = 'COMMAND_BUS';  Re = 'commandBus|CommandBus|DispatchCommand|dispatch_table|g_command' },
    @{ Name = 'AGENT_TOOL';   Re = 'registerTool|RegisterTool|ToolDef\{' },
    @{ Name = 'TEST_HARNESS'; Re = 'smoke|harness|gate_verifier|_test' }
)

$hit = @{}   # name -> hashtable surface -> [locations]

foreach ($f in $files) {
    $text = [System.IO.File]::ReadAllText($f.FullName)
    $rel  = $f.FullName.Substring($Root.Length + 1).Replace('\', '/')
    $isTest = ($rel -match 'test|Test|_test|smoke|harness|bench|demo')

    # Which surfaces does this file actually implement?
    $active = New-Object System.Collections.Generic.List[string]
    foreach ($s in $surfaceDefs) {
        $ok = $false
        if ($s.Name -eq 'TEST_HARNESS') { $ok = $isTest }
        elseif ($text -match $s.Re)    { $ok = $true }
        if ($ok) { $active.Add($s.Name) }
    }
    if ($active.Count -eq 0) { continue }

    foreach ($name in $defs.Keys) {
        $re = [regex]::Escape($name)
        $bound = ($text -match ("&"       + $re + "\b"))   -or
                 ($text -match ("\b"      + $re + "\s*\(")) -or
                 ($text -match ("[""']"   + $re + "[""']"))
        if (-not $bound) { continue }
        if (-not $hit.ContainsKey($name)) {
            $hit[$name] = @{}
        }
        foreach ($a in $active) {
            if (-not $hit[$name].ContainsKey($a)) { $hit[$name][$a] = New-Object System.Collections.Generic.List[string] }
            $hit[$name][$a].Add($rel)
        }
    }
}

# ---------------------------------------------------------------------------
# Pass 3 -- adjudication.
# ---------------------------------------------------------------------------
$rows = New-Object System.Collections.Generic.List[object]
foreach ($name in ($defs.Keys | Sort-Object)) {
    $d = $defs[$name]
    $total = $d.Count

    $quals = ($d | ForEach-Object { $_.Qual } | Sort-Object -Unique).Count
    $sigs  = ($d | ForEach-Object { $_.Sig } | Sort-Object -Unique).Count
    $nsSet = ($d | ForEach-Object { $_.Ns } | Sort-Object -Unique).Count

    $h = @{}
    if ($hit.ContainsKey($name)) { $h = $hit[$name] }

    $menu    = $h.ContainsKey('MENU')
    $accel   = $h.ContainsKey('ACCELERATOR')
    $palette = $h.ContainsKey('PALETTE')
    $regis   = $h.ContainsKey('REGISTRY')
    $bus     = $h.ContainsKey('COMMAND_BUS')
    $agent   = $h.ContainsKey('AGENT_TOOL')
    $testOnl = $h.ContainsKey('TEST_HARNESS')
    $anyBound = $menu -or $accel -or $palette -or $regis -or $bus -or $agent

    # Reachable = bound on a product surface in a file that is NOT test-only.
    $prodReachable = $anyBound -and -not ($testOnl -and -not ($menu -or $accel -or $palette -or $regis -or $bus -or $agent))

    $reachedLocs = New-Object System.Collections.Generic.List[string]
    if ($prodReachable) {
        foreach ($a in @('MENU','ACCELERATOR','PALETTE','REGISTRY','COMMAND_BUS','AGENT_TOOL')) {
            if ($h.ContainsKey($a)) { foreach ($l in $h[$a]) { $reachedLocs.Add($l) } }
        }
    }
    $reachedDefs = $reachedLocs | Sort-Object -Unique
    $prodReachableDefs = $reachedDefs.Count

    $fiction = ($d | Where-Object { $_.IsFiction }).Count
    $fakeOk  = ($d | Where-Object { $_.IsFakeOk }).Count
    $testDefs = ($d | Where-Object { $_.IsTest }).Count

    # Disposition precedence: the winner is what the product can dispatch.
    if ($total -ge 2 -and $quals -ge 2)                    { $disp = 'NAMESPACE_NOT_COLLISION' }
    elseif ($total -ge 2 -and $sigs -ge 2)                  { $disp = 'SIGNATURE_OVERLOAD_NOT_COLLISION' }
    elseif ($prodReachableDefs -ge 2)                      { $disp = 'PRODUCT_REACHABLE_COLLISION' }
    elseif ($prodReachableDefs -eq 1 -and $total -ge 2)    { $disp = 'REAL_REACHABLE_AUTHORITY' }
    elseif ($testOnl -and $total -ge 2)                     { $disp = 'TEST_ONLY_DUPLICATE' }
    elseif ($anyBound -and $total -ge 2)                    { $disp = 'UNRESOLVED_DYNAMIC_DISPATCH' }
    elseif ($total -ge 2)                                  { $disp = 'DEAD_CANDIDATE' }
    else                                                  { $disp = 'REAL_REACHABLE_AUTHORITY' }

    $rows.Add([pscustomobject]@{
        NAME                      = $name
        TOTAL_DEFINITIONS         = $total
        QUALIFIED_DEFINITIONS     = $quals
        DISTINCT_SIGNATURES       = $sigs
        DISTINCT_NAMESPACES       = $nsSet
        MENU_BOUND                = [int]$menu
        ACCELERATOR_BOUND         = [int]$accel
        PALETTE_BOUND             = [int]$palette
        REGISTRY_BOUND            = [int]$regis
        COMMAND_BUS_BOUND         = [int]$bus
        AGENT_TOOL_BOUND          = [int]$agent
        TEST_ONLY_BOUND           = [int]$testOnl
        PRODUCT_REACHABLE_DEFS    = $prodReachableDefs
        FICTION_DEFS              = $fiction
        FAKE_OK_DEFS              = $fakeOk
        TEST_ONLY_DEFS            = $testDefs
        UNREACHABLE_DEFS          = ($total - $prodReachableDefs)
        DISPOSITION               = $disp
        LOCATIONS                 = (($d | ForEach-Object { "$($_.Qual)@$($_.File):$($_.Line)" }) -join ';')
    })
}

$rows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

$coll  = ($rows | Where-Object { $_.DISPOSITION -eq 'PRODUCT_REACHABLE_COLLISION' }).Count
$dyn   = ($rows | Where-Object { $_.DISPOSITION -eq 'UNRESOLVED_DYNAMIC_DISPATCH' }).Count
$dead  = ($rows | Where-Object { $_.DISPOSITION -eq 'DEAD_CANDIDATE' }).Count
$nsDif = ($rows | Where-Object { $_.DISPOSITION -eq 'NAMESPACE_NOT_COLLISION' }).Count
$sigDif= ($rows | Where-Object { $_.DISPOSITION -eq 'SIGNATURE_OVERLOAD_NOT_COLLISION' }).Count
$testD = ($rows | Where-Object { $_.DISPOSITION -eq 'TEST_ONLY_DUPLICATE' }).Count
$real  = ($rows | Where-Object { $_.DISPOSITION -eq 'REAL_REACHABLE_AUTHORITY' }).Count

$fakeOkReach = ($rows | Where-Object { [int]$_.FAKE_OK_DEFS -gt 0 -and [int]$_.PRODUCT_REACHABLE_DEFS -gt 0 }).Count
$ficReach    = ($rows | Where-Object { [int]$_.FICTION_DEFS -gt 0 -and [int]$_.PRODUCT_REACHABLE_DEFS -gt 0 }).Count

Write-Output "RAWRXD_COMMAND_REACHABILITY_CENSUS_002"
Write-Output "SOURCE_FILES_SCANNED=$($files.Count)"
Write-Output "NAMES_TOTAL=$($rows.Count)"
Write-Output ""
Write-Output "DISPOSITION_REAL_REACHABLE_AUTHORITY=$real"
Write-Output "DISPOSITION_PRODUCT_REACHABLE_COLLISION=$coll"
Write-Output "DISPOSITION_UNRESOLVED_DYNAMIC_DISPATCH=$dyn"
Write-Output "DISPOSITION_DEAD_CANDIDATE=$dead"
Write-Output "DISPOSITION_TEST_ONLY_DUPLICATE=$testD"
Write-Output "DISPOSITION_NAMESPACE_NOT_COLLISION=$nsDif"
Write-Output "DISPOSITION_SIGNATURE_OVERLOAD_NOT_COLLISION=$sigDif"
Write-Output ""
Write-Output "FAKE_OK_REACHABLE=$fakeOkReach"
Write-Output "FEATURE_FICTION_REACHABLE=$ficReach"
Write-Output "MULTIPLE_PRODUCT_AUTHORITIES_PER_COMMAND=$coll"
Write-Output "CSV=$OutCsv"
Write-Output ""
Write-Output "GATE_PRODUCT_REACHABLE_COLLISION=$coll"
Write-Output "GATE_UNRESOLVED_DYNAMIC_DISPATCH=$dyn"
Write-Output "GATE_FAKE_OK_REACHABLE=$fakeOkReach"
Write-Output "GATE_FEATURE_FICTION_REACHABLE=$ficReach"
$v = 'FAIL'
if ($coll -eq 0 -and $dyn -eq 0 -and $fakeOkReach -eq 0 -and $ficReach -eq 0) { $v = 'PASS' }
Write-Output "VERDICT=$v"
