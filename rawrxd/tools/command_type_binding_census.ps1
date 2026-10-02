# ============================================================================
# tools/command_type_binding_census.ps1
# RAWRXD_COMMAND_TYPE_BINDING_CENSUS_005
#
# The decisive question is NOT "does another handleFoo string appear". It is:
# does a CommandResult-PRODUCING CALLABLE become reachable from a product
# entrypoint. So this census searches BY TYPE FLOW, not by name:
#
#   CommandResult (*fn)(...)                    raw function pointer
#   std::function<CommandResult(...)>           lambda-wrapped callable
#   using/typedef ... CommandResult             alias hiding the signature
#   map/unordered_map/vector/array/pair ... CommandResult   container of them
#   Register/Bind/Add/Install/Dispatch(... CommandResult ...)  registration
#   CommandSpec/CommandDescriptor/CommandHandler           generated table
#
# Name-based reference counting was already tried three times and produced
# three invalid results (false negative, file-level false positives, and
# punctuation-window false positives). Those tools remain for the duplicate
# census; this one is deliberately orthogonal.
#
# Read-only. Emits a CSV and a gate summary.
# ============================================================================
param(
    [string]$Root = "F:\~dev\rawrxd",
    [string]$OutCsv = ""
)

$ErrorActionPreference = "Stop"

$scanRoots = @()
foreach ($r in @('src','include','tools','src/win32app')) {
    $p = Join-Path $Root $r
    if (Test-Path $p) { $scanRoots += $p }
}
if ([string]::IsNullOrEmpty($OutCsv)) { $OutCsv = Join-Path $Root "audit\command_type_binding_census.csv" }
New-Item -ItemType Directory -Force -Path (Split-Path $OutCsv) | Out-Null

# Each pattern is a way a CommandResult callable can be stored or registered.
$typeFlows = @(
    @{ Id = 'FUNC_PTR';        Re = 'CommandResult\s*\(\s*\*' }
    @{ Id = 'STDFUNCTION';     Re = 'std::function\s*<\s*CommandResult' }
    @{ Id = 'ALIAS_USING';     Re = '^\s*(using|typedef)\s+\w+\s*=.*CommandResult' }
    @{ Id = 'CONTAINER';       Re = '\b(map|unordered_map|vector|array|pair|tuple|deque|list)\s*<[^;]*CommandResult' }
    @{ Id = 'REGISTRATION';    Re = '\b(Register|register|Bind|Add|Install|Dispatch|Route|Execute)\w*\s*\([^;)]*CommandResult' }
    @{ Id = 'COMMAND_TABLE';   Re = 'Command(Spec|Descriptor|Handler|Entry|Record)\b' }
    @{ Id = 'XMACRO';          Re = '^\s*#\s*define\s+\w*(COMMAND|HANDLER|TOOL)\w*' }
    @{ Id = 'SIGNATURE_ARG';   Re = '\(\s*const\s+CommandResult\s*&|\*\s*CommandResult\s*\)' }
)

# Product paths, per your precedence. Only PRODUCT promotes to reachable.
$productDirs = @('src\win32app','src\deep2','src\core','src\agentic','src\security')

$rows = New-Object System.Collections.Generic.List[object]
$hits = @{}
foreach ($t in $typeFlows) { $hits[$t.Id] = New-Object System.Collections.Generic.List[string] }

foreach ($r in $scanRoots) {
    foreach ($f in (Get-ChildItem -Path $r -Recurse -Include *.cpp,*.h,*.hpp -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -notmatch '\\build\\|\\cmlink\\|\\certbuild\\' })) {
        $rel = $f.FullName.Substring($Root.Length + 1).Replace('\', '/')
        # Both sides MUST use the same separator. With $pd left as 'src\core'
        # and $rel using '/', the -like never matched and PRODUCT_HITS was
        # structurally zero for every file -- a detector bug that reported PASS.
        $isProduct = $false
        foreach ($pd in $productDirs) {
            $norm = $pd.Replace('\', '/')
            if ($rel.StartsWith($norm + '/')) { $isProduct = $true; break }
        }
        $lines = [System.IO.File]::ReadAllLines($f.FullName)
        for ($i = 0; $i -lt $lines.Length; $i++) {
            foreach ($t in $typeFlows) {
                if ($lines[$i] -match $t.Re) {
                    $hits[$t.Id].Add(("{0}|{1}:{2}|{3}" -f $(if($isProduct){'PRODUCT'}else{'OTHER'}), $rel, ($i+1), $t.Id))
                }
            }
        }
    }
}

foreach ($t in $typeFlows) {
    $h = $hits[$t.Id]
    $prod = @($h | Where-Object { $_ -like 'PRODUCT|*' })
    $rows.Add([pscustomobject]@{
        FLOW               = $t.Id
        PATTERN            = $t.Re
        TOTAL_HITS         = $h.Count
        PRODUCT_HITS      = $prod.Count
        SAMPLE_PRODUCT    = $(if ($prod.Count) { ($prod | Select-Object -First 3) -join ' ; ' } else { '' })
        SAMPLE_NONPRODUCT = $(if ($h.Count -gt $prod.Count) { ((@($h | Where-Object { $_ -notlike 'PRODUCT|*' })) | Select-Object -First 2) -join ' ; ' } else { '' })
    })
}

$rows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

$prodTotal = ($rows | Measure-Object -Property PRODUCT_HITS -Sum).Sum

Write-Output "RAWRXD_COMMAND_TYPE_BINDING_CENSUS_005"
Write-Output "SEARCH_ROOTS=src,include,tools"
foreach ($r in $rows) { Write-Output ("FLOW_{0}={1}" -f $r.FLOW, $r.TOTAL_HITS) }
Write-Output ""
foreach ($r in $rows) { if ($r.PRODUCT_HITS -gt 0) { Write-Output ("PRODUCT_FLOW_{0}={1}" -f $r.FLOW, $r.PRODUCT_HITS) } }
Write-Output ""
Write-Output "PRODUCT_TYPE_BINDINGS_TOTAL=$prodTotal"
Write-Output "CSV=$OutCsv"
Write-Output ""
if ($prodTotal -eq 0) {
    Write-Output "COMMAND_RESULT_CALLABLE_STORED_IN_PRODUCT=0"
    Write-Output "COMMAND_HANDLE_LAYER=ORPHANED_PARALLEL_PROVEN"
    Write-Output "DUPLICATE_COMMAND_AUTHORITY_P0=RETRACTED"
    Write-Output "DUPLICATE_HANDLER_SOURCE_DEBT=PROVEN"
    Write-Output "VERDICT=PASS"
} else {
    Write-Output "COMMAND_HANDLE_LAYER=PRODUCT_CONSUMER_EXISTS"
    Write-Output "DUPLICATE_COMMAND_AUTHORITY_P0=STILL_POSSIBLE"
    Write-Output "VERDICT=REVIEW_REQUIRED"
}