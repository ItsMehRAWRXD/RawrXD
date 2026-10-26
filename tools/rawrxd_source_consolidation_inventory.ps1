[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ProductRoot,
    [Parameter(Mandatory=$true)][string]$DevelopmentRoot,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string[]]$RelativeRoots = @()
)
$ErrorActionPreference = 'Stop'

function Get-Inventory([string]$root) {
    $excluded = '\\.git(\\|$)|\\build[^\\]*(\\|$)|\\out(\\|$)|\\bin(\\|$)|\\obj(\\|$)|\\node_modules(\\|$)|\\__pycache__(\\|$)'
    $rootFull = [IO.Path]::GetFullPath($root).TrimEnd('\\')
    $scanRoots = if ($RelativeRoots.Count) {
        @($RelativeRoots | ForEach-Object { Join-Path $rootFull $_ } | Where-Object { Test-Path -LiteralPath $_ })
    } else { @($rootFull) }
    Get-ChildItem -LiteralPath $scanRoots -Recurse -File -Force |
        Where-Object { $_.FullName -notmatch $excluded -and $_.Extension -in @('.cpp','.c','.h','.hpp','.hh','.inl','.asm','.comp','.cmake','.ps1','.bat','.md','.txt','.json','.yml','.yaml') } |
        ForEach-Object {
            $relative = $_.FullName.Substring($rootFull.Length).TrimStart([char[]]"\\/") -replace '\\','/'
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            [pscustomobject]@{ path=$relative; bytes=$_.Length; sha256=$hash }
        }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$product = @(Get-Inventory $ProductRoot)
$development = @(Get-Inventory $DevelopmentRoot)
$pmap = @{}; $dmap = @{}
foreach ($x in $product) { $pmap[$x.path] = $x }
foreach ($x in $development) { $dmap[$x.path] = $x }
$paths = @($pmap.Keys + $dmap.Keys | Sort-Object -Unique)
$diff = foreach ($path in $paths) {
    $p = $pmap[$path]; $d = $dmap[$path]
    if (!$p) { $kind='development_only' }
    elseif (!$d) { $kind='product_only' }
    elseif ($p.sha256 -ne $d.sha256) { $kind='content_diff' }
    else { $kind='identical' }
    [pscustomobject]@{ path=$path; kind=$kind; product=$p; development=$d }
}
$receipt = [pscustomobject]@{
    generated_utc=[DateTime]::UtcNow.ToString('o'); product_root=$ProductRoot; development_root=$DevelopmentRoot
    product_files=$product.Count; development_files=$development.Count
    identical=(@($diff | ? kind -eq identical).Count); product_only=(@($diff | ? kind -eq product_only).Count)
    development_only=(@($diff | ? kind -eq development_only).Count); content_diff=(@($diff | ? kind -eq content_diff).Count)
    files=$diff
}
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'source_inventory.json') -Encoding UTF8
$diff | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutputDirectory 'source_inventory.csv')
Write-Output "INVENTORY=$OutputDirectory/source_inventory.json"
Write-Output "PRODUCT_FILES=$($product.Count) DEVELOPMENT_FILES=$($development.Count)"
Write-Output "IDENTICAL=$($receipt.identical) PRODUCT_ONLY=$($receipt.product_only) DEVELOPMENT_ONLY=$($receipt.development_only) CONTENT_DIFF=$($receipt.content_diff)"
