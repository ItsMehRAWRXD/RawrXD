param(
    [string]$Contracts = "F:\~dev\evidence\STRICT_IDE_OFFLINE_003\batch4_contracts.txt",
    [string]$Out = "F:\~dev\evidence\STRICT_IDE_OFFLINE_003\batch4_classified.csv"
)

$ErrorActionPreference = "Stop"
if (!(Test-Path $Contracts)) {
    throw "Contracts file not found: $Contracts"
}

$rows = foreach ($line in Get-Content $Contracts) {
    $kind =
        if ($line -match 'nlohmann/json\.hpp') { 'NATIVE_JSON_MIGRATION' }
        elseif ($line -match 'fatal error C1083') { 'MISSING_HEADER_OR_INCLUDE' }
        elseif ($line -match 'LNK2001|LNK2019|unresolved external symbol') { 'MISSING_IMPLEMENTATION' }
        elseif ($line -match 'LNK1120') { 'LINK_SUMMARY' }
        elseif ($line -match 'error C[0-9]{4}') { 'COMPILE_CONTRACT' }
        else { 'OTHER' }

    [pscustomobject]@{
        Kind=$kind
        Diagnostic=$line
    }
}

$rows | Export-Csv $Out -NoTypeInformation -Encoding UTF8
$rows | Group-Object Kind | Sort-Object Name | Format-Table Name,Count -AutoSize
Write-Host "Classified: $Out"
