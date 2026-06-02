param(
    [int]$Count = 128,
    [int]$FanIn = 2,
    [int]$DeadSymbolEvery = 5,
    [string]$OutputRoot = "D:\rawrxd\artifacts\linker_dag_stress",
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

function Resolve-ToolPath {
    param(
        [Parameter(Mandatory = $true)][string[]]$Candidates,
        [Parameter(Mandatory = $true)][string]$ToolName
    )

    foreach ($candidate in $Candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "$ToolName not found. Checked: $($Candidates -join '; ')"
}

$runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runRoot = Join-Path $OutputRoot $runStamp
$srcDir = Join-Path $runRoot 'src'
$objDir = Join-Path $runRoot 'obj'

if ($Clean -and (Test-Path $runRoot)) {
    Remove-Item -LiteralPath $runRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
New-Item -ItemType Directory -Path $objDir -Force | Out-Null

$python = Resolve-ToolPath -ToolName 'Python' -Candidates @(
    'D:\.venv\Scripts\python.exe',
    'C:\Python312\python.exe'
)
$ml64 = Resolve-ToolPath -ToolName 'ml64.exe' -Candidates @(
    'C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe',
    'C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe'
)

& $python 'D:\rawrxd\scripts\generate_linker_dag_stress.py' `
    --out-dir $srcDir `
    --count $Count `
    --fan-in $FanIn `
    --dead-symbol-every $DeadSymbolEvery

$asmFiles = Get-ChildItem -LiteralPath $srcDir -Filter '*.asm' | Sort-Object Name
$assembled = @()

foreach ($asmFile in $asmFiles) {
    $objPath = Join-Path $objDir ($asmFile.BaseName + '.obj')
    & $ml64 /c /nologo /W3 /Zi /Fo$objPath $asmFile.FullName
    if ($LASTEXITCODE -ne 0) {
        throw "Assembly failed for $($asmFile.FullName) with exit code $LASTEXITCODE"
    }
    $assembled += $objPath
}

$manifest = Get-Content -LiteralPath (Join-Path $srcDir 'manifest.json') -Raw | ConvertFrom-Json
$objectListPath = Join-Path $runRoot 'objects.txt'
$assembled | Set-Content -LiteralPath $objectListPath -Encoding ascii

$summary = [ordered]@{
    generatedObjects = $Count
    assembledObjects = $assembled.Count
    fanIn = $FanIn
    deadSymbolEvery = $DeadSymbolEvery
    sourceRoot = $srcDir
    objectRoot = $objDir
    manifestPath = Join-Path $srcDir 'manifest.json'
    objectListPath = $objectListPath
    rootDependencies = @($manifest.entry.dependencies)
}

$summaryPath = Join-Path $runRoot 'summary.json'
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $summaryPath -Encoding utf8

Write-Host "[linker-dag-stress] Generated $Count source files and assembled $($assembled.Count) objects."
Write-Host "[linker-dag-stress] Sources: $srcDir"
Write-Host "[linker-dag-stress] Objects: $objDir"
Write-Host "[linker-dag-stress] Summary: $summaryPath"