param(
    [string]$Repo = "F:\~dev\rawrxd",
    [string]$OutDir = "F:\~dev\evidence\STRICT_IDE_SOURCE_CLOSURE_002"
)

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path $Repo).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$sourceFiles = Get-ChildItem $Repo -Recurse -File -Include *.cpp,*.cc,*.cxx,*.c,*.h,*.hpp |
    Where-Object {
        $_.FullName -notmatch '\\build[^\\]*\\' -and
        $_.FullName -notmatch '\\CMakeFiles\\'
    }

# 1) External source dependencies / network fetches.
$depPatterns = @(
    'FetchContent',
    'ExternalProject',
    'find_package\s*\(',
    '#include\s*[<"]nlohmann/',
    '#include\s*[<"]boost/',
    '#include\s*[<"]Qt',
    '#include\s*[<"]curl/',
    '#include\s*[<"]onnxruntime',
    '#include\s*[<"]torch/'
)

$depHits = foreach ($p in $depPatterns) {
    Get-ChildItem $Repo -Recurse -File -Include CMakeLists.txt,*.cmake,*.cpp,*.cc,*.cxx,*.h,*.hpp |
        Select-String -Pattern $p -AllMatches -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{
                Pattern = $p
                File = $_.Path
                Line = $_.LineNumber
                Text = $_.Line.Trim()
            }
        }
}
$depHits | Export-Csv (Join-Path $OutDir "external_dependency_hits.csv") -NoTypeInformation -Encoding UTF8

# 2) Stub/link-closure authority candidates.
$authorityPattern = '(?i)(stub|mock|shim|fallback|linker_closure|unlinked_symbols_batch)'
$authority = $sourceFiles |
    Where-Object { $_.Name -match $authorityPattern } |
    Select-Object FullName,Name,Length
$authority | Export-Csv (Join-Path $OutDir "compatibility_authority_candidates.csv") -NoTypeInformation -Encoding UTF8

# 3) Direct placeholder bodies likely to be real unresolved implementation debt.
$bodyPatterns = @(
    '\{\s*\}',
    'return\s+false\s*;',
    'return\s+true\s*;',
    'return\s+0\s*;',
    'return\s+nullptr\s*;',
    'E_NOTIMPL',
    'ERROR_CALL_NOT_IMPLEMENTED',
    'not implemented',
    'TODO',
    'FIXME'
)

$bodyHits = foreach ($p in $bodyPatterns) {
    $sourceFiles |
        Select-String -Pattern $p -AllMatches -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{
                Pattern = $p
                File = $_.Path
                Line = $_.LineNumber
                Text = $_.Line.Trim()
            }
        }
}
$bodyHits | Export-Csv (Join-Path $OutDir "implementation_debt_candidates.csv") -NoTypeInformation -Encoding UTF8

Write-Host "Evidence: $OutDir"
Write-Host "External dependency hits : $($depHits.Count)"
Write-Host "Compatibility TUs        : $($authority.Count)"
Write-Host "Implementation candidates: $($bodyHits.Count)"
