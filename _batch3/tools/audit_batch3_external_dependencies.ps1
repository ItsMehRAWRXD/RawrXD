param(
    [string]$Repo = "F:\~dev\rawrxd",
    [string]$OutDir = "F:\~dev\evidence\STRICT_IDE_OFFLINE_003"
)

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path $Repo).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$allText = Get-ChildItem $Repo -Recurse -File -Include *.cpp,*.cc,*.cxx,*.h,*.hpp,*.cmake,CMakeLists.txt |
    Where-Object {
        $_.FullName -notmatch '\\build[^\\]*\\' -and
        $_.FullName -notmatch '\\CMakeFiles\\'
    }

# External package/network authority scan.
$patterns = @(
    'FetchContent_Declare',
    'FetchContent_MakeAvailable',
    'ExternalProject_Add',
    'https?://',
    '#include\s*[<"]nlohmann/json\.hpp[>"]',
    'nlohmann_json::nlohmann_json'
)

$hits = foreach ($p in $patterns) {
    $allText |
        Select-String -Pattern $p -AllMatches -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{
                Pattern=$p
                File=$_.Path
                Line=$_.LineNumber
                Text=$_.Line.Trim()
            }
        }
}
$hits | Export-Csv (Join-Path $OutDir "external_dependency_hits.csv") -NoTypeInformation -Encoding UTF8

# Known runtime-required SDK/system dependencies are recorded separately.
$systemPatterns = @(
    'find_package\(Vulkan',
    'Vulkan::Vulkan',
    'vulkan-1\.lib',
    'bcrypt',
    'advapi32',
    'crypt32',
    'wintrust',
    'winhttp',
    'dbgeng'
)
$systemHits = foreach ($p in $systemPatterns) {
    $allText |
        Select-String -Pattern $p -AllMatches -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{
                Pattern=$p
                File=$_.Path
                Line=$_.LineNumber
                Text=$_.Line.Trim()
            }
        }
}
$systemHits | Export-Csv (Join-Path $OutDir "system_sdk_dependencies.csv") -NoTypeInformation -Encoding UTF8

Write-Host "External/source dependency hits: $($hits.Count)"
Write-Host "System/SDK dependency hits     : $($systemHits.Count)"
Write-Host "Evidence: $OutDir"
