param(
    [string]$Repo = "F:\~dev\rawrxd"
)

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path $Repo).Path
$cmake = Join-Path $Repo "CMakeLists.txt"
if (!(Test-Path $cmake)) { throw "Missing CMakeLists.txt: $cmake" }

$text = Get-Content $cmake -Raw
$backup = "$cmake.batch3.bak"
Copy-Item -Force $cmake $backup

# Remove the unconditional FetchContent/nlohmann block.
$fetchPattern = '(?s)# ============================================================================\r?\n# nlohmann/json via FetchContent.*?FetchContent_MakeAvailable\(nlohmann_json\)\r?\n'
if ($text -match $fetchPattern) {
    $text = [regex]::Replace(
        $text,
        $fetchPattern,
        @'
# ============================================================================
# Strict offline dependency policy
# ============================================================================
# Batch 3: external JSON FetchContent removed from the production tree.
# If an active target still includes <nlohmann/json.hpp>, compilation must fail
# and that exact source becomes a native-source migration obligation.
set(FETCHCONTENT_FULLY_DISCONNECTED ON CACHE BOOL
    "RawrXD production builds must not download dependencies" FORCE)

'@
    )
} else {
    Write-Host "nlohmann FetchContent block not found; continuing with link cleanup."
    if ($text -notmatch 'FETCHCONTENT_FULLY_DISCONNECTED') {
        $anchor = 'project(RawrXD VERSION 14.7.3 LANGUAGES C CXX ASM_MASM)'
        if ($text -notmatch [regex]::Escape($anchor)) {
            throw "Could not identify RawrXD project anchor; refusing blind edit."
        }
        $insert = @"
$anchor

# Strict offline dependency policy
set(FETCHCONTENT_FULLY_DISCONNECTED ON CACHE BOOL
    "RawrXD production builds must not download dependencies" FORCE)
"@
        $text = $text.Replace($anchor, $insert)
    }
}

# nlohmann_json is header-only, so a bare target_link_libraries token is only
# include-path propagation. Remove it; any live include will now become a real
# compiler error rather than triggering a network download.
$text = [regex]::Replace(
    $text,
    '(?m)^[ \t]*nlohmann_json::nlohmann_json[ \t]*\r?\n',
    ''
)

Set-Content -Path $cmake -Value $text -Encoding UTF8
Write-Host "Patched: $cmake"
Write-Host "Backup : $backup"
Write-Host "Policy : external FetchContent disabled; nlohmann target removed."
