# ============================================================================
# cmake_source_audit.ps1 - a source manifest audit for a CMake tree.
#
# The question this answers is: "can a FRESH CHECKOUT of this repository
# configure and build?"
#
# A tree can configure perfectly in the maintainer's checkout and still fail
# in a clean clone, because a target depends on a source file that was never
# committed. The symptom appears far from the cause -- CMake reports
# "Cannot find source file" for a path that plainly exists on disk -- which
# is why it is worth auditing the manifest rather than chasing the error.
#
# Every source-looking path mentioned anywhere in the tree's CMake files is
# collected, and each one is classified:
#
#   OK          present, and tracked by git
#   UNTRACKED   present, but git does not track it: a fresh checkout will
#               NOT have it, so the configure step will fail there
#   IGNORED     present, but matched by a .gitignore rule (usually because
#               it sits under a directory named "build")
#   MISSING     not present at all
#
# Usage: powershell -File cmake_source_audit.ps1 -Repo <root>
# ============================================================================

param(
    [Parameter(Mandatory = $true)][string]$Repo
)

$ErrorActionPreference = 'Continue'

Write-Host "SOURCE_MANIFEST_AUDIT $Repo"
Write-Host ""

# ---- 1. Every source path the CMake files mention --------------------------
$extensions = @('cpp', 'cc', 'cxx', 'c', 'h', 'hpp', 'hxx', 'cu', 'asm')
$tokens = @()
foreach ($extension in $extensions) {
    $regex = '[A-Za-z0-9_./\\-]+\.' + $extension + '\b'
    $found = & git -C $Repo grep -h -o -E $regex -- '*CMakeLists.txt' '*.cmake' 2>$null
    foreach ($token in $found) {
        $clean = $token.Trim().Replace('\', '/')
        if (-not $clean) { continue }
        # A reference such as ${CMAKE_SOURCE_DIR}/src/foo.cpp is captured with
        # its leading separator, which is not part of the repository relative
        # path.
        while ($clean.StartsWith('/')) { $clean = $clean.Substring(1) }
        if (-not $clean) { continue }
        if ($clean -match '^\.\./') { continue }
        if ($clean -match '^[A-Za-z]:/') { continue }   # an absolute path
        $tokens += $clean
    }
}
$tokens = $tokens | Sort-Object -Unique

if (-not $tokens) {
    Write-Host "  no source paths were found in the CMake files"
    exit 0
}

# ---- 2. Classify each one --------------------------------------------------
# The git state is loaded ONCE. Asking git about each path individually is
# thousands of process launches and takes minutes.
$trackedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($line in (& git -C $Repo ls-files 2>$null)) {
    if ($line) { [void]$trackedSet.Add($line.Replace('\', '/')) }
}
$ignoredSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($line in (& git -C $Repo ls-files --others --ignored --exclude-standard 2>$null)) {
    if ($line) { [void]$ignoredSet.Add($line.Replace('\', '/')) }
}

$counts = @{ OK = 0; UNTRACKED = 0; IGNORED = 0; MISSING = 0 }
$problems = @()

# The directories a relative source path may be resolved against: the
# repository root, and every directory that holds a CMake file, because a
# target declared in a subdirectory resolves its sources against THAT
# directory, not against the root.
$baseDirectories = @($Repo)
foreach ($cmakeFile in (Get-ChildItem -LiteralPath $Repo -Recurse -Filter 'CMakeLists.txt' -File |
                        Where-Object { $_.FullName -notmatch '\\(\.git|\.vs|CMakeFiles)\\' -and
                                       $_.FullName -notmatch '\\build[A-Za-z0-9_]*\\' })) {
    $baseDirectories += $cmakeFile.DirectoryName
}

foreach ($token in $tokens) {
    $relative = $token
    $present = $false
    $resolved = ''
    foreach ($base in $baseDirectories) {
        $candidate = Join-Path $base ($token.Replace('/', '\'))
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $present = $true
            $resolved = $candidate.Substring($Repo.Length).TrimStart('\').Replace('\', '/')
            break
        }
    }
    if (-not $present) {
        $candidate = Join-Path $Repo ($token.Replace('/', '\'))
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $present = $true; $resolved = $token }
    }
    if (-not $present) { $class = 'MISSING'; $relative = $token }
    else {
        # The tracked and ignored lookups use the path where the file was
        # actually found, because a target declared in a subdirectory
        # resolves its sources against that directory.
        $tracked = $trackedSet.Contains($resolved)
        $ignored = $ignoredSet.Contains($resolved)
        $relative = $resolved
        if ($ignored) { $class = 'IGNORED' }
        elseif (-not $tracked) { $class = 'UNTRACKED' }
        else { $class = 'OK' }
    }

    $counts[$class]++
    if ($class -ne 'OK') {
        $problems += [PSCustomObject]@{ Class = $class; Source = $relative }
    }
}

Write-Host "  OK        $($counts.OK)"
Write-Host "  UNTRACKED $($counts.UNTRACKED)   present, but not in git: a fresh checkout cannot configure"
Write-Host "  IGNORED   $($counts.IGNORED)   present, but matched by a .gitignore rule"
Write-Host "  MISSING   $($counts.MISSING)   not present at all"
Write-Host ""
Write-Host "Two classes are benign and are expected in a healthy tree:"
Write-Host "  * files inside a submodule (3rdparty/quickjs, 3rdparty/quickjs_ng) are"
Write-Host "    tracked in that submodule's own repository, not in this one"
Write-Host "  * a MISSING entry whose path is relative to a subdirectory, and which"
Write-Host "    carries a doubled separator, is a fragment of a longer reference"
Write-Host ""
foreach ($problem in ($problems | Sort-Object Class, Source)) {
    "{0,-9} {1}" -f $problem.Class, $problem.Source
}

if ($counts.UNTRACKED + $counts.MISSING -gt 0) {
    exit 1
}
exit 0
