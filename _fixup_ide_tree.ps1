# Automated recovery of branch-referenced sources that exist only as untracked
# files in the main working tree (the certified branch references them but never
# committed them, so configure fails from the branch alone).
$wt = "F:\rawrxd_cert"
$main = "F:\rawrxd"
for ($i = 0; $i -lt 20; $i++) {
    cmd /c "call `"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat`" -arch=amd64 -host_arch=amd64 >nul && cmake -S $wt -B $wt\build_ide -G `"Visual Studio 17 2022`" -A x64 -DCMAKE_BUILD_TYPE=Release" > "$wt\cmake_ide.log" 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Output "CONFIGURE_OK after $i fix iterations"; break }
    $missing = Select-String -LiteralPath "$wt\cmake_ide.log" -Pattern "Cannot find source file:\s*$" -Context 0,1 |
        ForEach-Object { $_.Context.PostContext[0].Trim() } | Sort-Object -Unique
    if (-not $missing) { Write-Output "NO_MISSING_FILE_ERRORS"; break }
    $fixed = 0
    foreach ($m in $missing) {
        $src = Join-Path $main $m
        if (Test-Path -LiteralPath $src) {
            $dst = Join-Path $wt $m
            $dd = Split-Path -Parent $dst
            if (-not (Test-Path -LiteralPath $dd)) { New-Item -ItemType Directory -Path $dd -Force | Out-Null }
            Copy-Item -LiteralPath $src -Destination $dst -Force
            $fixed = $fixed + 1
        } else {
            Write-Output "NOT_IN_MAIN_TREE: $m"
        }
    }
    Write-Output "iteration $i : copied $fixed"
    if ($fixed -eq 0) { break }
}
