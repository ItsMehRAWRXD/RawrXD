$Script:headerFile = "d:\rawrxd\src\win32app\Win32IDE.h"
$Script:backupFile = "d:\rawrxd\src\win32app\Win32IDE.h.bak"
$Script:middleFile = "d:\rawrxd\clean_middle.txt"

$Script:bak = Get-Content $backupFile
$Script:mid = Get-Content $middleFile

Write-Host "Backup: $($bak.Count) lines"
Write-Host "Middle: $($mid.Count) lines"

# Part 1: Backup lines 1-1014 (indices 0-1013) - clean before corruption
$Script:part1 = $bak[0..1013]

# Part 2: Clean middle content (Window dimensions through m_chatMode)
$Script:part2 = $mid

# Part 3: Backup lines 1294-end (indices 1293+) - clean after corruption (PS Panel through end)
$Script:part3 = $bak[1293..($bak.Count - 1)]

Write-Host "Part1: $($part1.Count) lines (backup 1-1014)"
Write-Host "Part2: $($part2.Count) lines (clean middle)"
Write-Host "Part3: $($part3.Count) lines (backup 1294-$($bak.Count))"

# Combine
$Script:newContent = $part1 + $part2 + $part3

# Write the new file
$newContent | Set-Content $headerFile -Encoding UTF8

$Script:check = Get-Content $headerFile
Write-Host "New file: $($check.Count) lines"
Write-Host "Done!"
