@echo off
setlocal
cd /d F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001
findstr /C:"missing " fsck_latest_stdout.txt > missing_raw.txt
findstr /C:"dangling " fsck_latest_stdout.txt > dangling_objects.txt
findstr /I /C:"corrupt" /C:"sha1 mismatch" /C:"badObject" fsck_latest_stdout.txt fsck_latest_stderr.txt > corrupt_objects.txt
findstr /I /C:"broken link" /C:"invalid sha1" /C:"points nowhere" /C:"dangling symref" fsck_latest_stdout.txt fsck_latest_stderr.txt > invalid_refs.txt
echo MISSING_COUNT
find /c /v "" missing_raw.txt
echo DANGLING_COUNT
find /c /v "" dangling_objects.txt
echo CORRUPT_COUNT
find /c /v "" corrupt_objects.txt
echo INVALID_COUNT
find /c /v "" invalid_refs.txt
echo ---- MISSING HEAD ----
powershell -NoProfile -Command "Get-Content -LiteralPath 'missing_raw.txt' -TotalCount 50"
echo ---- INVALID HEAD ----
powershell -NoProfile -Command "Get-Content -LiteralPath 'invalid_refs.txt' -TotalCount 40"
echo ---- CORRUPT HEAD ----
powershell -NoProfile -Command "Get-Content -LiteralPath 'corrupt_objects.txt' -TotalCount 20"
echo ---- DANGLING HEAD ----
powershell -NoProfile -Command "Get-Content -LiteralPath 'dangling_objects.txt' -TotalCount 10"
