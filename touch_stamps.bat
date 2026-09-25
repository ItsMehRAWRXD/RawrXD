@echo off
powershell -NoProfile -Command "Get-ChildItem 'F:\~dev\rawrxd\build\CMakeFiles\generate.stamp' | ForEach-Object { $_.LastWriteTime = (Get-Date).AddMinutes(30) }"
powershell -NoProfile -Command "Get-ChildItem 'F:\~dev\rawrxd\build\CMakeFiles\generate.stamp.depend' | ForEach-Object { $_.LastWriteTime = (Get-Date).AddMinutes(30) }"
echo timestamps updated
