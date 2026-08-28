cd D:\rawrxd

$exe = ".\build-hotpatch-test\bin\hotpatch_stress_test.exe"
$hash = Get-FileHash $exe -Algorithm SHA256
$file = Get-Item $exe

$manifest = @"
RawrXD Hotpatch Certification Baseline
=======================================
Executable: $($file.FullName)
SHA256:     $($hash.Hash)
Size:       $($file.Length)
Timestamp:  $($file.LastWriteTime.ToString("o"))
Tests:      187
Passed:     187
Failed:     0
Exit code:  0
Build dir:  build-hotpatch-test
Generator:  Ninja
Vulkan:     OFF
"@

$manifest | Set-Content .\HOTPATCH_CERTIFICATION_MANIFEST.txt
Get-Content .\HOTPATCH_CERTIFICATION_MANIFEST.txt