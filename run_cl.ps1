param($FilePath)
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe" /showIncludes $FilePath 2>&1 | Out-File -FilePath "F:\rawrxd\includes_out.txt" -Encoding ASCII