param($FilePath, $OutFile)
# Set up the environment
$vs_path = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"
$include_path = "F:\rawrxd\src\deep2"

& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe" /showIncludes /I $include_path $FilePath 2>&1 | Out-File -FilePath $OutFile -Encoding ASCII