$cl = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"
$src = "G:\VSC0de\Deep2Engine\scripts\inspect_gguf.cpp"
$out = "G:\VSC0de\Deep2Engine\scripts\inspect_gguf.exe"
& $cl /O2 /EHsc $src /Fe$out 2>&1