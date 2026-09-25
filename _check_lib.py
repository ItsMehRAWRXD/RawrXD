import subprocess, os

libexe = r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\lib.exe'
libfile = r'F:\~dev\rawrxd\build\Release\InferenceEngine.lib'

# List contents
result = subprocess.run([libexe, '/list', libfile], capture_output=True, text=True)
with open(r'F:\~dev\_lib_list.txt', 'w') as f:
    f.write(result.stdout)
    f.write(result.stderr)
print('lib list written to F:\\~dev\\_lib_list.txt')
print('returncode', result.returncode)
