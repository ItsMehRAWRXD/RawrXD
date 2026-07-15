import subprocess
import os

ML64 = r"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
LINK = r"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
OUTDIR = r"d:\rawrxd\compilers\final_69_working"

os.makedirs(OUTDIR, exist_ok=True)

asm_content = """; Test
extrn GetStdHandle: proc
extrn WriteFile: proc
extrn ExitProcess: proc

.data
    banner db "Test", 13, 10
    banner_len equ $ - banner
.code
mainCRTStartup proc FRAME
    sub rsp, 56
    .allocstack 56
    .endprolog
    mov rcx, -11
    call GetStdHandle
    xor ecx, ecx
    call ExitProcess
    add rsp, 56
    ret
mainCRTStartup endp
end
"""

asm_path = os.path.join(OUTDIR, 'test.asm')
obj_path = os.path.join(OUTDIR, 'test.obj')
exe_path = os.path.join(OUTDIR, 'test.exe')

with open(asm_path, 'w') as f:
    f.write(asm_content)

# Assemble
result = subprocess.run([ML64, '/c', '/Fo', obj_path, '/W3', asm_path], capture_output=True, text=True)
print('Assembly:', result.returncode)
if result.stderr:
    print('ASM stderr:', result.stderr)

# Link
result = subprocess.run([LINK, '/SUBSYSTEM:CONSOLE', '/ENTRY:mainCRTStartup', 'kernel32.lib', obj_path, '/OUT:' + exe_path], capture_output=True, text=True)
print('Link:', result.returncode)
print('stdout:', result.stdout)
print('stderr:', result.stderr)
