def djb2(s):
    h = 5381
    for char in s:
        h = ((h << 5) + h + ord(char)) & 0xFFFFFFFF
    return h

targets = [
    'VirtualAlloc', 'VirtualFree', 'VirtualProtect', 'GetTickCount64',
    'GetCurrentProcess', 'SetPriorityClass', 'GetCurrentThread',
    'SetThreadAffinityMask', 'OutputDebugStringA', 'FlushInstructionCache',
    'CreateFileW', 'CreateFileMappingW', 'UnmapViewOfFile', 'OpenFileMappingA'
]

for t in targets:
    print(f"HASH_{t} equ 0{djb2(t):08X}h")
