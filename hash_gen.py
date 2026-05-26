def djb2(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF

names = ['OpenProcessToken', 'LookupPrivilegeValueW', 'AdjustTokenPrivileges', 'MapViewOfFileEx', 'GetLastError']
for n in names:
    print(f"{n}: {hex(djb2(n))}")
