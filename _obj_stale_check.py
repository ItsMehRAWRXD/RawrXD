import os, datetime
names = ['unlinked_symbols_batch_005','unlinked_symbols_batch_006',
         'unlinked_symbols_batch_007','unlinked_symbols_batch_008',
         'unlinked_symbols_batch_009','unlinked_symbols_batch_001',
         'unlinked_symbols_batch_011','unlinked_symbols_batch_010',
         'win32ide_watchdog_init']
for name in names:
    cpp = r'F:\~dev\rawrxd\src\core' + '\\' + name + '.cpp'
    obj = r'F:\~dev\rawrxd\build_w1\RawrXD-Win32IDE.dir\Release' + '\\' + name + '.obj'
    if os.path.exists(cpp) and os.path.exists(obj):
        ct = os.path.getmtime(cpp)
        ot = os.path.getmtime(obj)
        status = 'STALE' if ot < ct else 'FRESH'
        cts = datetime.datetime.fromtimestamp(ct).strftime("%H:%M:%S")
        ots = datetime.datetime.fromtimestamp(ot).strftime("%H:%M:%S")
        print(name + ': src=' + cts + ' obj=' + ots + ' ' + status)
    elif not os.path.exists(cpp):
        obj_exists = os.path.exists(obj)
        print(name + ': SOURCE MISSING, obj=' + str(obj_exists) + ' (ORPHAN OBJ)')
    elif not os.path.exists(obj):
        print(name + ': obj MISSING (will recompile)')