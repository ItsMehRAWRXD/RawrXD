import shutil, os
src = r'f:\~dev\_ide_stub_closure_recovery_001\rawrxd_ide_stub_closure_recovery\src\win32app'
dst = r'f:\~dev\rawrxd\src\win32app'
count = 0
for fname in os.listdir(src):
    s = os.path.join(src, fname)
    d = os.path.join(dst, fname)
    if os.path.exists(d):
        os.replace(d, d + '.old')
    shutil.copy2(s, d)
    count += 1
print('Copied', count, 'files')
