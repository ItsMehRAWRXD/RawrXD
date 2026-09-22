import re
path = r'F:\~dev\rawrxd\3rdparty\quickjs\quickjs.c'
with open(path, 'r', encoding='utf-8') as f:
    c = f.read()
orig = c
# Remove (JSValue) and (JSValueConst) casts that are not followed by another '('
# This avoids stripping casts used in constructors like (JSValue){...}
c = re.sub(r'\(JSValueConst\)([^(])', r'\1', c)
c = re.sub(r'\(JSValue\)([^(])', r'\1', c)
print('Replaced', len(orig) - len(c), 'chars')
with open(path, 'w', encoding='utf-8') as f:
    f.write(c)
