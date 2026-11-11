import re
with open(r'F:\rawrxd\src\GGUFLoader.cpp', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()
    includes = re.findall(r'#include\s+[<"]([^">]+)[>"]', content)
    for inc in sorted(set(includes)):
        print(inc)
