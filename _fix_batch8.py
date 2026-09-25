import re
path = r'F:\~dev\rawrxd\CMakeLists.txt'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()
orig = content
for fn in ['src/production_config_manager.cpp', 'src/project_context.cpp', 'src/rawrxd_inference.cpp']:
    pattern = re.escape(fn) + r'\s*\n'
    content = re.sub(pattern, '', content)
if content != orig:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print('Removed references')
else:
    print('No changes')
