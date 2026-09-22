import re

with open(r'f:\~dev\rawrxd\CMakeLists.txt', 'r', encoding='utf-8', newline='') as f:
    content = f.read()

new_content = re.sub(
    r'(option\(BUILD_DEEP2_[^)]+\s+"[^"]*\([^)]*\)[^"]*"\s+)ON\)',
    r'\1OFF)',
    content
)

with open(r'f:\~dev\rawrxd\CMakeLists.txt', 'w', encoding='utf-8', newline='') as f:
    f.write(new_content)

count_before = len(re.findall(r'option\(BUILD_DEEP2_[^)]+\s+ON\)', content))
count_after = len(re.findall(r'option\(BUILD_DEEP2_[^)]+\s+ON\)', new_content))
count_fixed = len(re.findall(r'option\(BUILD_DEEP2_[^)]+\s+OFF\)', new_content))
print(f'Before ON: {count_before}')
print(f'After ON: {count_after}')
print(f'After OFF: {count_fixed}')
