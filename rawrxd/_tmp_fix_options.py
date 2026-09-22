import re

with open(r'f:\~dev\rawrxd\CMakeLists.txt', 'r', encoding='utf-8', newline='') as f:
    content = f.read()

new_content = re.sub(r'(option\(BUILD_DEEP2_[^)]+)\s+ON\)', r'\1 OFF)', content)

with open(r'f:\~dev\rawrxd\CMakeLists.txt', 'w', encoding='utf-8', newline='') as f:
    f.write(new_content)

count = len(re.findall(r'option\(BUILD_DEEP2_[^)]+ OFF\)', new_content))
print(f'Done. Replaced {count} occurrences.')
