import re

with open(r'f:\~dev\rawrxd\CMakeLists.txt', 'r', encoding='utf-8', newline='') as f:
    content = f.read()

# Replace any line that starts with option(BUILD_DEEP2_ and has ON) at the end
new_content = re.sub(r'^(option\(BUILD_DEEP2_[^\n]+?)\bON\)', r'\1OFF)', content, flags=re.MULTILINE)

with open(r'f:\~dev\rawrxd\CMakeLists.txt', 'w', encoding='utf-8', newline='') as f:
    f.write(new_content)

count_before = len(re.findall(r'^option\(BUILD_DEEP2_[^\n]+?\bON\)', content, flags=re.MULTILINE))
count_after = len(re.findall(r'^option\(BUILD_DEEP2_[^\n]+?\bON\)', new_content, flags=re.MULTILINE))
count_fixed = len(re.findall(r'^option\(BUILD_DEEP2_[^\n]+?\bOFF\)', new_content, flags=re.MULTILINE))
print(f'Before ON: {count_before}')
print(f'After ON: {count_after}')
print(f'After OFF: {count_fixed}')
