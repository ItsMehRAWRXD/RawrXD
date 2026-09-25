import re
with open('CMakeLists.txt', 'r') as f:
    content = f.read()
count1 = content.count('src/cpu_inference_engine.cpp')
count2 = content.count('src/cpu_inference_engine_autofix_stub.cpp')
print('Found {} cpu refs'.format(count1))
print('Found {} autofix refs'.format(count2))
content = re.sub(r'\n    src/cpu_inference_engine\.cpp', '', content)
content = re.sub(r'\n            src/cpu_inference_engine_autofix_stub\.cpp', '', content)
remaining = content.count('cpu_inference_engine.cpp')
print('Remaining: {}'.format(remaining))
with open('CMakeLists.txt', 'w') as f:
    f.write(content)
print('Done')
