import subprocess
import sys

# Get the original modelfile
result = subprocess.run(['ollama', 'show', 'qwen3-next:80b', '--modelfile'], capture_output=True, text=True, timeout=60)
lines = result.stdout.split('\n')

# Extract the TEMPLATE block
in_template = False
template_lines = []
for line in lines:
    if line.startswith('TEMPLATE'):
        in_template = True
        template_lines.append(line)
        continue
    if in_template:
        template_lines.append(line)
        if line.strip() == '"""' and len(template_lines) > 2:
            break

template = '\n'.join(template_lines)
print('TEMPLATE_LINES:', len(template_lines))
print('TEMPLATE_LEN:', len(template))

# Write the new Modelfile
modelfile = 'from qwen3next-reap128:latest\n' + template + '\n'

with open(r'F:\rawrxd\Modelfile.qwen3next-reap128-fixed', 'w', encoding='utf-8') as f:
    f.write(modelfile)

print('Modelfile written')
print('First 200 chars:', modelfile[:200])