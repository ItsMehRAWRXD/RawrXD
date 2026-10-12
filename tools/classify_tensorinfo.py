# classify_tensorinfo.py - classify every TensorInfo occurrence in the tree.
# RAWRXD_TENSORINFO_TYPE_AUTHORITY_001
#
# Counts textual occurrences, then classifies each as Loader-facing,
# Engine-facing, Boundary, Ambiguous or Unrelated. Occurrences are not
# consumers: a declaration and its uses are separate facts, and both are
# reported separately.
import os, re, json, collections, hashlib, sys

ROOT = r'F:\rawrxd'

# Directories that are not production source.
SKIP_DIRS = {'.git', '.kilo', 'build', 'build_cert', 'build_ggml_profiler',
             'tmp_build', 'tmp_build_e2e', 'tmp_build_cert', 'tmp_build_owns',
             'tmp_llama-clean', 'tmp_llama-cpp-cpu', 'tmp_llama-clone',
             'Deep2_RuntimeIRBridge', 'Deep2_Runtime_IR_Bridge',
             'RawrXD_ParityDrop', 'packages', 'node_modules', '__pycache__'}
SKIP_EXT = {'.obj', '.pdb', '.exe', '.dll', '.lib', '.ilk', '.o', '.a', '.bin',
            '.zip', '.png', '.jpg', '.pdf', '.gguf', '.log', '.bak'}

SRC_EXT = {'.cpp', '.hpp', '.h', '.c', '.cc', '.cxx', '.inl'}

def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_EXT:
                continue
            yield os.path.join(dirpath, fn)

# Keyword sets are ordered; first match wins so classification is deterministic.
RULES = [
    ('Unrelated',
        re.compile(r'tensorinfo_inventory|tensorinfo_inventory\.json', re.I)),
    ('Boundary',
        re.compile(r'TensorInfo\s*(rom|_rom|from_rom|to_rom|_romable|_convert)', re.I)),
    ('Boundary',
        re.compile(r'(rom|gguf|loader|file).{0,24}TensorInfo|TensorInfo.{0,24}(rom|gguf|loader|file)', re.I)),
    ('Loader',
        re.compile(r'readTensorInfo|parseTensorInfo|loadTensorInfo|scanTensorInfo|'
                   r'tensorInfo\w*\(|readTensor|parseTensor|'
                   r'GGUF|gguf|hdr\.|header|metadata|liveTensors|dataOffset|'
                   r'fread|fseek|MapViewOfFile|mmap', re.I)),
    ('Engine',
        re.compile(r'arena|activation|cache|kv[\-_ ]?cache|dispatch|execute|'
                   r'matmul|dot|quant|dequant|forward|residual|softmax|'
                   r'slice|weights|elementCount|dims', re.I)),
]
COMMENT = re.compile(r'^\s*(//|\*|/\*|\*/)')

occurrences = []
for path in walk(ROOT):
    ext = os.path.splitext(path)[1].lower()
    if ext not in SRC_EXT and ext != '.py':
        continue
    try:
        text = open(path, 'r', encoding='utf-8', errors='replace').read()
    except Exception:
        continue
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if not re.search(r'TensorInfo', line):
            continue
        occurrences.append({
            'file': os.path.relpath(path, ROOT).replace('\\', '/'),
            'line': i,
            'text': line.strip()[:200],
            'is_comment': bool(COMMENT.match(line)),
        })

def classify(o):
    t = o['text']
    if o['is_comment']:
        return 'Unrelated'
    for label, pat in RULES:
        if pat.search(t):
            return label
    return 'Ambiguous'

for o in occurrences:
    o['class'] = classify(o)

counts = collections.Counter(o['class'] for o in occurrences)
by_file = collections.Counter(o['file'] for o in occurrences)

# Declarations are a different thing from uses. Count sites that look like a
# definition (struct/class, using alias, or a function parameter/return type).
DECL = re.compile(r'\b(struct|class|using|typedef)\s+.*\bTensorInfo\b', re.I)
declarations = [o for o in occurrences if DECL.search(o['text'])]

res = {
    'occurrences_total': len(occurrences),
    'declaration_sites': len(declarations),
    'class_counts': dict(counts),
    'per_occurrence_top_files': dict(by_file.most_common(15)),
    'declaration_files': sorted({o['file'] for o in declarations}),
    'generated': True,
}

out = os.path.join(ROOT, 'evidence', 'RAWRXD_TENSORINFO_TYPE_AUTHORITY_001')
os.makedirs(out, exist_ok=True)
json.dump(res, open(os.path.join(out, 'counts.json'), 'w'), indent=2)
json.dump(occurrences, open(os.path.join(out, 'occurrences.json'), 'w'), indent=2)

print('occurrences total   :', len(occurrences))
print('declaration sites   :', len(declarations))
print()
for k in ['Loader-facing' if False else 'Loader', 'Engine', 'Boundary',
          'Ambiguous', 'Unrelated']:
    print('  %-12s %d' % (k, counts.get(k, 0)))
print()
print('declaration sites:')
for o in declarations[:40]:
    print('   %s:%d  %s' % (o['file'], o['line'], o['text'][:150]))
print()
print('top files by occurrences:')
for f, c in by_file.most_common(10):
    print('   %-58s %d' % (f, c))
print()
print('wrote', os.path.join(out, 'counts.json'))
