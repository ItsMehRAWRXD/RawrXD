import re

src = open(r'F:\rawrxd\tmp_llama-clone\src\unicode-data.cpp', encoding='utf-8').read()

# Scope extraction to the two tables we need: unicode_ranges_flags and
# unicode_set_whitespace. Other tables in this file share the same shape.
def block(name):
    i = src.index(name)
    b = src.index('{', i)
    e = src.index('};', b)
    return src[b:e + 1]

flags_block = block('unicode_ranges_flags')
pairs = re.findall(r'\{0x([0-9A-Fa-f]+),\s*0x([0-9A-Fa-f]+)\}', flags_block)
starts = [int(a, 16) for a, b in pairs]
flags = [int(b, 16) for a, b in pairs]
print('flags entries', len(pairs), 'first', hex(starts[0]), 'last', hex(starts[-1]))
assert starts[0] == 0
assert starts[-1] == 0x110000, hex(starts[-1])

number = []
for i in range(len(starts) - 1):
    if flags[i] & 0x0002:  # NUMBER (\p{N}); flags[i] covers [starts[i], starts[i+1])
        number.append((starts[i], starts[i + 1] - 1))

ws_block = block('unicode_set_whitespace')
ws = [(c, c) for c in sorted(int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]+)', ws_block))]
print('number raw', len(number), 'ws', len(ws))


def merge(lst):
    out = []
    for lo, hi in sorted(lst):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


number = merge(number)
ascii_ws = [(0x09, 0x0D), (0x20, 0x20)]
ws_all = merge(ascii_ws + ws)
print('number merged', len(number), 'ws merged', len(ws_all))

# letter / punctuation / CJK classes straight from the reference binary's
# deepseek-llm regex.
d = open(r'F:\rawrxd\tmp_llama-cpp-cpu\llama.dll', 'rb').read()
t = d.decode('utf-8', 'replace')

ESC = {'r': 0x0D, 'n': 0x0A, 't': 0x09, 'v': 0x0B, 'f': 0x0C, 'b': 0x08,
       '\\': 0x5C, ']': 0x5D, '[': 0x5B, '^': 0x5E, '-': 0x2D, '$': 0x24,
       '+': 0x2B, '<': 0x3C, '>': 0x3E, '|': 0x7C, '(': 0x28, ')': 0x29,
       '.': 0x2E, '?': 0x3F, '*': 0x2A, '{': 0x7B, '}': 0x7D, '`': 0x60,
       "'": 0x27, '"': 0x22, '/': 0x2F, ',': 0x2C, ':': 0x3A, ';': 0x3B,
       '=': 0x3D, '~': 0x7E, '!': 0x21, '#': 0x23, '%': 0x25, '&': 0x26,
       ' ': 0x20, 'a': 0x07, 'e': 0x1B}


def one(body, i):
    if body[i] == '\\':
        if body[i + 1] == 'x':
            return int(body[i + 2:i + 4], 16), 4
        return ESC.get(body[i + 1], ord(body[i + 1])), 2
    return ord(body[i]), 1


def parse_ranges(body):
    out = []
    i = 0
    while i < len(body):
        cp, used = one(body, i)
        i += used
        if i < len(body) and body[i] == '-' and i + 1 < len(body):
            hi, used2 = one(body, i + 1)
            out.append((cp, hi))
            i += 1 + used2
        else:
            out.append((cp, cp))
    return out


def class_body(prefix):
    i = t.find(prefix)
    assert i > 0, prefix
    b = t.find('[', i)
    e = t.find(']', b)
    return t[b + 1:e]


letters = merge(parse_ranges(class_body('\\s?[A-Za-z')))
punct = merge(parse_ranges(class_body('\\s?[!-/:-~')))
cjk = [(0x4E00, 0x9FA5), (0x0800, 0x4E00), (0xAC00, 0xD7FF)]
print('letters', len(letters), 'punct', len(punct))


def emit(o, name, rows):
    o.write('static constexpr uint32_t k%s[][2] = {\n' % name)
    for i in range(0, len(rows), 4):
        o.write('    ' + ' '.join('{0x%04X,0x%04X},' % r for r in rows[i:i + 4]) + '\n')
    o.write('};\n\n')


with open(r'F:\rawrxd\src\tokenizer\deepseek_pretokenizer_ranges.inc', 'w', encoding='utf-8', newline='\n') as o:
    o.write('// Generated range tables for the DeepSeek-LLM pre-tokenizer classes.\n')
    o.write('// Sources: the deepseek-llm regex compiled into the reference\n')
    o.write('// llama.dll (letter / punctuation / CJK classes) and the Unicode\n')
    o.write('// category table llama.cpp uses for \\p{N} and \\s.\n')
    o.write('// Included by deepseek_pretokenizer.hpp; do not edit by hand.\n')
    o.write('// Regenerate with _tmp_gen_pretok_ranges.py.\n\n')
    emit(o, 'LetterRanges', letters)
    emit(o, 'PunctRanges', punct)
    emit(o, 'CjkRanges', cjk)
    emit(o, 'NumberRanges', number)
    emit(o, 'WhitespaceRanges', ws_all)
print('regenerated')
