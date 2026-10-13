# gate1b_tokenize_ref.py -- Gate 1B: INDEPENDENT tokenizer parity reference.
#
# Implementation language: Python. Engine: the real `tiktoken` BPE core (the
# same implementation llama.cpp ports to C++ for llama-3 vocabularies) fed with
# llama-3's exact split pattern (python `regex` module) and the mergeable-rank
# table parsed out of the production GGUF itself. The C++ battery receipts
# (TOKIDS lines) must agree EXACTLY, token for token.
import sys
import unicodedata
import gguf
import regex
import tiktoken

MODEL = sys.argv[1] if len(sys.argv) > 1 else r"F:\rawrxd\llama3.2-3b-Q2_K.gguf"
IDS_PATH = sys.argv[2] if len(sys.argv) > 2 else r"F:\rawrxd\evidence\TOKTEST_2026-10-12\llama32_3b_toktest_v5.log"
PATTERN = (
    r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}"
    r"| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+"
)


def ch2byte(ch):
    cp = ord(ch)
    if cp <= 0x7F:
        return cp
    if 0xA1 <= cp <= 0xAC or 0xAE <= cp <= 0xFF:
        return cp
    if 256 <= cp <= 288:
        return cp - 256
    if 289 <= cp <= 322:
        return cp - 289 + 0x7F
    if cp == 323:
        return 0xAD
    return None


def piece_to_bytes(piece):
    out = bytearray()
    for ch in piece:
        b = ch2byte(ch)
        if b is None:
            out.extend(ch.encode('utf-8'))
        else:
            out.append(b)
    return bytes(out)


def main():
    r = gguf.GGUFReader(MODEL)

    def arr(name):
        f = r.fields.get(name)
        if f is None or not f.types or f.types[0] != gguf.GGUFValueType.ARRAY:
            return []
        out = []
        for v in f.contents():
            if isinstance(v, gguf.ReaderField):
                v = v.contents()[0]
            if isinstance(v, bytes):
                out.append(v.split(b'\0', 1)[0].decode('utf-8'))
            else:
                out.append(str(v))
        return out

    vocab = arr('tokenizer.ggml.tokens')
    if not vocab:
        print('GATE1B REF_ERROR no vocabulary')
        return

    ranks = {}
    for i, piece in enumerate(vocab):
        bs = piece_to_bytes(piece)
        ranks.setdefault(bs, i)
    enc = tiktoken.Encoding(
        name='rawrxd-gate1b-ref', pat_str=PATTERN, mergeable_ranks=ranks, special_tokens={}
    )

    mine = {}
    for line in open(IDS_PATH, 'r', encoding='utf-8', errors='replace'):
        if line.startswith('TOKIDS '):
            rest = line[len('TOKIDS '):].strip()
            name, ids = rest.split(' ', 1)
            mine[name] = ids

    cases = {
        'plain_expr': 'int add(int a, int b) { return a + b; }',
        'accents': 'caf\u00e9 na\u00efve \u00dcber stra\u00dfe',
        'cjk': '\u4f60\u597d \u4e16\u754c',
        'emoji': 'hi \U0001f44b end',
        'calc_src': '#include <cstdio>\nint add(int a, int b) {\n    return a - b;\n}\nint main() {\n    printf("%d\\n", add(2, 3));\n    return 0;\n}\n',
    }
    total = pass_count = 0
    for name, text in cases.items():
        total += 1
        try:
            ids = enc.encode(text, disallowed_special=())
            ref = ','.join(str(x) for x in ids)
        except Exception as ex:
            print(f'GATE1B {name} REF_ERROR {ex}')
            continue
        m = mine.get(name, '')
        ok = ref == m
        if ok:
            pass_count += 1
        print(f'GATE1B {name} {"PASS" if ok else "FAIL"}')
        if not ok:
            a, bkt = m.split(','), ref.split(',')
            first = next((k for k in range(min(len(a), len(bkt))) if a[k] != bkt[k]), min(len(a), len(bkt)))
            print(f'  first_diff index {first} (mine n={len(a)} ref n={len(bkt)})')
            ctx = 3
            print(f'  mine[{max(0, first - ctx)}:{first + ctx}] = {a[max(0, first - ctx):first + ctx]}')
            print(f'  ref[{max(0, first - ctx)}:{first + ctx}]  = {bkt[max(0, first - ctx):first + ctx]}')
    print(f'GATE1B tiktoken-reference parity: {pass_count}/{total}')


if __name__ == '__main__':
    main()
