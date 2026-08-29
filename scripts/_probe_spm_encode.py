from pathlib import Path
import heapq
from gguf import GGUFReader

MODEL = Path(r"F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf")
PROMPT = Path(
    r"F:\~dev\rawrxd\evidence\AGENT_E2E_002b\TOKENIZER_PARITY_001\rendered_prompt.bin"
).read_text(encoding="utf-8")
LLAMA = [
    int(x)
    for x in Path(
        r"F:\~dev\rawrxd\evidence\AGENT_E2E_002b\TOKENIZER_PARITY_002c\llama_cpu_ids.txt"
    )
    .read_text()
    .strip()
    .split(",")
]

r = GGUFReader(str(MODEL))
toks = [
    (t.decode("utf-8", "replace") if isinstance(t, bytes) else t)
    for t in r.get_field("tokenizer.ggml.tokens").contents()
]
scores = [float(x) for x in r.get_field("tokenizer.ggml.scores").contents()]
vocab = {t: i for i, t in enumerate(toks)}
fb = [-1] * 256
for i, t in enumerate(toks):
    if len(t) == 6 and t.startswith("<0x") and t.endswith(">"):
        try:
            b = int(t[3:5], 16)
            if fb[b] < 0:
                fb[b] = i
        except ValueError:
            pass
USP = "\u2581"


def sp_normalize(text: str) -> str:
    if not text:
        return ""
    return USP + text.replace(" ", USP)


class Sym:
    __slots__ = ("text", "prev", "next", "alive")

    def __init__(self, text, prev, next_):
        self.text = text
        self.prev = prev
        self.next = next_
        self.alive = True


def spm_encode(norm: str) -> list[int]:
    if not norm:
        return []
    chars = list(norm)
    syms = [
        Sym(c, i - 1, i + 1 if i + 1 < len(chars) else -1)
        for i, c in enumerate(chars)
    ]
    pq = []
    seq = 0
    rev = {}

    def try_add(left, right):
        nonlocal seq
        if left < 0 or right < 0:
            return
        L, R = syms[left], syms[right]
        if not L.alive or not R.alive:
            return
        text = L.text + R.text
        tid = vocab.get(text)
        if tid is None:
            return
        size = len(L.text) + len(R.text)
        # max-heap via negation; tie-break smaller left first (match llama.cpp)
        heapq.heappush(pq, (-scores[tid], left, seq, right, size))
        seq += 1
        rev[text] = (L.text, R.text)

    for i in range(1, len(syms)):
        try_add(i - 1, i)

    while pq:
        _, left, _, right, size = heapq.heappop(pq)
        L, R = syms[left], syms[right]
        if not L.alive or not R.alive:
            continue
        if len(L.text) + len(R.text) != size:
            continue
        L.text = L.text + R.text
        R.alive = False
        L.next = R.next
        if R.next >= 0:
            syms[R.next].prev = left
        try_add(L.prev, left)
        try_add(left, L.next)

    out: list[int] = []

    def resegment(text: str) -> None:
        tid = vocab.get(text)
        if tid is not None:
            out.append(tid)
            return
        if text in rev:
            a, b = rev[text]
            resegment(a)
            resegment(b)
            return
        for ch in text:
            for byte in ch.encode("utf-8"):
                out.append(fb[byte] if fb[byte] >= 0 else 0)

    i = 0
    while i < len(syms) and not syms[i].alive:
        i += 1
    while i != -1:
        resegment(syms[i].text)
        i = syms[i].next
    return out


ids = spm_encode(sp_normalize(PROMPT))
print("count", len(ids), "llama", len(LLAMA))
d = None
for i, (a, b) in enumerate(zip(ids, LLAMA)):
    if a != b:
        d = i
        break
if d is None and len(ids) != len(LLAMA):
    d = min(len(ids), len(LLAMA))
print("first_diff", d)
if d is not None:
    print("ours", ids[max(0, d - 2) : d + 5])
    print("llama", LLAMA[max(0, d - 2) : d + 5])
    print("ours pieces", [toks[x] for x in ids[max(0, d - 2) : d + 5]])
    print("llama pieces", [toks[x] for x in LLAMA[max(0, d - 2) : d + 5]])
else:
    print("EXACT MATCH")
print("token35", 35 in ids)
