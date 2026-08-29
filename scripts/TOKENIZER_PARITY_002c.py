#!/usr/bin/env python3
"""TOKENIZER-PARITY-002c

Single encode authority:
  Spm::encode = metaspace normalize + llama.cpp SPM bigram merges

Compare:
  1) BPETokenizer path (agentic) — Spm::encode
  2) GGUFEmbeddedTokenizer path (parity) — specials then Spm::encode per span
  3) llama-tokenize CPU (--no-bos)

Input: frozen AGENT_E2E rendered_prompt.bin
"""
from __future__ import annotations

import hashlib
import heapq
import subprocess
from pathlib import Path

from gguf import GGUFReader

MODEL = Path(r"F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf")
EV_IN = Path(r"F:\~dev\rawrxd\evidence\AGENT_E2E_002b\TOKENIZER_PARITY_001")
OUT = Path(r"F:\~dev\rawrxd\evidence\AGENT_E2E_002b\TOKENIZER_PARITY_002c")
PROMPT_BIN = EV_IN / "rendered_prompt.bin"
LLAMA_TOKENIZE = Path(r"F:\~dev\llama-direct\vulkan\llama-tokenize.exe")
USP = "\u2581"


def sp_normalize(text: str) -> str:
    if not text:
        return ""
    return USP + text.replace(" ", USP)


def build_byte_fallback(vocab: dict[str, int]) -> list[int]:
    fb = [-1] * 256
    for piece, tid in vocab.items():
        if len(piece) == 6 and piece.startswith("<0x") and piece.endswith(">"):
            try:
                b = int(piece[3:5], 16)
            except ValueError:
                continue
            if 0 <= b < 256 and fb[b] < 0:
                fb[b] = tid
    return fb


class _Sym:
    __slots__ = ("text", "prev", "next", "alive")

    def __init__(self, text: str, prev: int, next_: int) -> None:
        self.text = text
        self.prev = prev
        self.next = next_
        self.alive = True


def spm_encode(
    text: str,
    vocab: dict[str, int],
    scores: list[float],
    unk: int = 0,
) -> list[int]:
    """Port of RawrXD::Spm::encode / llama.cpp llm_tokenizer_spm_session."""
    if not text:
        return []
    norm = sp_normalize(text)
    fb = build_byte_fallback(vocab)
    chars = list(norm)
    syms = [
        _Sym(c, i - 1, i + 1 if i + 1 < len(chars) else -1)
        for i, c in enumerate(chars)
    ]
    pq: list[tuple] = []
    seq = 0
    rev: dict[str, tuple[str, str]] = {}

    def try_add(left: int, right: int) -> None:
        nonlocal seq
        if left < 0 or right < 0:
            return
        L, R = syms[left], syms[right]
        if not L.alive or not R.alive:
            return
        merged = L.text + R.text
        tid = vocab.get(merged)
        if tid is None:
            return
        size = len(L.text) + len(R.text)
        heapq.heappush(pq, (-scores[tid], left, seq, right, size))
        seq += 1
        rev[merged] = (L.text, R.text)

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

    def resegment(piece: str) -> None:
        tid = vocab.get(piece)
        if tid is not None:
            out.append(tid)
            return
        if piece in rev:
            a, b = rev[piece]
            resegment(a)
            resegment(b)
            return
        for ch in piece:
            for byte in ch.encode("utf-8"):
                out.append(fb[byte] if fb[byte] >= 0 else unk)

    i = 0
    while i < len(syms) and not syms[i].alive:
        i += 1
    while i != -1:
        resegment(syms[i].text)
        i = syms[i].next
    return out


def encode_parity_api(
    text: str,
    vocab: dict[str, int],
    scores: list[float],
    specials: list[tuple[str, int]],
) -> list[int]:
    if not text:
        return []
    out: list[int] = []
    pos = 0
    ordinary_start = 0

    def flush(end: int) -> None:
        if end <= ordinary_start:
            return
        out.extend(spm_encode(text[ordinary_start:end], vocab, scores))

    while pos < len(text):
        matched = False
        rest = text[pos:]
        for piece, tid in specials:
            if rest.startswith(piece):
                flush(pos)
                out.append(tid)
                pos += len(piece)
                ordinary_start = pos
                matched = True
                break
        if not matched:
            pos += 1
    flush(len(text))
    return out


def run_llama(prompt_path: Path) -> list[int]:
    cmd = [
        str(LLAMA_TOKENIZE),
        "-m",
        str(MODEL),
        "-f",
        str(prompt_path),
        "--ids",
        "--log-disable",
        "--no-escape",
        "--no-bos",
    ]
    p = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    out = (p.stdout or "").strip()
    if p.returncode != 0:
        raise RuntimeError(f"llama-tokenize failed rc={p.returncode}\n{p.stderr}\n{out}")
    start = out.find("[")
    end = out.rfind("]")
    if start < 0 or end < 0:
        raise RuntimeError(f"unparseable llama-tokenize output: {out[:200]!r}")
    return [int(x.strip()) for x in out[start + 1 : end].split(",") if x.strip()]


def first_diff(a: list[int], b: list[int]) -> int | None:
    m = min(len(a), len(b))
    for i in range(m):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return m
    return None


def write_ids(path: Path, ids: list[int]) -> None:
    path.write_text(",".join(str(x) for x in ids) + "\n", encoding="utf-8")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    prompt = PROMPT_BIN.read_bytes()
    prompt_text = prompt.decode("utf-8")
    sha = hashlib.sha256(prompt).hexdigest().upper()
    (OUT / "rendered_prompt.sha256").write_text(sha + "\n", encoding="utf-8")
    (OUT / "rendered_prompt.bin").write_bytes(prompt)

    r = GGUFReader(str(MODEL))
    pieces = r.get_field("tokenizer.ggml.tokens").contents()
    types = r.get_field("tokenizer.ggml.token_type").contents()
    score_field = r.get_field("tokenizer.ggml.scores").contents()
    vocab: dict[str, int] = {}
    for i, t in enumerate(pieces):
        if isinstance(t, bytes):
            t = t.decode("utf-8", "replace")
        vocab[t] = i
    scores = [float(x) for x in score_field]

    specials: list[tuple[str, int]] = []
    for i, t in enumerate(pieces):
        s = t.decode("utf-8", "replace") if isinstance(t, bytes) else t
        tt = int(types[i]) if i < len(types) else 1
        if tt in (3, 4) and s:
            specials.append((s, i))
    specials.sort(key=lambda x: (-len(x[0]), x[0]))

    bpe_ids = spm_encode(prompt_text, vocab, scores)
    parity_ids = encode_parity_api(prompt_text, vocab, scores, specials)
    llama_ids = run_llama(PROMPT_BIN)

    write_ids(OUT / "bpe_tokenizer_ids.txt", bpe_ids)
    write_ids(OUT / "parity_api_ids.txt", parity_ids)
    write_ids(OUT / "llama_cpu_ids.txt", llama_ids)

    d_bpe_llama = first_diff(bpe_ids, llama_ids)
    d_parity_llama = first_diff(parity_ids, llama_ids)
    d_bpe_parity = first_diff(bpe_ids, parity_ids)

    token_35_bpe = 35 in bpe_ids
    token_35_parity = 35 in parity_ids
    token_35_llama = 35 in llama_ids

    all_match = (
        d_bpe_llama is None
        and d_parity_llama is None
        and d_bpe_parity is None
        and len(bpe_ids) == len(llama_ids) == len(parity_ids) == 898
        and not token_35_bpe
        and not token_35_parity
        and not token_35_llama
    )

    lines = [
        "TOKENIZER-PARITY-002c",
        "",
        f"rendered_prompt_sha256={sha}",
        f"rendered_prompt_bytes={len(prompt)}",
        "encode_authority=RawrXD::Spm::encode (llama.cpp SPM bigram merges)",
        "",
        f"TOKEN_COUNT_BPE={len(bpe_ids)}",
        f"TOKEN_COUNT_PARITY_API={len(parity_ids)}",
        f"TOKEN_COUNT_LLAMA={len(llama_ids)}",
        "",
        f"FIRST_DIFF_BPE_VS_LLAMA={d_bpe_llama if d_bpe_llama is not None else 'NONE'}",
        f"FIRST_DIFF_PARITY_VS_LLAMA={d_parity_llama if d_parity_llama is not None else 'NONE'}",
        f"FIRST_DIFF_BPE_VS_PARITY={d_bpe_parity if d_bpe_parity is not None else 'NONE'}",
        "",
        f"TOKEN_35_BPE={str(token_35_bpe).lower()}",
        f"TOKEN_35_PARITY={str(token_35_parity).lower()}",
        f"TOKEN_35_LLAMA={str(token_35_llama).lower()}",
        "",
        f"BPE_FIRST={bpe_ids[0] if bpe_ids else 'EMPTY'} BPE_LAST={bpe_ids[-1] if bpe_ids else 'EMPTY'}",
        f"LLAMA_FIRST={llama_ids[0] if llama_ids else 'EMPTY'} LLAMA_LAST={llama_ids[-1] if llama_ids else 'EMPTY'}",
        "",
    ]
    if all_match:
        lines += [
            "VERDICT=PASS",
            "TOKENIZER-PARITY-002c=CERTIFIED",
            "TOKENIZER-PARITY-002b-001=CERTIFIED",
            "AGENTIC_TOKENIZER_IDS==PARITY_TOKENIZER_IDS==CPU_LLAMA_TOKENIZER_IDS",
            "FORWARD_CLAIMS_FROM_THIS_PROMPT=UNBLOCKED_FOR_TOKENIZER",
        ]
        rc = 0
    else:
        lines += [
            "VERDICT=FAIL",
            "TOKENIZER-PARITY-002c=NOT_CERTIFIED",
            "ROOT_DOMAIN=TOKENIZER",
        ]
        if d_bpe_llama is not None:
            i = d_bpe_llama
            lines.append(
                f"DIFF_DETAIL i={i} bpe={bpe_ids[i] if i < len(bpe_ids) else 'EOF'} "
                f"llama={llama_ids[i] if i < len(llama_ids) else 'EOF'}"
            )
        rc = 1

    verdict = "\n".join(lines) + "\n"
    (OUT / "VERDICT.txt").write_text(verdict, encoding="utf-8")
    # Also stamp 002b evidence as certified when green
    if all_match:
        stamp = (
            "TOKENIZER-PARITY-002b-001\n"
            "SUPERSEDED_BY=TOKENIZER-PARITY-002c\n"
            "VERDICT=PASS\n"
            "TOKENIZER-PARITY-002b-001=CERTIFIED\n"
            f"exact_token_ids=898 matched via Spm::encode\n"
        )
        (EV_IN / "VERDICT.txt").write_text(stamp, encoding="utf-8")
    print(verdict)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
