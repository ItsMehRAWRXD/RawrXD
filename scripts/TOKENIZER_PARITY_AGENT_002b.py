#!/usr/bin/env python3
"""TOKENIZER-PARITY-001 / AGENT-E2E-002b
Diff Deep2 BPETokenizer::Encode vs llama-tokenize on the rendered agent prompt.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from gguf import GGUFReader

MODEL = Path(r"F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf")
OUT = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\TOKENIZER_PARITY_001")
LLAMA_TOKENIZE = Path(r"F:\~dev\llama-direct\vulkan\llama-tokenize.exe")
TASK = (
    "Fix the compile error in main.c so the program builds and prints hello from b01. "
    "Inspect with tools first, then edit, build, and run. "
    'Emit tools using: TOOL_CALL: tool_name {"arg":"value"} '
    "Available tools include read_file, write_file, replace_in_file, run_command. "
    'Example: TOOL_CALL: read_file {"path":"main.c"} '
    "No canned repairs. When finished, give a short final answer without TOOL_CALL."
)
SYSTEM = (
    "You are RawrXD's local sovereign coding agent. "
    "You operate only on the provided workspace and local tools. "
    "Complete the user's task end-to-end. "
    "Inspect before editing. "
    "Use exact tool results; never claim a build or test passed unless "
    "you actually ran it and observed a successful result. "
    "When a command fails, inspect the failure, modify the source if "
    "appropriate, and retry with a changed strategy. "
    "Prefer narrow, correct edits over unrelated changes. "
    "Do not repeatedly issue an identical failed tool call. "
    "When finished, provide the concise final result and the validation "
    "you performed."
)

# Sorted by name — matches ToolRegistry::definitions()
TOOLS = [
    ("git_diff", "Show the current git diff for the workspace.",
     '{"type":"object","properties":{"cached":{"type":"boolean"}}}'),
    ("git_status", "Show git status for the current workspace.",
     '{"type":"object","properties":{}}'),
    ("list_directory", "List files/directories inside the workspace.",
     '{"type":"object","properties":{"path":{"type":"string"}}}'),
    ("read_file", "Read a UTF-8/text file inside the workspace.",
     '{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}'),
    ("replace_in_file", "Replace exact text inside one workspace file.",
     '{"type":"object","properties":{"path":{"type":"string"},"search":{"type":"string"},'
     '"replace":{"type":"string"},"replace_all":{"type":"boolean"}},'
     '"required":["path","search","replace"]}'),
    ("run_command", "Run an allow-listed local build/test/version-control command "
     "inside the workspace with a timeout.",
     '{"type":"object","properties":{"command":{"type":"string"},"timeout_ms":{"type":"integer"}},'
     '"required":["command"]}'),
    ("search_text", "Recursively search workspace text files for a literal string.",
     '{"type":"object","properties":{"query":{"type":"string"},"path":{"type":"string"},'
     '"max_results":{"type":"integer"}},"required":["query"]}'),
    ("write_file", "Write a complete file inside the workspace. Existing files are backed up "
     "before replacement.",
     '{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},'
     '"required":["path","content"]}'),
]


def json_quote(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def tools_openai_json() -> str:
    parts = []
    for name, desc, params in TOOLS:
        parts.append(
            '{"type":"function","function":{'
            f'"name":{json_quote(name)},'
            f'"description":{json_quote(desc)},'
            f'"parameters":{params}'
            "}}"
        )
    return "[" + ",".join(parts) + "]"


def tool_instruction_block() -> str:
    return (
        "You have access to local tools. "
        "Use tools when they are necessary to complete the task. "
        "Do not invent tool results.\n\n"
        "TOOLS:\n"
        + tools_openai_json()
        + "\n\n"
        "When calling a tool, prefer this line form (RawrXD IDE grammar):\n"
        'TOOL_CALL: tool_name {"arg":"value"}\n'
        "Alternatively emit exactly one JSON object:\n"
        '{"name":"tool_name","arguments":{...}}\n'
        "After a tool result is provided, continue from that result. "
        "When the task is complete, answer normally without a tool object."
    )


def render_mistral_agent_prompt() -> str:
    """Match ChatTemplate::renderMistral + withToolSystemMessage + first-turn agent loop."""
    system = SYSTEM + "\n\n" + tool_instruction_block()
    # <s>[INST] system\n\nuser [/INST]
    return f"<s>[INST] {system}\n\n{TASK} [/INST]"


def deep2_encode(text: str, vocab: dict[str, int]) -> list[int]:
    """Faithful port of Deep2::BPETokenizer::Encode (Tokenizer.hpp)."""
    tokens: list[int] = []
    pos = 0
    n = len(text)
    unk = 0
    while pos < n:
        max_len = min(n - pos, 64)
        found = False
        for length in range(max_len, 0, -1):
            sub = text[pos : pos + length]
            tid = vocab.get(sub)
            if tid is not None:
                tokens.append(tid)
                pos += length
                found = True
                break
        if not found:
            hex_tok = f"<0x{ord(text[pos]):02X}>"
            tokens.append(vocab.get(hex_tok, unk))
            pos += 1
    return tokens


def run_llama(prompt_path: Path, extra: list[str]) -> list[int]:
    cmd = [
        str(LLAMA_TOKENIZE),
        "-m", str(MODEL),
        "-f", str(prompt_path),
        "--ids",
        "--log-disable",
        "--no-escape",
        *extra,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (p.stdout or "").strip()
    if p.returncode != 0:
        raise RuntimeError(f"llama-tokenize failed rc={p.returncode}\n{p.stderr}\n{out}")
    # output like [1, 2, 3]
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


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    prompt = render_mistral_agent_prompt()
    prompt_path = OUT / "rendered_agent_prompt.txt"
    prompt_path.write_bytes(prompt.encode("utf-8"))

    r = GGUFReader(str(MODEL))
    pieces = r.get_field("tokenizer.ggml.tokens").contents()
    vocab: dict[str, int] = {}
    for i, t in enumerate(pieces):
        if isinstance(t, bytes):
            t = t.decode("utf-8", "replace")
        vocab[t] = i

    meta35 = pieces[35]
    meta29871 = pieces[29871]
    if isinstance(meta35, bytes):
        meta35 = meta35.decode("utf-8", "replace")
    if isinstance(meta29871, bytes):
        meta29871 = meta29871.decode("utf-8", "replace")

    deep2_ids = deep2_encode(prompt, vocab)

    # Primary: no extra BOS (prompt already starts with <s>); parse specials like llama chat
    llama_ids = run_llama(prompt_path, ["--no-bos"])
    # Also capture with default BOS for diagnostics
    llama_bos = run_llama(prompt_path, [])

    idx = first_diff(deep2_ids, llama_ids)
    sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    def piece(i: int) -> str:
        if i < 0 or i >= len(pieces):
            return "<OOB>"
        t = pieces[i]
        if isinstance(t, bytes):
            t = t.decode("utf-8", "replace")
        return t

    lines = []
    lines.append("TOKENIZER-PARITY-001 / AGENT-E2E-002b")
    lines.append(f"model={MODEL}")
    lines.append(f"rendered_prompt_bytes={len(prompt.encode('utf-8'))}")
    lines.append(f"rendered_prompt_sha256={sha}")
    lines.append(f"template_family=mistral (arch=llama detectFamily)")
    lines.append(f"tokens[35]={meta35!r}")
    lines.append(f"tokens[29871]={meta29871!r}")
    lines.append(f"deep2_n={len(deep2_ids)}")
    lines.append(f"llama_no_bos_n={len(llama_ids)}")
    lines.append(f"llama_default_n={len(llama_bos)}")
    lines.append(f"deep2_count_35={deep2_ids.count(35)}")
    lines.append(f"llama_count_35={llama_ids.count(35)}")
    lines.append(f"deep2_count_29871={deep2_ids.count(29871)}")
    lines.append(f"llama_count_29871={llama_ids.count(29871)}")
    lines.append(f"first_diff_index={idx}")
    if idx is not None:
        d = deep2_ids[idx] if idx < len(deep2_ids) else None
        l = llama_ids[idx] if idx < len(llama_ids) else None
        lines.append(f"first_diff_deep2_id={d}")
        lines.append(f"first_diff_llama_id={l}")
        lines.append(f"first_diff_deep2_piece={piece(d) if d is not None else None!r}")
        lines.append(f"first_diff_llama_piece={piece(l) if l is not None else None!r}")
        lo = max(0, idx - 3)
        hi = min(max(len(deep2_ids), len(llama_ids)), idx + 8)
        lines.append("context_deep2=" + ",".join(str(x) for x in deep2_ids[lo:hi]))
        lines.append("context_llama=" + ",".join(str(x) for x in llama_ids[lo:hi]))
        lines.append("context_deep2_pieces=" + " | ".join(repr(piece(x)) for x in deep2_ids[lo:hi]))
        lines.append("context_llama_pieces=" + " | ".join(repr(piece(x)) for x in llama_ids[lo:hi]))

    closed = (
        idx is not None
        and idx < len(deep2_ids)
        and idx < len(llama_ids)
        and deep2_ids[idx] == 35
        and llama_ids[idx] == 29871
    )
    lines.append(f"ROOT_CAUSE_CLOSED_SPACE_VS_METASPACE={closed}")
    if deep2_ids.count(35) > 0 and llama_ids.count(35) == 0:
        lines.append("CLASSIFICATION=DEEP2_BYTE_FALLBACK_FOR_ASCII_SPACE")
    elif idx is None:
        lines.append("CLASSIFICATION=TOKEN_IDS_MATCH")
    else:
        lines.append("CLASSIFICATION=TOKENIZER_MISMATCH_OTHER")

    verdict = "\n".join(lines) + "\n"
    (OUT / "verdict.txt").write_text(verdict, encoding="utf-8")
    (OUT / "deep2_ids.json").write_text(json.dumps(deep2_ids), encoding="utf-8")
    (OUT / "llama_ids_no_bos.json").write_text(json.dumps(llama_ids), encoding="utf-8")
    (OUT / "llama_ids_default.json").write_text(json.dumps(llama_bos), encoding="utf-8")

    # First 80 ids side-by-side for human skim
    with (OUT / "id_head.txt").open("w", encoding="utf-8") as f:
        f.write("pos\tdeep2\tdeep2_piece\tllama\tllama_piece\n")
        for i in range(min(80, max(len(deep2_ids), len(llama_ids)))):
            d = deep2_ids[i] if i < len(deep2_ids) else None
            l = llama_ids[i] if i < len(llama_ids) else None
            f.write(
                f"{i}\t{d}\t{piece(d) if d is not None else ''}\t"
                f"{l}\t{piece(l) if l is not None else ''}\n"
            )

    print(verdict)
    print(f"wrote {OUT}")
    return 0 if closed or (idx is None) else 1


if __name__ == "__main__":
    sys.exit(main())
