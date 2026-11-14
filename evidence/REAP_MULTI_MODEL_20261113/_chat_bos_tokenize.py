import json
from pathlib import Path

out = Path(r"F:\rawrxd\evidence\REAP_MULTI_MODEL_20261113")
gguf_path = (
    r"F:\OllamaModels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M"
    r"\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf"
)

import gguf
from tokenizers import Tokenizer
from tokenizers.models import BPE

r = gguf.GGUFReader(gguf_path)


def get_str(key):
    f = r.get_field(key)
    if f is None:
        return None
    try:
        return bytes(f.data[0]).decode("utf-8", errors="replace")
    except Exception as e:
        return f"ERR:{e}"


def get_int(key):
    f = r.get_field(key)
    if f is None:
        return None
    try:
        return int(f.data[0])
    except Exception:
        return None


vals = {
    "tokenizer.ggml.bos_token_id": get_int("tokenizer.ggml.bos_token_id"),
    "tokenizer.ggml.eos_token_id": get_int("tokenizer.ggml.eos_token_id"),
    "tokenizer.chat_template": get_str("tokenizer.chat_template"),
    "minimax-m2.expert_gating_func": get_int("minimax-m2.expert_gating_func"),
    "tokenizer.ggml.pre": get_str("tokenizer.ggml.pre"),
    "general.architecture": get_str("general.architecture"),
}
chat = vals.get("tokenizer.chat_template") or ""
bos = vals.get("tokenizer.ggml.bos_token_id")
eos = vals.get("tokenizer.ggml.eos_token_id")
print(
    "bos",
    bos,
    "eos",
    eos,
    "gating",
    vals.get("minimax-m2.expert_gating_func"),
    "chat_len",
    len(chat),
)

fmt = (
    "]~!b[]~b]system\n"
    "You are a helpful assistant. Your name is MiniMax-M2.7 and is built "
    "by MiniMax.[e~[\n"
    "]~b]user\n"
    "Hello[e~[\n"
    "]~b]ai\n"
    "<think>\n"
)
raw = "Hello"
(out / "CHAT_BOS_FORMATTED_HELLO_BUILTIN.txt").write_text(fmt, encoding="utf-8")
(out / "CHAT_BOS_RAW_HELLO.txt").write_text(raw, encoding="utf-8")

tokens_field = r.get_field("tokenizer.ggml.tokens")
merges_field = r.get_field("tokenizer.ggml.merges")
vocab = {}
if tokens_field is not None:
    for i, t in enumerate(tokens_field.data):
        s = bytes(t).decode("utf-8", errors="surrogateescape")
        vocab[s] = i

merges = []
if merges_field is not None:
    for m in merges_field.data:
        s = bytes(m).decode("utf-8", errors="replace")
        parts = s.split(" ")
        if len(parts) == 2:
            merges.append(tuple(parts))

markers = [
    "]~!b[",
    "]~b]system",
    "[e~[",
    "]~b]user",
    "]~b]ai",
    "<think>",
    "Hello",
    "\n",
]
marker_ids = {m: vocab.get(m) for m in markers}
print("MARKER_IDS", marker_ids)

enc_raw = enc_fmt = jinja_ids = None
rendered = None
bpe_note = None
try:
    model = BPE(vocab=vocab, merges=merges, unk_token=None, fuse_unk=False)
    tok = Tokenizer(model)
    enc_raw = tok.encode(raw)
    enc_fmt = tok.encode(fmt)
    print("BPE_RAW", enc_raw.ids, "n", len(enc_raw.ids))
    print("BPE_FMT", enc_fmt.ids[:80], "n", len(enc_fmt.ids))
except Exception as e:
    bpe_note = f"BPE_BUILD_FAIL {type(e).__name__}: {e}"
    print(bpe_note)

try:
    import jinja2

    env = jinja2.Environment()
    tmpl = env.from_string(chat)
    rendered = tmpl.render(
        messages=[{"role": "user", "content": "Hello"}],
        add_generation_prompt=True,
        tools=None,
    )
    (out / "CHAT_BOS_FORMATTED_HELLO_JINJA.txt").write_text(
        rendered, encoding="utf-8"
    )
    print("JINJA_LEN", len(rendered))
    print("JINJA_HEAD", repr(rendered[:220]))
    print("JINJA_TAIL", repr(rendered[-140:]))
    if "tok" in dir():
        enc_j = tok.encode(rendered)
        jinja_ids = enc_j.ids
        print("BPE_JINJA", jinja_ids[:80], "n", len(jinja_ids))
except Exception as e:
    print("JINJA_FAIL", type(e).__name__, e)

# Prefill position vectors: 0..n-1
def positions(n):
    return list(range(n)) if n else []


raw_ids = list(enc_raw.ids) if enc_raw is not None else None
fmt_ids = list(enc_fmt.ids) if enc_fmt is not None else None
result = {
    "schema": "rawrxd.chat_bos_token_compare.v1",
    "PROMOTE": 0,
    "CERTIFIED": 0,
    "CROSS_SHA": 0,
    "gguf": gguf_path,
    "bos_token_id": bos,
    "eos_token_id": eos,
    "add_bos_token_kv": "ABSENT",
    "add_eos_token_kv": "ABSENT",
    "expert_gating_func": vals.get("minimax-m2.expert_gating_func"),
    "tokenizer.ggml.pre": vals.get("tokenizer.ggml.pre"),
    "chat_template_len": len(chat),
    "raw_prompt": raw,
    "builtin_formatted_prompt": fmt,
    "jinja_formatted_prompt_len": len(rendered) if rendered else None,
    "marker_ids_exact_vocab_lookup": marker_ids,
    "bpe_without_minimax_pre_tokenizer": {
        "note": (
            "Offline BPE encode lacks tokenizer.ggml.pre=minimax-m2 rules; "
            "IDs are approximate vs Deep2 Spm::encode. Counts still bound "
            "chat vs raw divergence."
        ),
        "error": bpe_note,
        "raw_token_ids": raw_ids,
        "raw_token_count": len(raw_ids) if raw_ids is not None else None,
        "raw_prefill_positions": positions(len(raw_ids) if raw_ids else 0),
        "builtin_formatted_token_ids": fmt_ids,
        "builtin_formatted_token_count": len(fmt_ids) if fmt_ids is not None else None,
        "builtin_formatted_prefill_positions": positions(
            len(fmt_ids) if fmt_ids else 0
        ),
        "jinja_formatted_token_ids": jinja_ids,
        "jinja_formatted_token_count": len(jinja_ids) if jinja_ids is not None else None,
        "jinja_formatted_prefill_positions": positions(
            len(jinja_ids) if jinja_ids else 0
        ),
    },
    "runtime_measured": {
        "NEOX_F50B94E6_Hello_prompt_tokens": 1,
        "NEOX_F50B94E6_R256_Hello_prompt_tokens": 1,
        "NEOX_F50B94E6_CHAT_prompt_tokens": 9,
        "historical_ChatTemplate_Forced_minimax_prompt_tokens": 50,
        "interpretation": (
            "Sealed NEOX Hello/R256 prefill=1 matches raw 'Hello' path, "
            "NOT full chat template (builtin/jinja >> 1). NEOX_CHAT=9 is "
            "partial/alternate control, still << historical 50."
        ),
    },
    "parity": {
        "RAW_VS_FORMATTED_TOKEN_IDS": "DIVERGENT_BY_CONSTRUCTION",
        "RUNTIME_APPLIED_CHAT_TEMPLATE_ON_NEOX_HELLO": 0,
        "BOS_PREFIX_OBSERVED_ON_NEOX_HELLO": 0,
        "EXACT_SPM_IDS_ON_SEALED_EXE": "NOT_RUN",
        "PASS": 0,
    },
}
(out / "CHAT_BOS_TOKEN_COMPARE.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
)
print("WROTE CHAT_BOS_TOKEN_COMPARE.json")
