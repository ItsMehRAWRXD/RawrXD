# Model Locations

Canonical record of **where models physically live on this machine**, so no one
has to guess or re-scan. Every path and size below was measured on this host,
not transcribed from a manifest or a UI listing.

Two rules govern this file:

1. **A path is only listed here if the file was measured to exist.** Manifest
   entries whose weights are absent are listed separately and labelled, because
   a manifest is a *reference*, not an installation.
2. **Sizes are bytes from the filesystem**, cross-checked against the GGUF
   header where the dump authority parsed one.

---

## 1. Roots

| Root | Contents | Notes |
|---|---|---|
| `F:\OllamaModels` | Ollama blob store + ~25 standalone GGUF repos | Primary. Large models live here. |
| `G:\~dev\rawrxd\models` | 7 small GGUFs, the cert/gate test corpus | Working corpus for the parity + template sweeps |
| `F:\models` | 4 GGUFs + `aliases.txt` + `TrueTensorCore.dll` | Ad-hoc |

### Ollama store layout

```text
F:\OllamaModels\manifests\registry.ollama.ai\library\<name>\<tag>   JSON manifest
F:\OllamaModels\blobs\sha256-<digest>                              weight blobs
```

A tag has **no** human-readable filename — the blob is named only by digest.
To get a real path, always ask the dump authority rather than globbing:

```powershell
F:\~dev\build_dump_census\bin\rawr.exe dump "llama3.2:3b" --format json
```

Note: `--format json` prints the JSON **and then** a receipt block on stdout, so
it is not directly pipe-able into `ConvertFrom-Json`. Read the model object, or
use `--format table`.

---

## 2. Ollama models verified on disk

All `exists=true`, sizes read from disk. `tensors` and `quant` come from the
parsed GGUF header, not the Ollama tag string.

| Tag | Arch | Quant | Tensors | Bytes | GB | Blob path (`F:\OllamaModels\blobs\`) |
|---|---|---|---|---|---|---|
| `llama3.2:3b` | llama | Q4_K_M | 255 | 2,019,377,376 | 1.88 | `sha256-dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff` |
| `gemma3:4b` | gemma3 | Q4_K_M | 883 | 3,338,792,448 | 3.11 | `sha256-aeda25e63ebd698fab8638ffb778e68bed908b960d39d0becc650fa981609d25` |
| `qwen3:8b` | qwen3 | Q4_K_M | 399 | 5,225,374,496 | 4.87 | `sha256-a3de86cd1c132c822487ededd47a324c50491393e6565cd14bafa40d0b8e686f` |
| `llama3.1:8b` | llama | Q4_K_M | 292 | 4,920,738,944 | 4.58 | `sha256-667b0c1932bc6ffc593ed1d03f895bf2dc8dc6df21db3042284a6f4416b06a29` |
| `granite3.3:8b` | granite | Q4_K_M | 362 | 4,942,873,344 | 4.60 | `sha256-77bcee066a76dcdd10d0d123c87e32c8ec2c74e31b6ffd87ebee49c9ac215dca` |
| `nemotron-3-nano:4b` | nemotron_h | Q4_K_M | 263 | 2,837,586,496 | 2.64 | `sha256-527db2cf6c705d8fabb95693d038d9c06b4a2b0b8b0a4bbdbd01212d37242970` |
| `qwen2.5-coder:1.5b-base` | qwen2 | Q4_K_M | 338 | 986,048,512 | 0.92 | `sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e` |

Aliases that resolve to the **same** blob (so do not count twice):
`llama3.2:latest` → `llama3.2:3b`; `gemma3:latest` → `gemma3:4b`;
`gpt-oss:20b` → `gpt-oss:latest` (both ID `17052f91a42e`);
`bigdaddyglocal` / `bigdaddyg-productivity-local` → ID `890a6c1859b7`;
`bigdaddygnative` / `bigdaddyg-productivity-native` → ID `02a792bbc286`;
`deepseek-v4-flash:cloud` / `deepseek-v4-flash:0731-cloud` → ID `d3f1c8744721`.

### `F:\models`

```text
F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf
F:\models\Qwen_Offline_Game.gguf
F:\models\Qwen_Production_Final.gguf
F:\models\Qwen_Remixed_Master.gguf
```

---

## 3. Kimi K2 Instruct — present

```text
F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\
    Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf  ... -00013-of-00013.gguf
    13 shards, 578.6 GB total
```

Sharded, so there is **no single file** to point at — a loader needs all 13 in
directory order. Largest shard is 46.15 GB.

There is **no Kimi 2.5 Instruct on this host.** Only K2-Instruct-0905 (K2, 1T).
If a K2.5 reference was expected, it has not been downloaded.

---

## 4. DeepSeek-V3.1 671B — MANIFEST ONLY, NOT DOWNLOADED

This is the one entry that is easiest to get wrong, so it is stated explicitly.

```text
F:\OllamaModels\manifests\registry.ollama.ai\library\deepseek-v3.1\671b
    layers = 4
    model layer: mediaType=application/vnd.ollama.image.model
                 size=404494154496   (376.7 GB)
                 digest=sha256:8eeb1709986060613eb794d3fbbbf4ce7f2120cd174c95b64ee9f0c906c48910

F:\OllamaModels\blobs\sha256-8eeb17...c48910
    EXISTS = False          <-- weights are NOT on disk

F:\OllamaModels\manifests\registry.ollama.ai\library\deepseek-v3.1\671b-cloud
    layers = 0              <-- pure cloud reference, no weights by design
```

So `deepseek-v3.1:671b` is **registered but not installed**. It will not load
and it must not be reported as available. `rawr dump "deepseek-v3.1:671b"`
correctly returns:

```text
SELECTION_STATUS=AMBIGUOUS      (two manifests match: 671b and 671b-cloud)
VERDICT=FAIL_AMBIGUOUS
resolved_path=""  exists=false
```

Use the fully-qualified `deepseek-v3.1:671b` or `:671b-cloud` to disambiguate.

---

## 5. Cloud models — no local weights by definition

These appear in `ollama list` with size `-`. There is nothing to point at.

```text
minimax-m3:cloud          deepseek-v4.1-flash:cloud    deepseek-v4-flash:cloud
glm-5.3-flash:cloud       glm-5.3:cloud                kimi-k2.6:cloud
glm-5.2:cloud             deepseek-v3.1:671b-cloud    deepseek-v4-flash:0731-cloud
```

---

## 6. Standalone GGUF repos under `F:\OllamaModels`

```text
DeepSeek-R1-0528-Qwen3-8B-GGUF/        DeepSeek-R1-GGUF/
DeepSeek-R1-Q4_K_M/                    DeepSeek-R1-Q4_K_M-COMPLETE/
DeepSeek-R1-Recovery/                  gemma-4-31B-it-GGUF/
gemma-4-E4B-it-GGUF/                   GLM-4.7-Flash-GGUF/
Kimi-K2-Instruct-0905-GGUF/            MiniMax-M2.7-Q4_K_M/
NVIDIA-Nemotron-3-Nano-4B-GGUF/        Phi-3-medium-128k-instruct-14B-Q4_K_M/
phi3-mini_local/                       Qwen2.5-Coder-14B-Instruct-Q8_0/
Qwen3.6-27B-Fable-Fusion-711-Heretic-MAX-Q4_K_M/
Qwen3.6-35B-A3B-GGUF/                  Qwen3.8-27B-AD-Q4_K_M/
Qwen3.8-27B-Q4_K_M/                    Qwen3.8-Flash-Next-GGUF/
Qwen3.8-Flash-Next-Q4_K_M/             rawrxd_test_models/
unlocked-350M/                         _r1_iso/
```

Largest single files measured:

```text
 46.30 GB  MiniMax-M2.7-Q4_K_M-00002-of-00003.gguf
 41.76 GB  Qwen3.8-Flash-Next-AD-IQ1_M-M64-00001-of-00002.gguf
 38.68 GB  Qwen3.5-40B-Claude-4.6-Opus-Deckard-Heretic-Uncensored-Thinking.Q8_0.gguf
 36.94 GB  DeepSeek-R1-Q4_K_M-00009-of-00011.gguf
```

BigDaddyG single-file quant variants (36.2 GB each):
`BigDaddyG-UNLEASHED-Q4_K_M.gguf`, `BigDaddyG-NO-REFUSE-Q4_K_M.gguf`,
`BigDaddyG-F32-FROM-Q4.gguf`, plus `BigDaddyG-Q2_K-PRUNED-16GB.gguf` and
`BigDaddyG-Q2_K-ULTRA.gguf`.

---

## 7. Cert / gate test corpus — `G:\~dev\rawrxd\models`

This is the corpus the parity, tokenizer and template sweeps run against.

| File | Role |
|---|---|
| `tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf` | Baselines. The only model that has ever scored clean (3/3). |
| `tinyllama.gguf` | Duplicate of the above |
| `phi3-mini-Q2_K.gguf` | **2-bit.** Control with 14 real role tokens; garbage output is confounded by quantization. |
| `llama3.2-3b-Q2_K.gguf` | 2-bit, split ffn_gate layout. Admitted. |
| `gemma3-1b-Q2_K.gguf` | **Rejected** at admission: `numHeads*headDim != hiddenDim` |
| `DeepSeek-V2-Lite-Chat.Q4_K_M.gguf` | MLA + MoE. Not yet exercised. |
| `model.gguf` | **0 bytes.** Not a model. |

Quality note that matters when reading any sweep result: **Q2_K is not a usable
control.** At 2-bit it produces degenerate repetition and invalid UTF-8, which
is indistinguishable from an engine defect. Use `llama3.2:3b` (Q4_K_M, verified
on disk above) when a control is needed.

---

## 8. Known gaps

Measured by the dump authority on the last full scan:

```text
MODELS_DISCOVERED              = 222
MODELS_CLASSIFIED              = 222
MODELS_WITH_PATH               = 109
MODELS_WITH_UNKNOWN_PATH       = 113   <-- unresolved, see below
DEEP2_COMPATIBLE_COUNT         = 109
OLLAMA_MANIFESTS_SCANNED       = 168
GGUF_FILES_SCANNED             = 75
DUPLICATES_REMOVED             = 21
```

`MODELS_WITH_UNKNOWN_PATH=113` is the outstanding classification task from the
HTTP authority chain. The 113 are dominated by cloud-only tags and
manifest-only entries like the 671B in §4. They are **not** 113 broken files —
they are references with no local weights — but that distinction has not yet
been enumerated per-entry, so the count is recorded here as measured rather
than characterised.

---

## 9. Provenance

Measured on this host via `rawr dump --format json` (model objects) and direct
filesystem reads (sizes, `EXISTS`). Arch, tensor count and quantization are
parsed from GGUF headers by
`RAWRXD_GGUF_METADATA_PROBE_001` / `RAWRXD_RAWR_DUMP_AUTHORITY_001`.

Re-verify with:

```powershell
F:\~dev\build_dump_census\bin\rawr.exe dump "gemma3:4b" --format table
```