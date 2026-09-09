# GEMMA4_LAYER_TOPOLOGY_BIND_DROP_003

## Purpose

Gemma4 E4B is now past raw GGUF/model-open geometry. The remaining blocker is not `token_embd` and not the previous `Gemma4SchemaBinder` root mapping. It is a per-layer topology mismatch:

```text
GEMMA4_SCHEMA_BINDER=GEOM_READY
MODEL_OPEN=PASS
AUTHORITY_LADDER=BLOCKED
BLOCKED_AT=attn_q
CAUSE=BindLlamaSchema assumes every layer is llama split-attention
OBSERVED=blk.0.proj.weight; odd layers may expose blk.N.attn_q.weight
```

This drop adds a per-layer topology binder:

```text
split_attention        = attn_q + attn_k + attn_v + attn_o
fused_qkv_attention    = attn_qkv + attn_o
projector_block        = proj.weight, no split q/k/v requirement
```

`blk.N.proj.weight` is stored in the existing `wqkv` slot to avoid ABI changes. Runtime execution must enter the explicit projector block before normal attention.

## Apply

Copy:

```text
Gemma4LayerTopologyBind.hpp
```

into:

```text
G:\~dev\rawrxd\src\deep2\Gemma4LayerTopologyBind.hpp
```

Patch:

```text
G:\~dev\rawrxd\src\deep2\Deep2Engine.cpp
```

using the contextual patch:

```text
GEMMA4_LAYER_TOPOLOGY_BIND_DROP_003.patch
```

## Build

No full InferenceEngine rebuild required when only `Deep2Engine.cpp.obj` changes. Recompile the object, replace the library member, then relink parity.

```powershell
cmake --build build-fd --target InferenceEngine -j 1

$libexe = "${env:VCToolsInstallDir}bin\Hostx64\x64\lib.exe"
& $libexe /nologo `
  /REPLACE:Deep2Engine.cpp.obj `
  "G:\~dev\rawrxd\build-fd\InferenceEngine.lib" `
  "G:\~dev\rawrxd\build-fd\src\deep2\CMakeFiles\InferenceEngine.dir\Deep2Engine.cpp.obj"

cmake --build build-fd --target deep2_streamer_parity -j 1
```

## Expected Gemma4 receipt

```text
GEMMA4_LAYER_TOPOLOGY_BIND ok=1 why=GEOM_READY_NON_UNIFORM_PROJECTOR
GEMMA4_PROJECTOR_LAYER_EXEC=1
AUTHORITY_LADDER=PASS
MODEL_OPEN=PASS
TOKENS_COMMITTED>=1
PROMOTE=0
```

## Authority rule

Do not promote the model until Gemma4 emits its own runtime receipt. This drop only allows the next real blocker to surface.
