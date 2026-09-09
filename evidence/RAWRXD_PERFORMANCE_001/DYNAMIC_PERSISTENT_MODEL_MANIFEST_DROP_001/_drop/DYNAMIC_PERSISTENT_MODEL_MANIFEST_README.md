# Dynamic Persistent Model Manifest Drop 001

Purpose: replace static example manifests with per-model digestion streams.

Rule:
- The model location/path is the only stable user-supplied locator.
- Architecture, dimensions, root tensors, layer topology, quant histogram, authority, and blocked_at are discovered from the specific model file/shards.
- Persisted manifests are keyed by path + fingerprint, so Gemma4/Phi3/DSR1 do not inherit schema from each other.
- Runtime observations use a transient overlay and do not rewrite discovery facts.

Integration:
1. Copy `DynamicPersistentModelManifest.hpp` to `src/deep2/DynamicPersistentModelManifest.hpp`.
2. Include it in `Deep2Engine.cpp` after the existing schema binder headers.
3. After `ggufResult = std::move(result);`, call:

```cpp
auto dynManifest = rawr::manifest_dyn::DigestLoadedModel(
    firstShard.string(), ggufResult, stderr);
```

4. Bind model facts from the manifest before legacy `BindLlamaSchema` checks.

Receipt expected:

```text
MODEL_DIGESTION_STREAM_BEGIN=1
MODEL_PATH=<dynamic path>
ARCH=<derived>
HIDDEN=<derived> LAYERS=<derived> HEADS=<derived> KV_HEADS=<derived> HEAD_DIM=<derived> VOCAB=<derived>
SPLIT_QKV_LAYERS=<derived>
FUSED_QKV_LAYERS=<derived>
PROJECTOR_BLOCK_LAYERS=<derived>
MLA_LAYERS=<derived>
MANIFEST_READY=<0|1>
AUTHORITY_CLASS=DISCOVERY_ONLY
PROMOTE=0
MODEL_DIGESTION_STREAM_END=1
```
