# MODEL_PROVENANCE_MISMATCH_DROP_001

## Purpose

Fix the current owner:

```text
CURRENT_OWNER=PROVENANCE_MISMATCH
PROMOTE=0
```

The model location can be stable. Everything else must be digested from the exact model file/shard set and persisted under that model fingerprint.

## Authority law

```text
MODEL_LOCATION = stable locator
SCHEMA_FACTS   = dynamically digested
TOPOLOGY_FACTS = dynamically digested
RUNTIME_FACTS  = transient overlay
NO_SCHEMA_INHERITANCE = 1
```

## Install

Copy headers:

```text
src/deep2/ModelProvenanceSeal.hpp
src/deep2/ManifestRuntimeOverlay.hpp
```

Add includes in `Deep2Engine.cpp` after the dynamic manifest include:

```cpp
#include "ModelProvenanceSeal.hpp"
#include "ManifestRuntimeOverlay.hpp"
```

Wire after `GGUFLoader::Load` and after the schema/alias binders, before the authority ladder returns PASS.

## Expected receipt

```text
MODEL_PROVENANCE_BEGIN=1
MODEL_EXISTS=1
MODEL_LOCATOR_HASH=<dynamic>
TENSOR_NAME_SHAPE_HASH=<dynamic>
MODEL_EXPECTED_FP=<dynamic>
DIGEST_FP=<same>
MANIFEST_FP=<same or not-loaded>
BIND_FP=<same>
AUTHORITY_FP=<same>
RUNTIME_FP=<same>
MODEL_PROVENANCE_MATCH=1
BLOCKED_AT=NONE
WHY=SAME_MODEL_FINGERPRINT
AUTHORITY_CLASS=DISCOVERY_PROVENANCE
PROMOTE=0
MODEL_PROVENANCE_END=1
```

## If it fails

```text
BLOCKED_AT=PROVENANCE_MISMATCH
WHY=MANIFEST_FINGERPRINT_MISMATCH
```

means the persisted manifest is stale for that path.

```text
WHY=BIND_FINGERPRINT_MISMATCH
```

means the binder consumed aliases or topology from a different manifest/model family.

```text
WHY=INHERITED_SCHEMA_AUTHORITY
```

means llama/Phi/Gemma assumptions were promoted without being proven by this exact model digest.

## Correct interpretation

This drop can clear provenance authority. It cannot certify runtime generation. Runtime PASS still requires a model-specific runtime receipt.
