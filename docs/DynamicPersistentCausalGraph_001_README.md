# RawrXD Dynamic Persistent Causal Graph State

This source drop separates the runtime into two planes:

```text
IMMUTABLE PLANE
  model addresses
  graph nodes
  dependency edges
  kernel bindings
  tensor bindings

DYNAMIC PERSISTENT PLANE
  token step
  position
  KV cursor
  sampling state
  configurable kernel parameters
  other explicitly declared state values
```

The graph never needs to be rebuilt merely because decode state changes.

## Core law

```text
GRAPH_TOPOLOGY_MOVEMENT=0
DEPENDENCY_EDGE_MOVEMENT=0
BINDING_MOVEMENT=0

DYNAMIC_VALUE_MUTATION=1
DYNAMIC_VALUE_PERSISTENCE=1
DYNAMIC_VALUE_CONFIGURATION=1
DYNAMIC_VALUE_DECODING=1
```

## Persistent value schema

Each value has:

```text
stable id
type
flags
current value
default
minimum
maximum
```

Flags distinguish:

- configurable values
- persistent values
- runtime-only values
- read-only values
- per-token values
- per-layer values
- per-sequence values

## Snapshot

`SaveSnapshot()` writes a compact binary state image containing only values marked persistent and not runtime-only.

Header contains:

```text
magic
version
graph_hash
state generation
value count
payload hash
```

`LoadSnapshot()` is transactional and can require the exact same graph hash.

This prevents loading decode state into an incompatible causal graph.

## Human configuration

`ApplyConfigFile()` accepts:

```text
decode.max_tokens=256
sample.temperature=0.8
kernel.q_rows=64
kernel.qa_rows=64
kernel.qkv_rows=64
```

Names are converted to stable 64-bit IDs. Hex/decimal IDs are also accepted.

## Decodeable state

`DumpDecoded()` emits TSV with:

```text
id
type
flags
current
default
min
max
```

This lets evidence tooling inspect state without interpreting raw memory.

## Intended RawrXD integration

At model/session seal:

1. Build immutable causal graph.
2. Declare all legal dynamic values.
3. Load optional configuration.
4. Load matching persistent state if resuming.
5. Bind kernels/tensors.
6. Enter generation.

During generation:

```text
read persistent values
execute fixed graph
mutate only declared dynamic values
```

At checkpoint/end:

```text
SaveSnapshot()
```

No tensor-name lookup, graph rebuild, allocator activity, or policy discovery is required because a dynamic value changed.
