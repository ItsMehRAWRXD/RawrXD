# Product hook map — fail closed

These hooks complete the live measurement path without changing scheduling or residency behavior.
They are accounting only. Do not turn a miss into a hit, do not suppress copies, and do not reuse
any buffer solely to improve the gate.

## 1. Existing streamed weight hit/miss path

`src/deep2/GpuTransferCounters.hpp` already passes `bytes` to both:

```cpp
GpuTransfer_NoteWeightHit(uint64_t bytes)
GpuTransfer_NoteWeightMiss(uint64_t bytes, bool firstEver)
```

Add:

```cpp
#include "Deep2Locality64.hpp"

// in NoteWeightHit:
Locality64_NoteDemand(LocalityKind::Weight, bytes, true);

// in NoteWeightMiss:
Locality64_NoteDemand(LocalityKind::Weight, bytes, false);
```

Do not derive local bytes from hit *count*. Use the byte argument.

## 2. Q6_K dedicated logits path

Current sealed path is `src/vulkan_fwd_q6k_host.cpp::DispatchGEMVQ6kPacked`.
Immediately after `hit` is known:

```cpp
Deep2::Locality64_NoteDemand(Deep2::LocalityKind::Weight, bytes, hit);
```

The content-fingerprint hit-skip remains untouched. This hook only observes the same decision that
sealed RESIDENCY. The current sealed branch has a real `hit` predicate and uploads only on miss.

## 3. Host-to-device transport

At the lowest common upload/copy call already responsible for `GpuTransfer_NoteCopy`, add exactly
one:

```cpp
Locality64_NoteHostToDevice(bytes, decode_token_is_on_critical_path);
```

Do not add the same bytes again at the Q6_K caller if the common upload layer already records them.
The gate must reject double accounting.

## 4. KV demand

At the actual KV read/write residency decision, record bytes consumed by the decode token:

```cpp
Locality64_NoteDemand(LocalityKind::KV, kv_bytes, kv_is_device_local);
```

`kv_is_device_local` means no new host/inter-device fetch is required for those bytes for this token.

## 5. Activation/reduction demand

Only record bytes crossing a residency boundary. Scratch already local to the executing GPU is local.
Use `Activation` or `Reduction`; do not count arithmetic reads repeatedly if they never change tier.

## 6. Inter-GPU traffic

At each real peer/staged GPU0<->GPU1 transfer:

```cpp
Locality64_NoteInterGpu(bytes);
```

Zero is valid if the architecture performs independent local work with no inter-device transfer.

## 7. Same-token overlap

At the true GPU forward start/end timestamps (QPC or existing monotonic ns conversion), call:

```cpp
Locality64_NoteGpuForwardSpan(slot, measured_token_ordinal, start_ns, end_ns);
```

The collector counts overlap only when GPU0/GPU1 intervals intersect for the same ordinal.
Do not substitute "both forward counts nonzero" for same-token overlap.

## 8. Window discipline

Warm token 1 is outside the authority window. After its existing residency snapshot:

```cpp
auto& L = Locality64_Global();
L.reset();
L.setArmed(true);
L.beginWindow(now_ns());
```

Measure tokens 2..65 as ordinals 0..63, then `endWindow(now_ns())`.
Receipt reports `GENERATED_TOKENS=64` and may also report `RAW_GENERATED_TOKENS=65`.

## 9. Parent regression snapshot

Reuse the exact RESIDENCY counters before and after the 64-token window. Populate:

- `weight_upload_delta`
- `device_create_delta`
- `model_load_delta`
- `reload_bytes_delta`
- `pin_evict_delta`

Any nonzero delta makes the locality conjunction fail. A roofline PASS cannot reopen or weaken
RESIDENCY law.
