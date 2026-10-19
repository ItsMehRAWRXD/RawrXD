# Security and production-hardening notes

## Trust boundaries

`EnterpriseDualStickLocality` treats model tensor bytes, backend handles, device callbacks, and router inputs as separate trust boundaries. It does not parse GGUF itself and therefore relies on the adapter to validate physical expert slices before copying them into `LoadedExpertBundle`.

## Memory/lifetime rules

- Host staging bytes are owned by `std::vector<uint8_t>` inside shared cache entries.
- Resident entries retain a shared owner of host staging so pointers handed to `EnsureBundle` cannot dangle while residency exists.
- Device handles are opaque and must be released through `ReleaseBundle` on LRU eviction, `ClearCaches`, or destruction.
- Gate/Up/Down are evicted atomically.
- A resident hit never calls `EnsureBundle` again.
- `ClearCaches` must run before the adapter destroys the GPU/device context.

## Bounds/overflow behavior

- Bundle byte totals use saturating `uint64_t` accounting and invalid overflowed bundles fail validation.
- Stick and staging budgets reject a single bundle that cannot fit.
- `hiddenCount` must fit the backend `uint32_t` dimension range.
- Top-k is statically capped at 16 and runtime-capped by `Config::maxTopK`.
- Duplicate expert IDs and non-finite router weights are rejected.

## Fail-closed execution

- All selected experts are ensured before `BeginLayer`; capacity pressure cannot silently produce partial top-k execution.
- If any acquire fails, the layer returns failure before expert compute.
- Backend begin/submit/reduce failures increment `LAYER_FAILURES` and block authority.
- `AbortLayer` is invoked for backend execution failures when supplied.
- Router IDs/weights/order provenance are fingerprinted before and after execution.
- Mock/selftest backends default to `productBackendAttested=false` and cannot mint performance authority.
- `PROMOTE=0` is invariant in this drop.

## Concurrency

Public engine operations are serialized by an internal mutex. This intentionally favors correctness and deterministic cache ownership over concurrent mutation. GPU work may be asynchronous inside a backend layer, but the backend must honor the `BeginLayer` / grouped `SubmitExpert` / `EndLayerReduce` transaction boundary.

## Adapter obligations

The RawrXD backend must not treat a host pointer as evidence of device residency. `DeviceBundleHandle` must represent a real reusable device allocation/descriptor. Backend telemetry must reflect actual bytes/calls; fabricated counters would invalidate the receipt rather than change core correctness.

## Recommended live validation

Run with page heap / Application Verifier or ASan-equivalent where practical during adapter development, enable Vulkan validation for diagnostic builds, and compare router fingerprints + selected/executed counts on every acceptance gate before measuring performance.
