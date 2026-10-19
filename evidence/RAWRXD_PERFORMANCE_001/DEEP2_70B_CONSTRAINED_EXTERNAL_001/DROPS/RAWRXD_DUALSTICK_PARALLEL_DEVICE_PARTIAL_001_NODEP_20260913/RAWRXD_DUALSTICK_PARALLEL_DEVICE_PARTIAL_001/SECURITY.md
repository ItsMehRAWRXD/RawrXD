# Concurrency / lifetime rules

1. Each `VulkanCompute` instance is owned by exactly one stick worker while the layer is in flight.
2. A worker may not dereference a residency handle after eviction/generation change.
3. First-touch metadata mutation must be serialized; hit-only GPU execution must not be globally serialized.
4. Worker-visible counters are private to the worker or atomic. Merge occurs after join.
5. On any worker exception/failure, join all started threads, call backend abort, and do not modify final `accum`.
6. Device partial handles are opaque and valid only between `BeginLayer` and `EndLayer`/`AbortLayer`.
7. Product authority requires explicit backend attestation; simulators must return false.
8. No detached threads. No background lifetime beyond `RunLayer`.
