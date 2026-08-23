# VAL-051.7 — Extra A: Thread/Concurrency Contract

## Document Identity
- **Extra:** A
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Single-Threaded Phase (Current)

The `ResidencyManager` uses `std::mutex` for thread safety, but the current forward path is single-threaded per sequence.

### Rules
1. One forward operation at a time per engine instance.
2. Leases are not thread-safe for concurrent use.
3. Counter updates are atomic (via `std::atomic` in `ResidencyCounters`).

### Future Multi-Threaded Considerations
- Batch processing: multiple sequences share weights, each with independent KV cache.
- Weight residency can be shared across sequences (read-only).
- KV cache residency is per-sequence (not shared).
- Lease ownership must be per-sequence or per-thread.

## Tests
- [ ] Concurrent acquire/release on different tensors (if supported)
- [ ] Teardown during outstanding lease (must not crash)
