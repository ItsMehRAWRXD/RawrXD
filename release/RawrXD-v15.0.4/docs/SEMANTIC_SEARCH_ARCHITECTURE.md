# Semantic Search Architecture

## Overview
Phase 17 introduced "Intent-Aware Intelligence" to the RawrXD IDE. The architecture transitions from pure syntactic Trie matching to a Hybrid Retrieval System.

## Hybrid Retrieval Pipeline
The system operates on a dual-dispatch pattern:
1. **Trie Path:** Exact prefix matching for high-confidence identifiers.
2. **Semantic Path:** FAISS/HNSW vector search for contextual relevance.

**Weighted Fusion Formula:**
$$Score_{final} = \alpha \cdot Score_{Trie} + (1 - \alpha) \cdot Score_{Semantic}$$
*Default $\alpha = 0.75$*

## Memory Management
- **Index:** IVFPQ quantization fits in ~140MB RAM.
- **Cleanup:** All async futures are tracked via `std::atomic<bool> shutdown_requested` and joined in destructors to prevent memory leaks or zombie threads.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    UnifiedAutocompleteEngine                    │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │   Trie      │  │   Semantic   │  │   AST Context Provider  │ │
│  │   Index     │  │   Index      │  │   (Tier 3)              │ │
│  └──────┬──────┘  └──────┬───────┘  └───────────┬─────────────┘ │
│         │                │                      │               │
│         └────────────────┼──────────────────────┘               │
│                          ▼                                      │
│              ┌─────────────────────┐                            │
│              │   Fusion Engine     │                            │
│              │   (Weighted Merge)  │                            │
│              └──────────┬──────────┘                            │
│                         ▼                                       │
│              ┌─────────────────────┐                            │
│              │   Ranked Results    │                            │
│              └─────────────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

## Dual-Backend Index Strategy

### FAISS IVFPQ (Primary)
- **Use case:** Large codebases (10k+ snippets)
- **Memory:** ~140MB for 100k vectors @ 384d
- **Training:** Required after 1000 vectors
- **Latency:** P95 < 3.5ms with nprobe=4

### HNSW (Fallback)
- **Use case:** When FAISS unavailable
- **Memory:** Header-only, no BLAS dependency
- **Training:** Not required
- **Latency:** Comparable to FAISS for small indices

## Thread Safety Model

```cpp
// PIMPL pattern ensures ABI stability
class UnifiedAutocompleteEngine {
    class Impl;  // Implementation hidden
    std::unique_ptr<Impl> m_impl;
};

// Shutdown coordination
std::atomic<bool> shutdown_requested{false};
std::mutex futures_mutex;
```

## Latency Guard

Hard limits enforced via `std::future::wait_for()`:
- **Tier 1 (Trie):** 3ms budget
- **Tier 2 (Semantic):** 10ms budget
- **Tier 3 (AST):** 50ms budget

Early termination triggers when Trie returns 10+ exact matches.

## Configuration Tuning

| Parameter | Default | Range | Impact |
|-----------|---------|-------|--------|
| `alpha` | 0.75 | 0.0-1.0 | Trie vs Semantic weight |
| `nprobe` | 4 | 1-16 | FAISS search depth vs speed |
| `max_memory_mb` | 512 | 128-2048 | Index size limit |
| `min_score_threshold` | 0.7 | 0.5-0.95 | Result quality filter |

## Extending the Architecture

### Adding a New Embedding Model
1. Update `EmbedderConfig::embedding_dimension`
2. Ensure ONNX model outputs compatible tensor shape
3. Adjust `SemanticIndexConfig::vector_dimension` to match

### Swapping Index Types
Modify `SemanticIndexConfig::index_type`:
- `"IVF"` → FAISS IVFPQ
- `"HNSW"` → HNSWlib
- `"FLAT"` → Brute force (debug only)

## References
- `src/semantic_index/SemanticCodeIndex.h`
- `src/semantic_index/CodeEmbedder.h`
- `src/autocomplete_integration/UnifiedAutocompleteEngine.h`
