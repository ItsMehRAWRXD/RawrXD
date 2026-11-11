# Semantic Search API Reference

## UnifiedAutocompleteEngine

Primary interface for intent-aware code completion.

### Construction
```cpp
UnifiedAutocompleteEngine engine(config);
```

### Methods

#### `get_completions(const CursorContext& cursor)`
**Purpose:** Primary entry point for autocomplete requests.

**Parameters:**
- `cursor` — Current cursor position and context

**Returns:** `std::vector<UnifiedCompletion>` — Ranked completion candidates

**Latency:** P95 < 3.5ms under normal load

---

#### `classify_query(const CursorContext& cursor)`
**Purpose:** Determine optimal completion strategy.

**Returns:** `QueryType` — FAST_PREFIX, SEMANTIC, or CONTEXT_AWARE

**Usage:**
```cpp
auto qtype = engine.classify_query(cursor);
if (qtype == QueryType::FAST_PREFIX) {
    // Use trie-only for speed
}
```

---

#### `get_stats()`
**Purpose:** Retrieve telemetry statistics.

**Returns:** `Stats` struct containing:
- `total_queries` — Total autocomplete requests
- `trie_hits` — Trie-only completions served
- `semantic_hits` — Vector search completions served
- `hybrid_fusion_count` — Both paths triggered
- `timeout_count` — Semantic search timeouts
- `avg_latency_ms` — Average query latency
- `cache_hit_rate` — Embedding cache efficiency

---

## SemanticCodeIndex

Vector-based code snippet storage and retrieval.

### Construction
```cpp
SemanticIndexConfig config;
config.vector_dimension = 384;
config.index_nlist = 100;
SemanticCodeIndex index(config);
```

### Methods

#### `add_snippet(const std::string& snippet, const std::string& metadata)`
**Purpose:** Index a code snippet for semantic search.

**Parameters:**
- `snippet` — Code text to index
- `metadata` — File path, line number (JSON format)

**Returns:** `int64_t` — Unique snippet ID

**Note:** Triggers training when buffer reaches 1000 vectors (FAISS only)

---

#### `semantic_search(const std::string& intent_query, int top_k, float min_score)`
**Purpose:** Search for semantically similar code.

**Parameters:**
- `intent_query` — Natural language query (e.g., "async file I/O")
- `top_k` — Maximum results to return (default: 5)
- `min_score` — Minimum similarity threshold (default: -1 = use config)

**Returns:** `std::vector<ScoredSnippet>` — Ranked results

---

#### `search_with_budget(const std::string& query, int budget_ms, int top_k)`
**Purpose:** Time-bounded semantic search for real-time use.

**Parameters:**
- `budget_ms` — Maximum allowed latency
- `top_k` — Maximum results

**Returns:** Results within budget (may be empty if timeout)

---

#### `is_trained()`
**Purpose:** Check if IVFPQ index is trained (FAISS only).

**Returns:** `bool` — true if ready for search

---

#### `training_buffer_size()`
**Purpose:** Get number of vectors awaiting training.

**Returns:** `size_t` — Buffer size (triggers training at 1000)

---

#### `memory_usage()`
**Purpose:** Get current memory footprint.

**Returns:** `size_t` — Bytes used by index

---

## CodeEmbedder

ONNX Runtime-based code embedding engine.

### Construction
```cpp
EmbedderConfig config;
config.model_path = "models/all-MiniLM-L6-v2.onnx";
config.embedding_dimension = 384;
CodeEmbedder embedder(config);
```

### Methods

#### `Embed(std::string_view code)`
**Purpose:** Transform code into semantic vector.

**Pipeline:**
1. Tokenize using WordPiece/BPE
2. Create ONNX input tensors
3. Run inference for hidden states
4. Mean pool to 384-d vector
5. L2 normalize

**Parameters:**
- `code` — Source code snippet

**Returns:** `std::vector<float>` — 384-dimensional normalized embedding

**Latency:** ~5-15ms depending on sequence length

---

#### `PreloadModel()`
**Purpose:** Eagerly load ONNX model into memory.

**Returns:** `bool` — true if loaded successfully

**Usage:** Call during IDE startup to avoid cold-start latency

---

#### `IsLoaded()`
**Purpose:** Check if model is ready.

**Returns:** `bool` — true if ONNX session active

---

#### `GetLastLatencyMs()`
**Purpose:** Get last inference timing.

**Returns:** `float` — Milliseconds for last Embed() call

---

## Configuration Structures

### UnifiedAutocompleteConfig
```cpp
struct UnifiedAutocompleteConfig {
    int fast_prefix_budget = 3;      // Trie latency limit (ms)
    int semantic_budget = 10;        // Vector search limit (ms)
    int context_aware_budget = 50;   // AST+Semantic limit (ms)
    float semantic_min_score = 0.7f; // Minimum relevance
    int max_completions = 10;        // Results to return
    bool enable_semantic = true;     // Toggle vector search
    bool enable_ast = true;          // Toggle AST analysis
    bool enable_trie = true;         // Toggle prefix matching
    std::string model_path;          // ONNX model location
};
```

### SemanticIndexConfig
```cpp
struct SemanticIndexConfig {
    int vector_dimension = 384;        // Embedding size
    int index_nlist = 100;             // IVF clusters
    int nprobe = 4;                    // Search clusters
    float min_score_threshold = 0.7f; // Result filter
    size_t max_memory_mb = 512;       // Memory limit
    bool use_quantization = true;      // Enable IVFPQ
    std::string index_type = "IVF";   // Backend selection
};
```

### EmbedderConfig
```cpp
struct EmbedderConfig {
    std::string model_path;            // ONNX model file
    std::string tokenizer_vocab_path; // Vocabulary file
    int max_sequence_length = 512;   // Token limit
    int embedding_dimension = 384;   // Output size
    bool use_gpu = false;              // GPU inference
    int intra_op_threads = 4;          // ONNX parallelism
    int inter_op_threads = 1;        // Inter-op threads
};
```

## Error Handling

All methods return empty results or false on failure:
- Check `is_initialized()` / `IsLoaded()` before use
- Monitor `get_stats().timeout_count` for performance issues
- Verify `memory_usage()` stays within budget

## Thread Safety

- **UnifiedAutocompleteEngine:** Thread-safe for queries, not for config changes
- **SemanticCodeIndex:** Thread-safe for concurrent searches, lock for add/remove
- **CodeEmbedder:** Thread-safe for concurrent Embed() calls

## Example Usage

```cpp
// Initialize
UnifiedAutocompleteConfig config;
config.model_path = "models/codebert.onnx";
UnifiedAutocompleteEngine engine(config);
engine.initialize();

// Query
CursorContext ctx;
ctx.file_path = "main.cpp";
ctx.line = 42;
ctx.current_word = "async";

auto completions = engine.get_completions(ctx);
for (const auto& c : completions) {
    std::cout << c.text << " (score: " << c.score << ")\n";
}

// Telemetry
auto stats = engine.get_stats();
std::cout << "Avg latency: " << stats.avg_latency_ms << "ms\n";
```
