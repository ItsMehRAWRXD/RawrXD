# Phase 17 Implementation Kickoff
## Week 1: Build Infrastructure + Parallel Prototyping

### Day 1-2: Build Infrastructure (Priority: P0)
**Goal:** Establish FAISS/tree-sitter dependency management

**Tasks:**
1. Create CMake ExternalProject for FAISS (with HNSW fallback)
2. Integrate tree-sitter as git submodule (header-only)
3. Update CI/CD pipeline for new dependencies
4. Create dependency smoke test

**Success Criteria:**
- Clean build with `ninja deps` target
- HNSW fallback compiles if FAISS unavailable
- CI build time < 20% increase

### Day 3-5: Semantic Index Prototype (Priority: P0)
**Goal:** Implement basic vector search with memory constraints

**Tasks:**
1. Create SemanticCodeIndex stub with HNSW
2. Implement memory-mapped index loading
3. Add query classification logic
4. Integrate with existing Trie autocomplete

**Success Criteria:**
- Semantic query < 10ms P95
- Memory overhead < 512MB
- Trie autocomplete remains < 3ms P95

### Week 2-3: AST Integration (Priority: P0)
**Goal:** Replace mock context with tree-sitter AST

**Tasks:**
1. Integrate tree-sitter C/C++ parser
2. Implement incremental AST updates
3. Create ASTContextProvider
4. Wire to RAG query pipeline

**Success Criteria:**
- AST parse < 50ms incremental
- Scope-aware suggestions working
- No UI blocking during parse

### Week 4: Maintenance Sprint (Priority: P1)
**Goal:** Eliminate BG_THREAD_AV entries

**Tasks:**
1. Fix session cleanup race condition
2. Harden telemetry flush synchronization
3. Fix mutex unlock in exception handler
4. Full regression test

**Success Criteria:**
- 0 BG_THREAD_AV entries
- Clean logs for 24h soak test
- All smoke tests passing

## Risk Mitigation Strategy

### FAISS Build Risk
- **Mitigation:** HNSW header-only fallback
- **Trigger:** If FAISS build fails after 2 days
- **Action:** Switch to HNSW-only for Week 1

### Memory Risk
- **Mitigation:** Hard 512MB limit with IVFPQ
- **Trigger:** If index > 512MB during testing
- **Action:** Enable aggressive quantization

### Latency Regression Risk
- **Mitigation:** Trie remains Tier 1, async semantic
- **Trigger:** If Trie P95 > 3ms
- **Action:** Disable semantic search, investigate

## Success Metrics

| Week | Target | Measurement |
|------|--------|-------------|
| 1 | Build clean | ninja deps passes |
| 1 | HNSW prototype | < 10ms query |
| 2 | AST integration | < 50ms parse |
| 3 | Full pipeline | Intent > 85% |
| 4 | 0 BG_THREAD_AV | Clean logs |

## Executive Checkpoint

**Week 1 Review:**
- Build infrastructure stable?
- HNSW prototype functional?
- Memory within budget?

**Go/No-Go Decision:** End of Week 1
- GO: Proceed to full FAISS integration
- NO-GO: Continue with HNSW, defer FAISS

**Authorized:** Phase 17 Kickoff
**Date:** 2026-06-20
**Lead:** Core RAG Team + IDE Integration Team
