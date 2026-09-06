// ============================================================================
// KEEP IT SIMPLE — W0 critical path only (everything else is later)
// ============================================================================
//   1. W0-IR          (UniversalIR + Types)
//   2. Workspace      (KnowledgeCompiler::ingestSourceFile)
//   3. Intent         (compileQuery → TaskKind / NEED_INPUT)
//   4. AST synth      (CHANGE_LITERAL / EditOp stand-in)
//   5. Repair/evidence(structural verify + ledger)
//   6. HexMag binder  (W0HexMagBridge → allowFinal + isAllowedFinalClaim)
//
// NOT in MVP: rule induction, BM25, geographic indexes, multi-domain packs,
// Deep2 tensors, CMakeLists.ide.txt. Those layer onto a working loop.
// ============================================================================
