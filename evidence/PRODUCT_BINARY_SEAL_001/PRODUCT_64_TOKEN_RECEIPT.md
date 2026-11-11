# PRODUCT_64_TOKEN_RECEIPT

ASOF_UTC=2026-11-02T13:20:00Z
GATE=PRODUCT_64_TOKEN_E2E_CANDIDATE
BUILD_SCOPE=CANDIDATE_ONLY
SOURCE_AUTHORITY=a5ae60efecac790598e2e46d9e499eb8ac7287af
CANDIDATE_EXE=F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build\bin\RawrXD-Win32IDE-Native.exe
CANDIDATE_SHA256=CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB
SHA_MATCH_EXPECT=1

## Attempt
1. Native IDE ChatWindow path (exact hash CB34EF4E…): prompt submitted; Ollama model load PASS for `bigdaddyg-productivity-local:latest` with MAX_OUTPUT_TOKENS=512 — **not** a sealed 64-token product path. UI response / GENERATED_TOKENS / TOKEN_COMMIT not observed before teardown.
2. Candidate build bin: `deep2_benchmark.exe` **ABSENT** (`-DRAWRXD_BUILD_BENCHMARKS=OFF` on this candidate).
3. `F:\rawrxd\tools\certify_e2e.py` **PRESENT** but scopes `RAWRXD_CORE_DLL_NATIVE_E2E_001` tool evidence — **not** transferable to product IDE binary seal (Gate6/tool PASS transfer forbidden).
4. `Deep2ProductGate.hpp::PromoteReady` exists at tip sources; no ProductOpen/SESSION_ENTER/64-token headless runner was built or executed against this candidate EXE.

## Missing prerequisites (exact)
- No candidate-scoped 64-token product E2E harness wired to RawrXD-Win32IDE-Native.exe @ CB34EF4E…
- No deep2_benchmark / product-open binary in `product_seal_clean_a5ae60ef_build\bin`
- ChatWindow token-commit not observed (RESPONSE_OK=0)
- Cannot cite prior Deep2/CORE_DLL/Gate6 receipts as product PASS

## Verdict
VERDICT=NOT_VERIFIED
STOP_REASON=MISSING_CANDIDATE_64_TOKEN_PRODUCT_PATH
GENERATED_TOKENS=NOT_OBSERVED
TOKEN_COMMIT=NOT_OBSERVED
PRODUCT_OPEN=NOT_EXERCISED_ON_CANDIDATE
SESSION_ENTER=NOT_EXERCISED_ON_CANDIDATE
RUNTIME_PASS=0
INVENT_PASS=0
PROMOTE=0
CERTIFIED=0
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
TIP_CLIMB=HOLD
NOT_RUN_NEQ_PASS=1
