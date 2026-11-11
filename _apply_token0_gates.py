#!/usr/bin/env python3
# RAWRXD_APPLY_TOKEN0_GATES_001 — re-integrate authority gates + logits fingerprint
# into the current (rewritten) token0 source. Atomic: asserts each exact
# old-string is present exactly once; if any anchor shifted, aborts without
# writing so the file is never left half-patched.
import io, sys, datetime

SRC = r"F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp"

with io.open(SRC, "r", encoding="utf-8") as f:
    text = f.read()

edits = []

# --- Edit A: data-start alignment authority (ParseGGUFHeader) ---
edits.append(("A",
r'''        // Calculate data section start (after tensor info)
        ggufDataOffset = static_cast<uint64_t>(ptr - base);
''',
r'''        // Calculate data section start (after tensor info)
        // RAWRXD_ALIGNED_DATA_START_AUTHORITY_001
        // rawEnd is the raw tensor-directory end; physical tensor data begins
        // at the ALIGNMENT-aligned offset. The generated kDataStart must equal
        // the runtime-computed aligned start or tensors bind shifted.
        const uint64_t rawEnd = static_cast<uint64_t>(ptr - base);
        constexpr uint64_t ALIGNMENT = 32;
        ggufDataOffset = rawEnd + (ALIGNMENT - (rawEnd % ALIGNMENT)) % ALIGNMENT;

        fprintf(stderr,
            "[Gate] GGUF_RAW_DIRECTORY_END=%llu\n"
            "[Gate] GGUF_ALIGNMENT=%u\n"
            "[Gate] GGUF_ALIGNED_DATA_START=%llu\n"
            "[Gate] GGUF_GENERATED_DATA_START=%llu\n",
            (unsigned long long)rawEnd,
            (unsigned)ALIGNMENT,
            (unsigned long long)ggufDataOffset,
            (unsigned long long)Generated::ModelConfig::kDataStart);
        fflush(stderr);

        if (ggufDataOffset != Generated::ModelConfig::kDataStart)
        {
            fprintf(stderr,
                "[Gate] GGUF_DATA_START_AUTHORITY=FAIL\n"
                "[Gate] GGUF_DATA_START_DELTA=%lld\n",
                (long long)ggufDataOffset -
                    (long long)Generated::ModelConfig::kDataStart);
            fflush(stderr);
            return false;
        }

        fprintf(stderr, "[Gate] GGUF_DATA_START_AUTHORITY=PASS\n");
        fflush(stderr);
'''))

# --- Edit B: clearer [ROM] log line (raw_end vs aligned) ---
edits.append(("B",
r'''        printf("[ROM] GGUF parsed: tensors=%zu, data_start=%llu\n", liveTensors.size(), (unsigned long long)ggufDataOffset);
''',
r'''        printf("[ROM] GGUF parsed: tensors=%zu, raw_end=%llu, aligned_data_start=%llu\n",
            liveTensors.size(),
            (unsigned long long)rawEnd,
            (unsigned long long)ggufDataOffset);
'''))

# --- Edit C: corrected IR_CONSUMED semantics (decoupled from pass) ---
edits.append(("C",
r'''    // Execution authority verification
    auto stats = runtime.GetExecutionStats();
    fprintf(stderr, "[Gate] EXECUTION_IR_CONSUMED=%d\n", stats.executionIrConsumed ? 1 : 0);
    if (!stats.executionIrConsumed) pass = false;
''',
r'''    // Execution authority verification
    //
    // IMPORTANT:
    //   stats.executionIrConsumed is a LEGACY reachability milestone from the
    //   simplified forward path. It does NOT prove kExecutionIRTable owns
    //   execution; full authority requires every generated op to complete.
    auto stats = runtime.GetExecutionStats();

    const uint32_t irOpsExpected =
        static_cast<uint32_t>(Generated::kExecutionOpCount);

    const uint32_t legacyOpsExecuted = stats.opsExecuted;

    const uint32_t legacyOpsSkipped =
        legacyOpsExecuted < irOpsExpected
            ? (irOpsExpected - legacyOpsExecuted)
            : 0u;

    const bool irTableReachable =
        stats.executionIrConsumed;

    const bool irTableAuthority =
        irTableReachable &&
        legacyOpsExecuted == irOpsExpected;

    fprintf(stderr,
        "[Gate] IR_TABLE_REACHABLE=%d\n"
        "[Gate] IR_TABLE_AUTHORITY=%d\n"
        "[Gate] EXECUTION_IR_CONSUMED=%d\n"
        "[Gate] EXECUTION_OPS_EXPECTED=%u\n"
        "[Gate] EXECUTION_OPS_EXECUTED=%u\n"
        "[Gate] EXECUTION_OPS_SKIPPED=%u\n",
        irTableReachable ? 1 : 0,
        irTableAuthority ? 1 : 0,
        irTableAuthority ? 1 : 0,
        irOpsExpected,
        legacyOpsExecuted,
        legacyOpsSkipped);

    // Partial handwritten-model execution is allowed to remain a PASS while
    // native-IR authority is still under construction. Do NOT set pass=false
    // merely because IR_TABLE_AUTHORITY is not yet closed.
    //
    // RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001 may only PASS when
    // irTableAuthority is true and the dedicated interpreter counters prove
    // visited==dispatched==kExecutionOpCount with zero unsupported/fallbacks.
'''))

# --- Edit D: collapse the now-duplicate legacy EXECUTION_OPS block ---
edits.append(("D",
r'''    // Runtime execution verification
    fprintf(stderr, "[Gate] EXECUTION_OPS_EXPECTED=%u\n", Generated::kExecutionOpCount);
    fprintf(stderr, "[Gate] EXECUTION_OPS_EXECUTED=%u\n", stats.opsExecuted);
    if (stats.opsExecuted == 0) {
        fprintf(stderr, "[Gate] EXECUTION_OPS_SKIPPED=1\n");
        pass = false;
    } else {
        fprintf(stderr, "[Gate] EXECUTION_OPS_SKIPPED=0\n");
    }
''',
r'''    // Runtime execution verification (counts emitted via the authority gate above).
    // opsExecuted==0 means no forward ran at all -- distinct from IR authority.
    if (legacyOpsExecuted == 0) {
        pass = false;
    }
'''))

# --- Edit E: logits fingerprint (independent numerical parity baseline) ---
edits.append(("E",
r'''        fprintf(stderr, "[Gate] ARGMAX_IN_RANGE=%d\n", (token0 < Generated::ModelConfig::kVocabSize) ? 1 : 0);
        if (token0 >= Generated::ModelConfig::kVocabSize)
''',
r'''        fprintf(stderr, "[Gate] ARGMAX_IN_RANGE=%d\n", (token0 < Generated::ModelConfig::kVocabSize) ? 1 : 0);
        // RAWRXD_LOGITS_FINGERPRINT_001 -- parity baseline; decoding is greedy argmax.
        {
            const float* lg = logits.data();
            const size_t n = logits.size();
            size_t argmax = 0;
            float mx = lg[0], mn = lg[0];
            double lgsum = 0.0, lgsumsq = 0.0;
            for (size_t i = 0; i < n; ++i) {
                float v = lg[i];
                if (v > mx) { mx = v; argmax = i; }
                if (v < mn) mn = v;
                double d = (double)v;
                lgsum += d; lgsumsq += d * d;
            }
            const int K = 8;
            struct TopE { float v; uint32_t i; };
            TopE top[K];
            for (int k = 0; k < K; ++k) { top[k].v = -1e30f; top[k].i = 0; }
            for (size_t i = 0; i < n; ++i) {
                float v = lg[i];
                for (int k = 0; k < K; ++k) {
                    if (v > top[k].v) {
                        for (int s = K - 1; s > k; --s) top[s] = top[s - 1];
                        top[k] = { v, (uint32_t)i };
                        break;
                    }
                }
            }
            fprintf(stderr, "[Gate] LOGITS_ARGMAX=%u\n", (uint32_t)argmax);
            fprintf(stderr, "[Gate] LOGITS_ARGMAX_VALUE=%.6f\n", mx);
            for (int k = 0; k < K; ++k)
                fprintf(stderr, "[Gate] LOGITS_TOPK_%d=IDX:%u LOGIT:%.6f\n", k, top[k].i, (double)top[k].v);
            fprintf(stderr, "[Gate] LOGITS_SUM=%.6f\n", lgsum);
            fprintf(stderr, "[Gate] LOGITS_SUMSQ=%.6f\n", lgsumsq);
            fprintf(stderr, "[Gate] LOGITS_MIN=%.6f\n", mn);
            fprintf(stderr, "[Gate] DECODING_MODE=GREEDY\n");
            fprintf(stderr, "[Gate] DECODING_TEMPERATURE=0.0\n");
            fprintf(stderr, "[Gate] DECODING_TOPK=0\n");
            fprintf(stderr, "[Gate] DECODING_TOPP=1.0\n");
        }
        if (token0 >= Generated::ModelConfig::kVocabSize)
'''))

# --- Edit F1: normalize final IR evidence block ---
edits.append(("F1",
r'''    fprintf(stderr, "[Gate] EXECUTION_OPS_EXPECTED=%u\n", (unsigned)Generated::kExecutionOpCount);
    fprintf(stderr, "[Gate] EXECUTION_OPS_EXECUTED=%u\n", stats.opsExecuted);
    fprintf(stderr, "[Gate] EXECUTION_OPS_SKIPPED=%u\n", (unsigned)(Generated::kExecutionOpCount - stats.opsExecuted));
''',
r'''    fprintf(stderr, "[Gate] FINAL_IR_TABLE_REACHABLE=%d\n", irTableReachable ? 1 : 0);
    fprintf(stderr, "[Gate] FINAL_IR_TABLE_AUTHORITY=%d\n", irTableAuthority ? 1 : 0);
    fprintf(stderr, "[Gate] FINAL_EXECUTION_OPS_EXPECTED=%u\n", irOpsExpected);
    fprintf(stderr, "[Gate] FINAL_EXECUTION_OPS_EXECUTED=%u\n", legacyOpsExecuted);
    fprintf(stderr, "[Gate] FINAL_EXECUTION_OPS_SKIPPED=%u\n", legacyOpsSkipped);
'''))

# --- Edit F2: full executable verdict requires IR authority ---
edits.append(("F2",
r'''    if (pass && mlFullExecution && moeFullExecution)
''',
r'''    if (pass && mlFullExecution && moeFullExecution && irTableAuthority)
'''))

# Apply with strict per-edit assertions.
for name, old, new in edits:
    cnt = text.count(old)
    if cnt == 0:
        sys.stderr.write("ABORT: anchor %s not found (file changed?)\n" % name)
        sys.exit(1)
    if cnt > 1:
        sys.stderr.write("ABORT: anchor %s matched %d times (ambiguous)\n" % (name, cnt))
        sys.exit(1)
    text = text.replace(old, new, 1)
    sys.stdout.write("[OK] applied %s\n" % name)

backup = SRC + ".gatefix_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".bak"
import shutil
shutil.copy2(SRC, backup)

with io.open(SRC, "w", encoding="utf-8") as f:
    f.write(text)

sys.stdout.write("GATE_FIX=PASS\n")
sys.stdout.write("BACKUP=%s\n" % backup)
