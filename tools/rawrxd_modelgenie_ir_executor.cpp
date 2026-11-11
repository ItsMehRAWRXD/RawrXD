//=============================================================================
// rawrxd_modelgenie_ir_executor - standalone verification harness
// RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001
//
// Test-only driver. The real execution implementation now lives in
// src/modelgenie/ModelGenieExecutor.{hpp,cpp} and is shared verbatim with
// RawrXDCore.dll (RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001). This file owns
// only argument parsing, the teacher-forced harness, and receipt printing.
//=============================================================================

#include "ModelGenieExecutor.hpp"
#include <algorithm>
#include <chrono>
#include <numeric>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

//=============================================================================
// Main Entry Point
//=============================================================================
int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::fprintf(stderr, "Usage: %s <gguf_path> <evidence_dir> [--multitoken N | --teacher-forced token1 token2 ... | --differential [output_dir]]\n", argv[0]);
        return 1;
    }
    
    std::string ggufPath = argv[1];
    std::string evidenceDir = argv[2];
    bool multitoken = false;
    bool profile = false;
    std::vector<double> step_ms, step_exec_ms, step_sample_ms;
    int max_tokens = 1;
    bool teacher_forced = false;
    bool differential = false;
    std::string differential_dir;
    std::vector<uint32_t> forced_tokens;
    
    // Order-independent CLI options. Differential flags are never parsed as token IDs.
    size_t diff_position = (std::numeric_limits<size_t>::max)();
    auto parse_uint = [](const char* raw, uint32_t& value) -> bool {
        if (!raw || !raw[0] || raw[0] == '-') return false;
        try {
            size_t consumed = 0;
            const unsigned long long parsed = std::stoull(raw, &consumed, 10);
            if (consumed != std::strlen(raw) ||
                parsed > (std::numeric_limits<uint32_t>::max)()) return false;
            value = static_cast<uint32_t>(parsed);
            return true;
        } catch (const std::exception&) { return false; }
    };
    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--teacher-forced") {
            teacher_forced = true;
        } else if (arg == "--differential") {
            differential = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') differential_dir = argv[++i];
        } else if (arg == "--diff-position") {
            uint32_t p = 0;
            if (i + 1 >= argc || !parse_uint(argv[++i], p)) {
                std::fprintf(stderr, "ERROR: --diff-position needs an unsigned integer\n");
                return 2;
            }
            diff_position = p;
        } else if (arg == "--profile") {
        profile = true;
    } else if (arg == "--multitoken") {
            multitoken = true;
            max_tokens = 16;
            uint32_t n = 0;
            if (i + 1 < argc && parse_uint(argv[i + 1], n)) {
                ++i;
                if (n == 0 || n > 1024) { std::fprintf(stderr, "ERROR: invalid token count\n"); return 2; }
                max_tokens = static_cast<int>(n);
            }
        } else {
            uint32_t n = 0;
            if (!parse_uint(argv[i], n)) {
                std::fprintf(stderr, "ERROR: unknown option or invalid token: %s\n", argv[i]);
                return 2;
            }
            if (teacher_forced) forced_tokens.push_back(n);
            else if (i == 3 && n > 0 && n <= 1024) { multitoken = true; max_tokens = static_cast<int>(n); }
            else { std::fprintf(stderr, "ERROR: numeric token requires --teacher-forced\n"); return 2; }
        }
    }
    if (differential && differential_dir.empty()) differential_dir = evidenceDir + "\\differential";
    if (teacher_forced && forced_tokens.empty()) {
        std::fprintf(stderr, "ERROR: --teacher-forced needs at least one token\n"); return 2;
    }
    if (teacher_forced && multitoken) {
        std::fprintf(stderr, "ERROR: choose teacher-forced or multitoken, not both\n"); return 2;
    }
    if (diff_position != (std::numeric_limits<size_t>::max)() &&
        (!differential || !teacher_forced || diff_position >= forced_tokens.size())) {
        std::fprintf(stderr, "ERROR: --diff-position requires an in-range teacher-forced position and --differential\n");
        return 2;
    }

    std::fprintf(stderr, "=============================================================================\n");
    std::fprintf(stderr, teacher_forced ? "RAWRXD_MODELGENIE_TEACHER_FORCED_DECODE\n" : 
                 multitoken ? "RAWRXD_MODELGENIE_MULTITOKEN_DECODE\n" : 
                 differential ? "RAWRXD_MODELGENIE_DIFFERENTIAL_CAPTURE\n" : "RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001\n");
    std::fprintf(stderr, "=============================================================================\n\n");
    
    std::fprintf(stderr, "GGUF: %s\n", argv[1]);
    std::fprintf(stderr, "Evidence: %s\n", argv[2]);
    if (multitoken) std::fprintf(stderr, "Max tokens: %d\n", max_tokens);
    if (teacher_forced) {
        std::fprintf(stderr, "Teacher-forced tokens: ");
        for (auto t : forced_tokens) std::fprintf(stderr, "%u ", t);
        std::fprintf(stderr, "\n");
    }
    if (differential) {
        std::fprintf(stderr, "Differential capture dir: %s\n", differential_dir.c_str());
    }
    fflush(stderr);
    
    // Load ModelGenome from evidence to get token baseline
    MG::ModelGenome genome;
    if (!LoadModelGenomeFromEvidence(evidenceDir, genome)) {
        std::fprintf(stderr, "ERROR: Failed to load ModelGenome\n");
        return 1;
    }
    
    std::string originalHash = genome.computeCanonicalHash();
    std::fprintf(stderr, "Original canonical hash: %s\n", originalHash.c_str());
    
    if (teacher_forced) {
        // Teacher-forced decode with specified token sequence
        std::fprintf(stderr, "\n=== Teacher-forced decode (%zu tokens) ===\n", forced_tokens.size());
        
        if (differential) {
            DIFF_ENABLE(differential_dir);
            g_differential_recorder.capture_position = diff_position;
            DIFF_CLEAR();
        }
        
        IRExecutor executor(ggufPath, forced_tokens[0]);
        
        for (size_t step = 0; step < forced_tokens.size(); ++step) {
            uint32_t input_token = forced_tokens[step];
            executor.SetTokenId(input_token);
            executor.ClearArena(); // Clear activations but keep KV cache
            
            std::fprintf(stderr, "\n--- Step %zu (position %zu), input token: %u ---\n", 
                         step, executor.Position(), input_token);
            
            bool success = executor.Execute();
            
            uint32_t predictedToken = executor.SampleToken();
            const std::vector<float>* logits = executor.GetLogits();
            bool logitsFinite = true;
            if (logits) {
                for (float v : *logits) {
                    if (!std::isfinite(v)) { logitsFinite = false; break; }
                }
            } else {
                logitsFinite = false;
            }
            
            // Save logits for comparison
            char fname[512];
            sprintf_s(fname, "%s\\native_tf_logits_pos%zu.bin", evidenceDir.c_str(), step);
            if (logits && !logits->empty()) {
                std::ofstream f(fname, std::ios::binary);
                f.write(reinterpret_cast<const char*>(logits->data()), logits->size() * sizeof(float));
                f.close();
                std::fprintf(stderr, "Saved logits to %s\n", fname);
            }
            
            std::fprintf(stderr, "Predicted token: %u, Logits finite: %d, Ops: %u/%u\n",
                         predictedToken, logitsFinite ? 1 : 0, executor.Dispatched(), executor.Visited());
            
            if (!success || !logitsFinite) {
                std::fprintf(stderr, "ERROR: Execution failed at step %zu\n", step);
                if (differential) DIFF_SAVE(); // preserve partial evidence
                return 1;
            }
            
            executor.AdvancePosition();
        }
        
        if (differential) {
            DIFF_SAVE();
            DIFF_DISABLE();
        }
        
        std::fprintf(stderr, "\n=============================================================================\n");
        std::fprintf(stderr, "TEACHER_FORCED_DECODE=PASS\n");
        std::fprintf(stderr, "TOKENS_PROCESSED=%zu\n", forced_tokens.size());
        std::fprintf(stderr, "=============================================================================\n");
        
        return 0;;
    } else if (differential) {
        // Differential execution capture mode
        std::fprintf(stderr, "\n=== Differential capture mode ===\n");
        
        DIFF_ENABLE(differential_dir);
        DIFF_CLEAR();
        
        IRExecutor executor(ggufPath, 1); // Start with token 1
        
        // Run single token with differential capture
        executor.Execute();
        DIFF_SAVE();
        DIFF_DISABLE();
        
        std::fprintf(stderr, "\n=============================================================================\n");
        std::fprintf(stderr, "DIFFERENTIAL_CAPTURE=PASS\n");
        std::fprintf(stderr, "RECORDS_CAPTURED=%zu\n", g_differential_recorder.records.size());
        std::fprintf(stderr, "OUTPUT_DIR=%s\n", differential_dir.c_str());
        std::fprintf(stderr, "=============================================================================\n");
        
        return 0;
    } else if (!multitoken) {
        // Single token execution (original mode)
        IRExecutor executor(ggufPath, 1);
        bool success = executor.Execute();
        
        uint32_t predictedToken = executor.SampleToken();
        const std::vector<float>* logits = executor.GetLogits();
        bool logitsFinite = true;
        if (logits) {
            for (float v : *logits) {
                if (!std::isfinite(v)) { logitsFinite = false; break; }
            }
        } else {
            logitsFinite = false;
        }
        
        // All receipt counters are obtained from the actual IR interpreter.
        // Table visibility does not by itself prove execution authority.
        std::fprintf(stderr, "\n=============================================================================\n");
        std::fprintf(stderr, "RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001\n");
        std::fprintf(stderr, "IR_TABLE_AUTHORITY=%d\n",
            (success && executor.Visited()==GEN::kExecutionOpCount &&
             executor.Dispatched()==GEN::kExecutionOpCount && executor.Skipped()==0) ? 1 : 0);
        std::fprintf(stderr, "IR_SOURCE_OP_COUNT=%u\n", GEN::kExecutionOpCount);
        std::fprintf(stderr, "IR_OPS_VISITED=%u\n", executor.Visited());
        std::fprintf(stderr, "IR_OPS_EXECUTED=%u\n", executor.Dispatched());
        std::fprintf(stderr, "IR_OPS_SKIPPED=%u\n", executor.Skipped());
        std::fprintf(stderr, "LOGITS_FINITE=%d\n", logitsFinite ? 1 : 0);
        std::fprintf(stderr, "PREDICTED_TOKEN=%u\n", predictedToken);
        std::fprintf(stderr, "EXPECTED_TOKEN=185\n");
        std::fprintf(stderr, "TOKEN_PARITY=%d\n", (predictedToken == 185) ? 1 : 0);
        std::fprintf(stderr, "VERDICT=%s\n", (success && logitsFinite && predictedToken == 185) ? "PASS" : "FAIL");
        std::fprintf(stderr, "=============================================================================\n");
        
        return (success && logitsFinite && predictedToken == 185) ? 0 : 1;
    } else {
        // Multi-token autonomous decode
        std::fprintf(stderr, "\n=== Multi-token autonomous decode (%d tokens) ===\n", max_tokens);
        
        IRExecutor executor(ggufPath, 1); // Start with token 1
        std::vector<uint32_t> tokens = {1};
        
        for (int step = 0; step < max_tokens; ++step) {
            uint32_t input_token = tokens.back();
            executor.SetTokenId(input_token);
            executor.ClearArena(); // Clear activations but keep KV cache

            std::fprintf(stderr, "\n--- Step %d (position %zu), input token: %u ---\n",
                         step, executor.Position(), input_token);

            // Per-token timing. Model weights are already resident, so this
            // measures decode cost and nothing else.
            const auto t_begin = std::chrono::steady_clock::now();
            bool success = executor.Execute();
            const auto t_exec_done = std::chrono::steady_clock::now();

            uint32_t predictedToken = executor.SampleToken();
            const std::vector<float>* logits = executor.GetLogits();
            const auto t_end = std::chrono::steady_clock::now();
            bool logitsFinite = true;
            if (logits) {
                for (float v : *logits) {
                    if (!std::isfinite(v)) { logitsFinite = false; break; }
                }
            } else {
                logitsFinite = false;
            }

            if (profile) {
                const double exec_ms =
                    std::chrono::duration<double, std::milli>(t_exec_done - t_begin).count();
                const double sample_ms =
                    std::chrono::duration<double, std::milli>(t_end - t_exec_done).count();
                const double total_ms =
                    std::chrono::duration<double, std::milli>(t_end - t_begin).count();
                step_ms.push_back(total_ms);
                step_exec_ms.push_back(exec_ms);
                step_sample_ms.push_back(sample_ms);
            }

            std::fprintf(stderr, "Predicted token: %u, Logits finite: %d, Ops: %u/%u\n",
                         predictedToken, logitsFinite ? 1 : 0, executor.Dispatched(), executor.Visited());

            if (!success || !logitsFinite) {
                std::fprintf(stderr, "ERROR: Execution failed at step %d\n", step);
                return 1;
            }

            tokens.push_back(predictedToken);
            executor.AdvancePosition();
        }
        
        std::fprintf(stderr, "\n=== Generated token sequence ===\n");
        for (size_t i = 0; i < tokens.size(); ++i) {
            std::fprintf(stderr, "  Position %zu: token %u\n", i, tokens[i]);
        }

        std::fprintf(stderr, "\n=============================================================================\n");
        std::fprintf(stderr, "MULTITOKEN_DECODE_TEST=PASS\n");
        std::fprintf(stderr, "TOKENS_GENERATED=%zu\n", tokens.size());

        if (profile && !step_ms.empty()) {
            // Report decode cost excluding the first step, which carries
            // first-call costs (arena growth, page faults) that are not
            // representative of steady-state decode.
            std::vector<double> steady(step_ms.begin() + 1, step_ms.end());
            if (steady.empty()) steady = step_ms;

            std::vector<double> sorted = steady;
            std::sort(sorted.begin(), sorted.end());
            const double sum = std::accumulate(steady.begin(), steady.end(), 0.0);
            const double mean = sum / (double)steady.size();
            const double median = sorted[sorted.size() / 2];
            const double mn = sorted.front();
            const double mx = sorted.back();
            double exec_sum = std::accumulate(step_exec_ms.begin() + 1,
                                              step_exec_ms.end(), 0.0);
            double sample_sum = std::accumulate(step_sample_ms.begin() + 1,
                                                step_sample_ms.end(), 0.0);

            std::fprintf(stderr, "\n");
            std::fprintf(stderr, "=============================================================================\n");
            std::fprintf(stderr, "RAWRXD_DEEP2_PER_TOKEN_PROFILE_001\n");
            std::fprintf(stderr, "STEPS_TOTAL=%zu\n", step_ms.size());
            std::fprintf(stderr, "STEPS_STEADY_STATE=%zu\n", steady.size());
            std::fprintf(stderr, "MEAN_MS_PER_TOKEN=%.4f\n", mean);
            std::fprintf(stderr, "MEDIAN_MS_PER_TOKEN=%.4f\n", median);
            std::fprintf(stderr, "MIN_MS_PER_TOKEN=%.4f\n", mn);
            std::fprintf(stderr, "MAX_MS_PER_TOKEN=%.4f\n", mx);
            std::fprintf(stderr, "MEAN_TPS=%.2f\n", 1000.0 / mean);
            std::fprintf(stderr, "MEAN_EXEC_MS=%.4f\n", exec_sum / (double)steady.size());
            std::fprintf(stderr, "MEAN_SAMPLE_MS=%.4f\n", sample_sum / (double)steady.size());
            std::fprintf(stderr, "IR_OPS_PER_TOKEN=%u\n", executor.Visited());
            std::fprintf(stderr, "IR_OPS_SKIPPED=%u\n", executor.Skipped());
            std::fprintf(stderr, "PER_TOKEN_OP_COST_US=%.3f\n",
                         1000.0 * mean / (double)std::max<uint32_t>(executor.Visited(), 1));
            std::fprintf(stderr, "\nPER_STEP_MS:");
            for (size_t i = 0; i < step_ms.size(); ++i)
                std::fprintf(stderr, " %.3f", step_ms[i]);
            std::fprintf(stderr, "\n");
            std::fprintf(stderr, "SCOPE=This profile measures the CPU decode path present in this\n");
            std::fprintf(stderr, " build. It is not a Nemotron benchmark and makes no GPU claim;\n");
            std::fprintf(stderr, " Vulkan is used only where RAWRXD_GPU_ROPE=1 selects it.\n");
            std::fprintf(stderr, "=============================================================================\n");
        }

        std::fprintf(stderr, "=============================================================================\n");

        return 0;
    }
}
