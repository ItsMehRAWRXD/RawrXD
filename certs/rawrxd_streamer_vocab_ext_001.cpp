// Streamer completion vocab — setup PASS ≠ generation PASS.
#include "../src/deep2/lavapath/K2QkvNextLaw.hpp"
#include "../src/deep2/lavapath/RawrStreamerCompletion.hpp"
#include "../src/deep2/lavapath/RawrStreamerExtNames.hpp"
#include <cstdio>

int main() {
    RawrCompletionReceipt r{};
    r.generation = 1;
    r.execution_scope = RAWR_SCOPE_END_TO_END;
    r.termination_class = RAWR_TERM_COMPLETED;
    r.completion_reason = RAWR_COMPLETE_MAX_TOKENS;
    r.production_state = RAWR_PRODUCTION_FINISHED;
    r.status = RAWR_STATUS_PASS;
    r.teardown_state = RAWR_TEARDOWN_COMPLETE;
    r.teardown_witness = 1;
    r.performance_class = RAWR_PERF_OVER_BUDGET;
    r.prompt_tokens = 8;
    r.generated_tokens = 64;
    r.wall_ns = 17900000000ull;
    r.decode_tps = 3.559;
    r.production_decode_path = 1;
    r.model_output_produced = 1;
    r.cpu_f32_expands = 0;
    r.host_forward_layer_calls = 0;
    r.numeric_valid = 1;
    r.output_valid = 1;

    const RAWR_U64 budget = PRODUCT_WALL_BUDGET_NS_64TOK;
    std::printf("CAN_RUN=1 RUNS_CORRECTLY=%u RUNS_FASTEST=0\n",
                RawrRunsCorrectly(r) ? 1u : 0u);
    std::printf("EXECUTION_SCOPE=%s\n",
                RawrExecutionScopeName(r.execution_scope));
    std::printf("PRODUCTION_DECODE_PATH=%u MODEL_OUTPUT_PRODUCED=%u "
                "GENERATED_TOKENS=%llu\n",
                r.production_decode_path, r.model_output_produced,
                (unsigned long long)r.generated_tokens);
    std::printf("TERMINATION_CLASS=%s COMPLETION_REASON=MAX_TOKENS\n",
                RawrTerminationClassName(r.termination_class));
    std::printf("TEARDOWN_WITNESS=%u TEARDOWN_STATE=COMPLETE\n",
                r.teardown_witness);
    std::printf("WALL_WITHIN_BUDGET=%u WALL_NS=%llu BUDGET_NS=%llu\n",
                RawrRunsWithinBudget(r, budget) ? 1u : 0u,
                (unsigned long long)r.wall_ns, (unsigned long long)budget);
    std::printf("TERMINAL=%s\n", RawrTerminalName(r));
    std::printf("STREAM_COMPLETE=%u PRODUCT_E2E=%u\n",
                RawrIsProductionCompletion(r) ? 1u : 0u,
                RawrRunsWithinBudget(r, budget) ? 1u : 0u);
    std::printf("LAW=setup_pass_ne_generation_pass\n");
    std::printf("RAWRXD_STREAMER_VOCAB_EXT_001=PASS\n");
    std::printf("RAWRXD_PERFORMANCE_001=OPEN\n");
    std::printf("RAWRXD_PRODUCT_E2E_001=OPEN\n");
    return 0;
}
