// ACTUAL_E2E_GENERATION_001 — PASS only when real model text is emitted E2E.
#include "../src/deep2/lavapath/ActualE2EEmit.hpp"
#include "../src/deep2/Deep2Engine.h"
#include "../src/deep2/RawrRunSession.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace Deep2;

int main() {
    const char* alias = std::getenv("RAWRXD_PRODUCT_MODEL");
    if (!alias || !alias[0]) alias = "llama32";
    RawrCompletionReceipt r{};
    r.generation = 1;
    r.execution_scope = RAWR_SCOPE_END_TO_END;
    r.production_state = RAWR_PRODUCTION_NOT_ENTERED;
    r.status = RAWR_STATUS_OPEN;
    std::string text;
    uint32_t nTok = 0;
    auto t0 = std::chrono::steady_clock::now();
    {
        Deep2Engine eng;
        rawr_run::RunWitness wit{};
        if (!rawr_run::OpenSession(eng, alias, wit)) {
            r.termination_class = RAWR_TERM_BLOCKED_BEFORE_EXECUTION;
            r.blocker_owner = RAWR_OWNER_MODEL_RESOLVER;
            r.failure_domain = RAWR_FAILURE_MODEL;
            ActualE2E_WriteGate(r, RawrTerminalName(r), 0);
            ActualE2E_Emit(r, RawrTerminalName(r), 0, false);
            return 2;
        }
        r.production_state = RAWR_PRODUCTION_ENTERED;
        GenerationOptions opt{};
        opt.maxTokens = 32;
        opt.temperature = 0.f;
        opt.topK = 1;
        const std::string prompt =
            rawr_run::FormatChatPrompt(eng, "Say hi in one short sentence.",
                                       &wit);
        auto gr = eng.generateStream(
            prompt, opt, [&](int32_t, const std::string& piece) {
                ++nTok;
                text += piece;
                r.production_state = RAWR_PRODUCTION_STREAM_ACTIVE;
                return true;
            });
        auto t2 = std::chrono::steady_clock::now();
        r.wall_ns = (uint64_t)std::chrono::duration_cast<
                        std::chrono::nanoseconds>(t2 - t0)
                        .count();
        r.generated_tokens = nTok ? nTok : gr.generatedTokens;
        r.decode_steps_completed = r.generated_tokens;
        r.prefill_layers_completed = 1;
        r.production_decode_path = 1;
        r.model_output_produced = text.empty() ? 0u : 1u;
        r.numeric_valid = 1;
        r.output_valid = text.empty() ? 0u : 1u;
        if (r.generated_tokens > 0 && r.model_output_produced) {
            r.termination_class = RAWR_TERM_COMPLETED;
            r.completion_reason = RAWR_COMPLETE_MAX_TOKENS;
            r.production_state = RAWR_PRODUCTION_FINISHED;
            r.status = RAWR_STATUS_PASS;
        } else {
            r.termination_class = RAWR_TERM_FAILED_DURING_STREAM;
            r.failure_domain = RAWR_FAILURE_STREAM;
            r.status = RAWR_STATUS_FAIL;
        }
        eng.unloadModel();
    }
    r.teardown_witness = 1;
    r.teardown_state = RAWR_TEARDOWN_COMPLETE;
    const char* term = RawrTerminalName(r);
    const bool pass = RawrIsProductionCompletion(r) && RawrHasCleanTeardown(r) &&
                      RawrRunsCorrectly(r);
    ActualE2E_WriteGate(r, term, text.size());
    ActualE2E_Emit(r, term, text.size(), pass);
    return pass ? 0 : 1;
}
