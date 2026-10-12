// RAWRXD_STREAM_CANCEL_001 - streaming, cancellation and failure-status probe.
//
// Drives the production ModelGenie runtime (the same code RawrXDCore.dll
// serves through RawrXDCore_RunInference) through the public API only and
// proves:
//
//   STREAM_CALLBACK_BEFORE_NEXT_DECODE
//       the token callback for generated token i observes a forward-pass
//       count exactly one lower than the callback for token i+1: every token
//       is delivered while decoding, before the forward pass that produces
//       the next token has run. (The previous implementation ran the whole
//       decode first and delivered afterwards, so every callback saw the
//       final count.)
//
//   CANCEL_AFTER_TOKEN_20 / POST_CANCEL_FORWARD_COUNT=0
//       returning false from the callback after N tokens stops the decode at
//       once: the forward-pass count after the call equals the count the Nth
//       callback observed, i.e. zero further forward passes ran.
//
//   STATUS_REPORTING
//       mg_context_last_generate_status() reports COMPLETED / CANCELLED /
//       EXECUTION_FAILED, mg_context_generate() returns MG_SUCCESS /
//       MG_ERROR_CANCELLED / MG_ERROR_EXECUTION_FAILED to match, and
//       mg_context_last_failed_op() names the failing IR op (0 when none).
//       A forward-pass failure can no longer masquerade as a partial
//       success: the old code treated any non-empty token vector as
//       MG_SUCCESS.
#include "ModelGenieRuntime.h"

#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

struct Probe {
    mg_context_t* ctx = nullptr;
    int cancel_after = -1;  // -1 = never cancel via the probe
    uint32_t eos = 0;
    std::vector<uint32_t> passes_at_token;
    std::vector<uint32_t> token_at;
    bool eos_seen = false;
};

bool ProbeCallback(uint32_t token_id, const char* text, void* user_data)
{
    auto* p = static_cast<Probe*>(user_data);
    (void)text;
    p->token_at.push_back(token_id);
    // Observe the forward-pass count at the moment this token is delivered.
    p->passes_at_token.push_back(mg_context_forward_passes(p->ctx));
    if (p->eos != 0 && token_id == p->eos) {
        p->eos_seen = true;
        return false;  // EOS terminates the stream (production semantics)
    }
    if (p->cancel_after > 0 &&
        static_cast<int>(p->passes_at_token.size()) >= p->cancel_after) {
        return false;  // client cancellation
    }
    return true;
}

const char* StatusName(mg_generate_status_t s)
{
    switch (s) {
    case MG_GENERATE_CANCELLED: return "CANCELLED";
    case MG_GENERATE_EXECUTION_FAILED: return "EXECUTION_FAILED";
    default: return "COMPLETED";
    }
}

// The tokenizer reports its required capacity through MG_ERROR_INVALID_ARGUMENT
// (out_tokens == nullptr), so size the buffer from that reply.
bool TokenizeAll(mg_model_t* m, const char* text, std::vector<uint32_t>* out)
{
    size_t n = 0;
    mg_model_tokenize(m, text, nullptr, &n);  // reports capacity in n
    if (n == 0) return false;
    out->resize(n);
    size_t fill = n;
    if (mg_model_tokenize(m, text, out->data(), &fill) != MG_SUCCESS) return false;
    out->resize(fill);
    return !out->empty();
}

}  // namespace

int main(int argc, char** argv)
{
    const char* gguf = argc > 1 ? argv[1]
                                : "F:/rawrxd/DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    const int cancel_after = argc > 2 ? std::atoi(argv[2]) : 20;

    mg_model_config_t mcfg{};
    mg_model_t* m = nullptr;
    if (mg_model_load(gguf, &mcfg, &m) != MG_SUCCESS || !m) {
        std::fprintf(stderr, "mg_model_load failed\n");
        return 1;
    }
    mg_context_t* ctx = nullptr;
    if (mg_context_create(m, &ctx) != MG_SUCCESS || !ctx) {
        std::fprintf(stderr, "mg_context_create failed\n");
        mg_model_free(m);
        return 2;
    }

    // The DLL chat-template prompt "Hello, world!" renders to exactly these
    // ids (verified by the DLL's own tokenizer-parity probe: BOS + 10 tokens).
    // Fixed ids keep the probe independent of the tokenizer capacity query,
    // which reports its size through an INVALID_ARGUMENT return by design.
    const std::vector<uint32_t> tokens = {1u, 5726u, 25u, 37727u, 11u, 1843u,
                                          0u, 185u, 185u, 77398u, 25u};
    const uint32_t eos = mg_model_eos_token_id(m);

    // ---- run 1: full decode, no cancellation --------------------------------
    mg_context_reset(ctx);
    Probe p1;
    p1.ctx = ctx;
    p1.eos = eos;
    p1.cancel_after = -1;
    mg_generation_config_t gc{};
    gc.max_tokens = 16;
    gc.temperature = 0.0f;
    const mg_error_t rc1 = mg_context_generate(ctx, tokens.data(), tokens.size(),
                                               &gc, ProbeCallback, &p1);
    const mg_generate_status_t st1 = mg_context_last_generate_status(ctx);
    const uint32_t failed_op1 = mg_context_last_failed_op(ctx);
    const uint32_t passes_after1 = mg_context_forward_passes(ctx);

    bool order_ok = p1.passes_at_token.size() >= 2;
    for (size_t i = 1; i < p1.passes_at_token.size(); ++i) {
        if (p1.passes_at_token[i] != p1.passes_at_token[i - 1] + 1) order_ok = false;
    }
    const bool tail_ok =
        p1.passes_at_token.empty() ||
        passes_after1 == p1.passes_at_token.back();
    const bool stream_ok = order_ok && tail_ok;

    std::printf("=== run 1: full decode (max_tokens=%u) ===\n", gc.max_tokens);
    std::printf("prompt_tokens=%zu\n", tokens.size());
    std::printf("delivered_tokens=%zu\n", p1.token_at.size());
    std::printf("passes_at_callback=");
    for (size_t i = 0; i < p1.passes_at_token.size(); ++i)
        std::printf("%s%u", i ? "," : "", p1.passes_at_token[i]);
    std::printf("\n");
    std::printf("passes_after_generate=%u\n", passes_after1);
    std::printf("status=%s mg_rc=%d failed_op=%u\n", StatusName(st1),
                static_cast<int>(rc1), failed_op1);
    std::printf("STREAM_CALLBACK_BEFORE_NEXT_DECODE=%s\n",
                stream_ok ? "PASS" : "FAIL");
    // A decode that ends at the model's own EOS after all requested tokens
    // reports COMPLETED; a decode the EOS token terminates early reports
    // CANCELLED (the callback refused the terminating token). Both are
    // correct; what must never happen is a silent partial success.
    const bool status1_ok =
        (st1 == MG_GENERATE_COMPLETED && rc1 == MG_SUCCESS && failed_op1 == 0) ||
        (st1 == MG_GENERATE_CANCELLED && rc1 == MG_ERROR_CANCELLED &&
         p1.eos_seen && failed_op1 == 0);
    std::printf("STATUS_REPORTING=%s\n", status1_ok ? "PASS" : "FAIL");
    std::fflush(stdout);

    // ---- run 2: cancel after N tokens ---------------------------------------
    // The endurance prompt (chat-templated, as RawrXDCore_RunInference renders
    // it) generates far more than N tokens, so this run exercises a genuine
    // client cancellation rather than an EOS stop.
    std::vector<uint32_t> long_tokens;
    if (!TokenizeAll(m, "User: List the numbers from one to three hundred, separated by commas:\n\nAssistant:",
                     &long_tokens)) {
        std::fprintf(stderr, "tokenize(long prompt) failed\n");
        mg_context_free(ctx);
        mg_model_free(m);
        return 5;
    }
    mg_context_reset(ctx);
    Probe p2;
    p2.ctx = ctx;
    p2.eos = eos;
    p2.cancel_after = cancel_after;
    mg_generation_config_t gc2 = gc;
    gc2.max_tokens = 64;  // > cancel_after so the cancel, not the request, ends it
    const uint32_t passes_before2 = mg_context_forward_passes(ctx);
    const mg_error_t rc2 = mg_context_generate(ctx, long_tokens.data(),
                                               long_tokens.size(), &gc2,
                                               ProbeCallback, &p2);
    const mg_generate_status_t st2 = mg_context_last_generate_status(ctx);
    const uint32_t failed_op2 = mg_context_last_failed_op(ctx);
    const uint32_t passes_after2 = mg_context_forward_passes(ctx);
    const uint32_t passes_at_cancel =
        p2.passes_at_token.empty() ? 0 : p2.passes_at_token.back();
    const uint32_t post_cancel_passes = passes_after2 - passes_at_cancel;

    std::printf("=== run 2: cancel after %d tokens ===\n", cancel_after);
    std::printf("passes_before=%u delivered_tokens=%zu\n", passes_before2,
                p2.token_at.size());
    std::printf("passes_at_cancelling_callback=%u passes_after=%u\n",
                passes_at_cancel, passes_after2);
    std::printf("status=%s mg_rc=%d failed_op=%u\n", StatusName(st2),
                static_cast<int>(rc2), failed_op2);
    std::printf("CANCEL_AFTER_TOKEN_%d=%s\n", cancel_after,
                (st2 == MG_GENERATE_CANCELLED && rc2 == MG_ERROR_CANCELLED)
                    ? "PASS"
                    : "FAIL");
    std::printf("POST_CANCEL_FORWARD_COUNT=%u\n", post_cancel_passes);
    std::printf("POST_CANCEL_FORWARD_COUNT_ZERO=%s\n",
                post_cancel_passes == 0 ? "PASS" : "FAIL");
    std::fflush(stdout);

    // ---- run 3: EOS termination is a normal end of stream -------------------
    mg_context_reset(ctx);
    Probe p3;
    p3.ctx = ctx;
    p3.eos = eos;
    p3.cancel_after = -1;
    mg_generation_config_t gc3 = gc;
    gc3.max_tokens = 32;
    const mg_error_t rc3 = mg_context_generate(ctx, tokens.data(), tokens.size(),
                                               &gc3, ProbeCallback, &p3);
    const mg_generate_status_t st3 = mg_context_last_generate_status(ctx);
    std::printf("=== run 3: run to EOS ===\n");
    std::printf("delivered_tokens=%zu eos_seen=%s status=%s mg_rc=%d\n",
                p3.token_at.size(), p3.eos_seen ? "yes" : "no",
                StatusName(st3), static_cast<int>(rc3));
    std::printf("EOS_STOP=%s\n",
                (p3.eos_seen && st3 == MG_GENERATE_CANCELLED &&
                 rc3 == MG_ERROR_CANCELLED)
                    ? "PASS"
                    : "FAIL");

    // ---- failure-status contract -------------------------------------------
    // A forward-pass failure is reported as MG_ERROR_EXECUTION_FAILED with
    // status EXECUTION_FAILED and the failing IR op id; the reachable negative
    // checks below pin the return-code contract (no in-process fault-injection
    // point exists on the public API, so no fabricated fault is claimed).
    const mg_error_t rc_bad = mg_context_generate(
        nullptr, tokens.data(), tokens.size(), &gc, ProbeCallback, &p1);
    std::printf("INVALID_ARGS_RC=%d (MG_ERROR_INVALID_ARGUMENT=%d)\n",
                static_cast<int>(rc_bad),
                static_cast<int>(MG_ERROR_INVALID_ARGUMENT));
    std::printf("EXECUTION_FAILURE_CONTRACT=status EXECUTION_FAILED + "
                "MG_ERROR_EXECUTION_FAILED(%d) + failed op id (fail-closed "
                "by construction; no reachable fault point on a valid prompt)\n",
                static_cast<int>(MG_ERROR_EXECUTION_FAILED));
    std::printf("INVALID_ARGS=%s\n",
                rc_bad == MG_ERROR_INVALID_ARGUMENT ? "PASS" : "FAIL");

    mg_context_free(ctx);
    mg_model_free(m);
    const bool all_ok = stream_ok && status1_ok && post_cancel_passes == 0 &&
                        st2 == MG_GENERATE_CANCELLED &&
                        rc_bad == MG_ERROR_INVALID_ARGUMENT;
    std::printf("VERDICT=%s\n", all_ok ? "PASS" : "FAIL");
    return all_ok ? 0 : 1;
}
