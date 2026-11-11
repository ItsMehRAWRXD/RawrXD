// ============================================================================
// deep2_speculative.cpp  --  RAWRXD_DEEP2_SPEC_VERIFY_001
// ----------------------------------------------------------------------------
// Implementation of Deep2::SpeculativeVerifier. See the header for the
// verification contract, the greedy-equivalence argument, and the KV-repair
// rule. Everything here runs against the real executor over real weights;
// there is no simulation and no fallback that fabricates tokens.
//
// Round structure (the standard draft-then-verify formulation):
//   * pending_ is a token that was already EMITTED but not yet consumed by
//     the executor (the model's own greedy "head" token, or the previous
//     round's bonus token). It heads the next verify batch, which is what
//     makes the batch exactly [t_{n+1}, d_0, ..., d_{gamma-1}].
//   * A speculative round runs ONE batched pass over that batch at
//     positions consumed_ .. consumed_+gamma, yielding gamma+1
//     per-position distributions:
//         perPos[i] = P(token at consumed_+1+i)
//     d_i proposes the token at position consumed_+1+i, so it is accepted
//     iff d_i == argmax(perPos[i]). The extra distribution perPos[gamma] is
//     the bonus token.
//   * Full acceptance: emit d_0..d_{gamma-1} + bonus; the bonus becomes the
//     new pending_. Partial acceptance at j: emit d_0..d_{j-1} + the
//     verifier's own argmax(perPos[j]) as the replacement, then repair the
//     rejected position's KV entry with one serial pass over the
//     replacement (causal attention never reads the stale entries beyond
//     it, and every later position is rewritten when it is reached).
//   * With no draft (or after adaptive disable) the loop degenerates to
//     serial decode: consume the head, emit the next argmax as the new head.
//     One forward pass per token, identical to the serial arm.
// ============================================================================

#include "deep2_speculative.hpp"

#include <algorithm>
#include <chrono>

namespace Deep2 {

const char* WorkloadName(WorkloadKind k) {
    switch (k) {
        case WorkloadKind::Code:  return "code";
        case WorkloadKind::Prose: return "prose";
        default:                  return "other";
    }
}

SpeculativeVerifier::SpeculativeVerifier(
    RawrXD::Deep2::RuntimeGraph::Executor& exe, const SpeculativeConfig& cfg)
    : exe_(exe), cfg_(cfg) {
    if (cfg_.gamma == 0) cfg_.gamma = 1;
    if (cfg_.ngram == 0) cfg_.ngram = 1;
}

uint32_t SpeculativeVerifier::Argmax(const std::vector<float>& logits) {
    if (logits.empty()) return 0;
    size_t best = 0;
    for (size_t i = 1; i < logits.size(); ++i)
        if (logits[i] > logits[best]) best = i;
    return static_cast<uint32_t>(best);
}

double SpeculativeVerifier::ElapsedMs(const std::chrono::steady_clock::time_point& t0) {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
}

std::vector<uint32_t> SpeculativeVerifier::DraftTokens(
    const std::vector<uint32_t>& context) const {
    const size_t gamma = cfg_.gamma;
    if (context.empty() || gamma == 0) return {};
    switch (cfg_.policy) {
        case DraftPolicy::RepeatLast: {
            return std::vector<uint32_t>(gamma, context.back());
        }
        case DraftPolicy::PromptLookup:
        default: {
            // Longest suffix of the context (up to ngram tokens) that occurs
            // EARLIER in the context; propose what followed that earlier
            // occurrence, capped at gamma tokens.
            const size_t ctx = context.size();
            const size_t maxLen = std::min(cfg_.ngram, ctx - 1);
            for (size_t len = maxLen; len >= 1; --len) {
                const size_t start = ctx - len;
                if (start == 0) break;   // no earlier position to match against
                for (size_t i = 0; i + len <= start; ++i) {
                    if (std::equal(context.begin() + (long)i,
                                   context.begin() + (long)(i + len),
                                   context.begin() + (long)start)) {
                        std::vector<uint32_t> d;
                        for (size_t k = i + len; k < ctx && d.size() < gamma; ++k)
                            d.push_back(context[k]);
                        return d;
                    }
                }
                if (len == 1) break;   // size_t underflow guard
            }
            return {};
        }
    }
}

bool SpeculativeVerifier::Step(const std::vector<uint32_t>& context,
                               std::vector<uint32_t>& emitted,
                               bool& speculated, std::string& err) {
    emitted.clear();
    speculated = false;
    err.clear();

    if (context.empty()) { err = "spec-verify: empty context"; return false; }
    if (first_step_) {
        // After a prefill of p tokens the executor has consumed positions
        // 0..p-1 and Logits() is the distribution for position p.
        consumed_ = context.size();
        first_step_ = false;
    } else if (context.size() != consumed_ + (has_pending_ ? 1u : 0u)) {
        // Bookkeeping invariant: the harness appends exactly what the
        // previous Step emitted, and every emitted token except a pending
        // bonus was consumed by the executor. A mismatch means the caller's
        // stream and the executor's KV positions have diverged - fail closed
        // rather than write KV entries the caller does not know about.
        err = "spec-verify: context/position invariant broken (context=" +
              std::to_string(context.size()) + " consumed=" +
              std::to_string(consumed_) + " pending=" +
              (has_pending_ ? "1" : "0") + ")";
        return false;
    }
    // COPY the carried logits: the batched verify pass clears logits_ as it
    // runs, so holding a reference here would silently alias the LAST verify
    // position's logits and corrupt the first prime step's choice.
    const std::vector<float> carried = exe_.Logits();
    if (carried.empty()) { err = "spec-verify: no carried logits (prefill missing?)"; return false; }

    WorkloadStats& ws = stats_.Mutable(cfg_.workload);
    const auto t0 = std::chrono::steady_clock::now();

    // ---- head emission: no pending token yet ---------------------------------
    // The model's own greedy token for position consumed_ becomes the batch
    // head of the next verify round. It is emitted but NOT consumed here:
    // consuming it is exactly what the next round's batched pass does as its
    // first token, so this costs zero extra forward passes. (After a partial
    // round the repair pass already consumed the replacement, so the next
    // Step arrives in this state too.)
    if (!has_pending_) {
        pending_tok_ = Argmax(carried);
        has_pending_ = true;
        emitted.push_back(pending_tok_);
        ws.serial_steps++;
        ws.tokens_emitted += 1;
        ws.serial_wall_ms += ElapsedMs(t0);
        return true;
    }

    // ---- draft --------------------------------------------------------------
    std::vector<uint32_t> draft;
    if (!auto_disabled_) draft = DraftTokens(context);

    // ---- serial fallback: no draft, or speculative decoding disabled --------
    // Consume the already-emitted head token, then take the model's own
    // argmax for the next position as the new head. Exactly one forward pass
    // per emitted token - identical to the serial arm.
    if (draft.empty()) {
        if (!exe_.ExecuteToken(pending_tok_, consumed_)) {
            err = "spec-verify: serial fallback ExecuteToken failed: " + exe_.LastError();
            return false;
        }
        ++consumed_;
        pending_tok_ = Argmax(exe_.Logits());
        emitted.push_back(pending_tok_);
        ws.serial_steps++;
        ws.tokens_emitted += 1;
        ws.serial_wall_ms += ElapsedMs(t0);
        return true;
    }

    // ---- batched verification pass: [pending] ++ draft ----------------------
    std::vector<uint32_t> batch;
    batch.reserve(draft.size() + 1);
    batch.push_back(pending_tok_);
    batch.insert(batch.end(), draft.begin(), draft.end());

    std::vector<std::vector<float>> perPos;
    if (!exe_.PrefillBatch(batch, consumed_, &perPos)) {
        err = "spec-verify: batched verify pass failed: " + exe_.LastError();
        return false;
    }
    if (perPos.size() != batch.size()) {
        err = "spec-verify: verify pass returned " + std::to_string(perPos.size()) +
              " position logits, expected " + std::to_string(batch.size());
        return false;
    }
    // perPos[i] = P(token at consumed_+1+i); d_i proposes exactly that.
    size_t accepted = 0;
    uint32_t replacement = 0;
    for (size_t i = 0; i < draft.size(); ++i) {
        const uint32_t want = Argmax(perPos[i]);
        if (draft[i] == want) {
            ++accepted;
        } else {
            replacement = want;   // the verifier's own greedy choice
            break;
        }
    }

    ws.rounds++;
    ws.proposed += draft.size();
    ws.accepted += accepted;

    if (accepted == draft.size()) {
        const uint32_t bonus = Argmax(perPos[draft.size()]);
        emitted = draft;
        emitted.push_back(bonus);
        ws.bonus++;
        consumed_ += draft.size() + 1;   // batch consumed pending + all drafts
        pending_tok_ = bonus;
        has_pending_ = true;             // bonus is emitted, not yet consumed
        speculated = true;
    } else {
        emitted.assign(draft.begin(), draft.begin() + (long)accepted);
        emitted.push_back(replacement);
        // The rejected draft's KV entry sits at position consumed_+accepted+1
        // and was computed from a prefix that never happened; rewrite it with
        // one serial pass over the replacement token.
        const size_t repair_pos = consumed_ + accepted + 1;
        if (!exe_.ExecuteToken(replacement, repair_pos)) {
            err = "spec-verify: KV repair pass failed: " + exe_.LastError();
            return false;
        }
        consumed_ += accepted + 2;       // pending + accepted drafts + replacement
        has_pending_ = false;            // replacement was consumed by the repair
        ws.replacements++;
        speculated = true;
    }

    // ---- adaptive disable ----------------------------------------------------
    if (accepted == 0) {
        ++consecutive_zero_;
        ++ws.zero_accept_rounds;
        if (cfg_.adaptive_disable && consecutive_zero_ >= cfg_.max_consecutive_zero)
            auto_disabled_ = true;
    } else {
        consecutive_zero_ = 0;
    }

    ws.tokens_emitted += emitted.size();
    ws.spec_wall_ms += ElapsedMs(t0);
    return true;
}

} // namespace Deep2
