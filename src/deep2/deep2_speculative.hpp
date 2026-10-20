// ============================================================================
// deep2_speculative.hpp  --  RAWRXD_DEEP2_SPEC_VERIFY_001
// ----------------------------------------------------------------------------
// Native batched speculative verification for Deep2.
//
// The published EXL3/RDNA4 reference reaches ~150 tok/s on 27B-class code
// generation through speculative decoding: a draft proposes gamma tokens and
// the target model checks ALL of them in one batched pass, accepting the
// longest verified prefix plus one bonus token. The reference's repo documents
// a WMMA verification path where checking eight draft tokens costs ~1.16x a
// normal decode step instead of 1.55x. This file is the Deep2-native version
// of that idea over the existing runtime graph executor.
//
// The primitive it builds on is Executor::PrefillBatch's verify mode: one
// batched pass over the gamma drafted tokens (headed by the model's own last
// emitted token) returns the verifier's logits at EVERY drafted position.
// Acceptance is then pure arithmetic on the host:
//
//   head  = the model's own greedy token at position p (emitted, not consumed)
//   draft d_0..d_{gamma-1} proposed for positions p+1..p+gamma
//   batch = [head, d_0, ..., d_{gamma-1}]          -> perPos[0..gamma]
//   perPos[i] = P(token at p+1+i)
//   d_i accepted  iff  argmax(perPos[i]) == d_i
//   all accepted  -> bonus = argmax(perPos[gamma])  (token at p+gamma+1)
//   first reject at j -> replacement = argmax(perPos[j]), rest discarded
//
// Greedy equivalence (why this is certifiable): greedy decode is a
// deterministic function of the true prefix, and this loop emits, at every
// position, exactly the verifier's own argmax - the head is it, accepted
// drafts already equalled it, the replacement IS it, and the bonus is it. So
// the speculative token stream must be identical, token for token, to serial
// greedy decoding. The benchmark harness asserts exactly that.
//
// KV repair: the batched pass writes KV for the batched positions. Entries
// after the first rejection were computed from a prefix that never happened.
// Attention is causal, so only the rejected position itself is ever read
// again; one serial ExecuteToken of the replacement token at that position
// rewrites it exactly, and every later position is rewritten when it is
// reached. Recurrent (SSM) graphs cannot be repaired that way - the state is
// the memory - so the verifier fails closed on them (Executor::HasSsm).
// ============================================================================

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"

namespace Deep2 {

// Which kind of text is being generated. The EXL3 reference reports very
// different rates for code (~150 tok/s) and prose (~60 tok/s) because
// acceptance differs; acceptance is therefore measured PER WORKLOAD rather
// than averaged into one meaningless number.
enum class WorkloadKind : uint8_t { Code = 0, Prose = 1, Other = 2 };

const char* WorkloadName(WorkloadKind k);

// Draft proposal policy. The verifier is policy-agnostic: anything that can
// propose token ids can be verified by the same batched pass. A quantized
// drafter (the DFlash2-style draft model) slots in here unchanged.
enum class DraftPolicy : uint8_t {
    PromptLookup = 0,  // n-gram continuation of the previous occurrence
    RepeatLast    = 1, // degenerate probe: repeat the last token (floor)
};

struct SpeculativeConfig {
    size_t gamma = 4;                 // draft length per round
    WorkloadKind workload = WorkloadKind::Other;
    DraftPolicy policy = DraftPolicy::PromptLookup;
    size_t ngram = 3;                 // prompt-lookup match length
    bool adaptive_disable = true;     // stop speculating on persistent rejection
    // Two consecutive zero-accept rounds are already more expensive than
    // serial decoding for the current verifier. Disable speculation early and
    // continue with the exact serial path until a future draft policy earns a
    // new controlled measurement.
    size_t max_consecutive_zero = 2;  // rounds with zero accepted drafts
};

// Per-workload counters. Every field is a real observation from the loop;
// nothing is estimated.
struct WorkloadStats {
    uint64_t rounds = 0;           // speculative verify passes executed
    uint64_t proposed = 0;         // draft tokens proposed
    uint64_t accepted = 0;         // draft tokens accepted by the verifier
    uint64_t replacements = 0;     // verifier-chosen corrections (one per partial round)
    uint64_t bonus = 0;            // free tokens after a fully accepted round
    uint64_t zero_accept_rounds = 0;
    uint64_t serial_steps = 0;     // serial fallback steps (disabled or no draft)
    uint64_t verify_batches = 0;   // PrefillBatch calls used for draft verification
    uint64_t verify_positions = 0; // token positions evaluated across those calls
    uint64_t repair_steps = 0;     // serial KV repairs after first rejection
    uint64_t serial_fallbacks = 0; // rounds that had no draft/after adaptive disable
    bool adaptive_disabled = false; // fail-safe engaged for this workload
    double   spec_wall_ms = 0.0;   // wall time inside speculative Steps
    double   serial_wall_ms = 0.0; // wall time inside serial Steps
    uint64_t tokens_emitted = 0;   // total tokens emitted by this verifier

    double acceptance_rate() const {
        return proposed ? static_cast<double>(accepted) / static_cast<double>(proposed) : 0.0;
    }
    double tokens_per_round() const {
        return rounds ? static_cast<double>(accepted + replacements + bonus) /
                            static_cast<double>(rounds)
                      : 0.0;
    }
    double spec_tps() const {
        return tokens_emitted && spec_wall_ms > 0.0
                   ? tokens_emitted / (spec_wall_ms * 1e-3)
                   : 0.0;
    }
};

class SpeculativeStats {
public:
    const WorkloadStats& Get(WorkloadKind k) const { return w_[(size_t)k]; }
    WorkloadStats& Mutable(WorkloadKind k) { return w_[(size_t)k]; }
private:
    WorkloadStats w_[3];
};

class SpeculativeVerifier {
public:
    SpeculativeVerifier(RawrXD::Deep2::RuntimeGraph::Executor& exe,
                        const SpeculativeConfig& cfg);

    // One decode step. `context` is every token fed so far (prompt plus
    // emitted); the next token is consumed at position context.size().
    // `emitted` receives 1..gamma+1 tokens that the caller appends to the
    // stream. Returns false (with `err` set) only on a real execution
    // failure - a caller MUST stop in that case, because the executor's KV
    // cache can no longer be trusted.
    bool Step(const std::vector<uint32_t>& context, std::vector<uint32_t>& emitted,
              bool& speculated, std::string& err);

    const SpeculativeStats& Stats() const { return stats_; }
    const SpeculativeConfig& Config() const { return cfg_; }

    // Draft proposal, exposed for unit-level inspection.
    std::vector<uint32_t> DraftTokens(const std::vector<uint32_t>& context) const;

private:
    static uint32_t Argmax(const std::vector<float>& logits);
    // Milliseconds since `t0` (steady_clock), for the wall-time counters.
    static double ElapsedMs(const std::chrono::steady_clock::time_point& t0);

    RawrXD::Deep2::RuntimeGraph::Executor& exe_;
    SpeculativeConfig cfg_;
    SpeculativeStats stats_;
    bool auto_disabled_ = false;
    uint64_t consecutive_zero_ = 0;
    // Positions 0..consumed_-1 are in the executor's KV cache. When
    // has_pending_ is true, pending_tok_ (the token at position consumed_)
    // was already emitted to the stream but not yet consumed.
    size_t consumed_ = 0;
    bool has_pending_ = false;
    uint32_t pending_tok_ = 0;
    bool first_step_ = true;
};

} // namespace Deep2
