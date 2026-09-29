// TraceProfilePolicy.h — RAWRXD_TRACE_PROFILE_POLICY_001
// Named trace profile authority. Controls which stderr traces fire.
//
// Profiles:
//   perf    — no stderr hotpath spam; structured counters only; TPS valid
//   ide     — structured IDE diagnostics; stage events; summaries; no flood
//   debug   — full unsilent stderr flood; TPS marked DEBUG_CONTAMINATED
//   receipt — machine-readable receipts only
//
// Direct call sites:
//   rawrxd::trace::currentProfile()
//   rawrxd::trace::enabled(RawrTraceChannel::LinearW)
//   rawrxd::trace::markDebugContaminated(reason)
//   rawrxd::trace::writeTraceProfileReceipt(path)
#pragma once
#include <cstdint>
#include <string>

namespace rawrxd { namespace trace {

enum class RawrTraceProfile : uint8_t {
    Perf,       // clean TPS, no hotpath spam
    Ide,        // structured stage events, no flood
    Debug,      // full unsilent stderr flood
    Receipt     // machine-readable receipts only
};

enum class RawrTraceChannel : uint8_t {
    Init,           // [INIT] engine init
    Alloc,          // [ALLOC] buffer allocation
    Tokenize,       // [TOKENIZE] / [DETOKENIZE]
    Embed,          // [EMBED] embedding
    Forward,        // [FWD_ALL] / [FWD_LAYER] forward path
    LinearW,        // LINEARW* per-op traces
    GpuForward,     // GPU_FORWARD_STAGE per-layer traces
    Logits,         // LOGITS_SANITY / [LOGITS] per-token stats
    Sampler,        // SAMPLER_RESULT per-token
    Decode,         // [DECODE] per-token decode loop
    Stream,         // [STREAM] generateStream result
    Generate,       // [GENERATE] generate() exit
    Speculative,    // [SPEC] speculative decode
    MoE,            // [MOE_FFN] MoE traces
    SSM,            // [SSM] Mamba traces
    KernelRoute     // kernel selection / route
};

// Get the active profile (resolved once from env, cached)
RawrTraceProfile currentProfile();

// Check if a channel should emit traces under the current profile
bool enabled(RawrTraceChannel channel);

// Mark the current run as debug-contaminated (TPS not valid for baseline)
void markDebugContaminated(const char* reason);

// Check if TPS is valid for baseline (false if debug-contaminated)
bool isTpsBaselineValid();

// Get trace spam line count (for receipt)
uint64_t traceSpamLines();

// Increment trace spam counter (called by hotpath trace macro)
void incrementTraceSpam();

// Write trace profile receipt
void writeTraceProfileReceipt(const std::string& path);

// Get profile name as string
const char* profileName(RawrTraceProfile p);

// Get channel name as string
const char* channelName(RawrTraceChannel c);

}} // namespace rawrxd::trace