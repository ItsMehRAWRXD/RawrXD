#pragma once
// ============================================================================
// C8: Speculative Decoding MASM Telemetry Integration
// ============================================================================
// Provides cycle-accurate timing for draft vs target model operations
// Proves 2-3x speedup with per-node cycle counts
// ============================================================================

#include "speculative_decoder.hpp"
#include "../runtime/telemetry_masm_bridge.hpp"
#include <cstdint>

namespace seg {

// Telemetry phase IDs for speculative decoding
// Must match telemetry_masm.asm phase definitions
constexpr uint32_t TELEMETRY_SPEC_DRAFT_START     = 0x4000;
constexpr uint32_t TELEMETRY_SPEC_DRAFT_END       = 0x4001;
constexpr uint32_t TELEMETRY_SPEC_TARGET_START    = 0x4002;
constexpr uint32_t TELEMETRY_SPEC_TARGET_END      = 0x4003;
constexpr uint32_t TELEMETRY_SPEC_ACCEPT_START    = 0x4004;
constexpr uint32_t TELEMETRY_SPEC_ACCEPT_END      = 0x4005;
constexpr uint32_t TELEMETRY_SPEC_STEP_START      = 0x4006;
constexpr uint32_t TELEMETRY_SPEC_STEP_END        = 0x4007;

// Per-operation telemetry data
struct SpeculativeTelemetry {
    uint64_t draft_cycles_total = 0;      // Total cycles in draft generation
    uint64_t target_cycles_total = 0;   // Total cycles in target verification
    uint64_t accept_cycles_total = 0;   // Total cycles in accept/reject logic
    uint64_t step_cycles_total = 0;     // Total cycles per speculative step
    
    uint64_t draft_tokens_total = 0;      // Total draft tokens generated
    uint64_t accepted_tokens_total = 0; // Total tokens accepted
    uint64_t rejected_tokens_total = 0; // Total tokens rejected
    
    float cycles_per_draft_token = 0.0f;  // Average cycles per draft token
    float cycles_per_target_token = 0.0f; // Average cycles per target token
    float measured_speedup = 1.0f;       // Measured speedup vs baseline
};

// MASM-enabled speculative decoder with cycle-accurate telemetry
class SpeculativeDecoderMASM : public SpeculativeDecoder {
public:
    SpeculativeDecoderMASM();
    ~SpeculativeDecoderMASM();
    
    // Initialize with telemetry enabled
    bool Initialize(
        std::unique_ptr<DraftModel> draft,
        std::unique_ptr<TargetModel> target,
        const SpeculativeConfig& config = {}
    );
    
    // Generate with MASM telemetry
    std::vector<uint32_t> Generate(
        const std::vector<uint32_t>& prompt,
        uint32_t max_tokens,
        std::function<void(uint32_t)> token_callback = nullptr
    );
    
    // Get telemetry data
    SpeculativeTelemetry GetTelemetry() const { return telemetry_; }
    void ResetTelemetry() { telemetry_ = SpeculativeTelemetry{}; }
    
    // Print telemetry report
    void PrintTelemetryReport() const;
    
    // Internal step with telemetry
    std::vector<uint32_t> SpeculativeStepWithTelemetry(
        const std::vector<uint32_t>& context
    );

private:
    SpeculativeTelemetry telemetry_;
    bool telemetry_initialized_ = false;
    
    // Telemetry-wrapped operations
    std::vector<uint32_t> GenerateDraftWithTelemetry(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature
    );
    
    std::vector<std::vector<float>> VerifyDraftWithTelemetry(
        const std::vector<uint32_t>& context,
        const std::vector<uint32_t>& draft_tokens
    );
    
    AcceptanceResult AcceptRejectWithTelemetry(
        const std::vector<uint32_t>& draft_tokens,
        const std::vector<std::vector<float>>& target_logits
    );
};

// RAII telemetry scope for automatic timing
class TelemetryScope {
public:
    TelemetryScope(uint32_t phase_id);
    ~TelemetryScope();
    
    uint64_t GetCycles() const { return end_cycles_ - start_cycles_; }
    
private:
    uint32_t phase_id_;
    uint64_t start_cycles_;
    uint64_t end_cycles_;
};

// Macro for easy telemetry scoping
#define MASM_SPEC_SCOPE(phase_id) TelemetryScope _telemetry_scope(phase_id)

} // namespace seg
