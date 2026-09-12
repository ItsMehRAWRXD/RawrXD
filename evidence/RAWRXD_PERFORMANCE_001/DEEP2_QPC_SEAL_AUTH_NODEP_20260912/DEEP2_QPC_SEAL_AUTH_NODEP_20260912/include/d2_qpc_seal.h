#pragma once
#include <cstdint>
#include <cstddef>

#ifndef D2_QPC_MAX_TOKENS
#define D2_QPC_MAX_TOKENS 256u
#endif

namespace d2qpc {

enum Scope : std::uint32_t {
    SCOPE_NONE = 0,
    SCOPE_MEASURE = 1u << 0,
    SCOPE_SEAL = 1u << 1,
    SCOPE_MINT_TPS = 1u << 2
};

struct Grant {
    std::uint64_t magic;
    std::uint64_t nonce;
    std::uint32_t scope;
    std::uint32_t reserved;
    char authority_name[64];
};

struct Predicates {
    bool full_model_forward;
    bool real_autoregressive_decode;
    bool warmup_excluded;
    bool sealed_logits_reuse_zero;
    bool synthetic_logits_zero;
    bool device_lost_zero;
    bool cert_binary_unchanged;
};

struct Sample {
    std::uint64_t begin_qpc;
    std::uint64_t end_qpc;
};

struct Metrics {
    std::uint64_t generated_tokens;
    std::uint64_t generation_wall_qpc;
    std::uint64_t token_min_qpc;
    std::uint64_t token_max_qpc;
    std::uint64_t token_mean_qpc;
    std::uint64_t token_p50_qpc;
    std::uint64_t token_p95_qpc;

    std::uint64_t generation_wall_ns;
    std::uint64_t token_min_ns;
    std::uint64_t token_max_ns;
    std::uint64_t token_mean_ns;
    std::uint64_t token_p50_ns;
    std::uint64_t token_p95_ns;

    double sustained_tps;
};

struct Receipt {
    char gate_id[96];
    char cert_sha256_hex[65];
    char authority_name[64];

    std::uint64_t grant_nonce;
    std::uint64_t qpc_frequency;
    std::uint32_t target_tokens;
    std::uint32_t observed_tokens;

    Predicates predicates;
    Metrics metrics;

    std::uint8_t receipt_sha256[32];
};

struct State {
    bool grant_bound;
    bool identity_bound;
    bool qpc_bound;
    bool observation_open;
    bool token_open;
    bool observation_closed;
    bool cardinality_valid;
    bool qpc_valid;
    bool predicates_valid;
    bool receipt_sealed;
    bool full_model_tps_authority;
};

using QpcNowFn = bool (*)(void* user, std::uint64_t* out_qpc) noexcept;
using QpcFrequencyFn = bool (*)(void* user, std::uint64_t* out_frequency) noexcept;

struct QpcProvider {
    void* user;
    QpcNowFn now;
    QpcFrequencyFn frequency;
};

// Implemented by src/d2_qpc_win32.cpp without windows.h.
// On Windows this binds directly to Kernel32 QueryPerformanceCounter/Frequency.
bool bind_win32_qpc(QpcProvider* out) noexcept;

class SealAuthority {
public:
    static constexpr std::uint64_t kGrantMagic = 0x4432515043534541ull; // "D2QPCSEA"

    SealAuthority() noexcept;

    bool grant(const Grant& g) noexcept;
    bool bind_identity(const char* gate_id,
                       const char* cert_sha256_hex,
                       std::uint32_t target_tokens) noexcept;
    bool bind_qpc(const QpcProvider& qpc) noexcept;

    // Predicates are observations from the measured path, not defaults.
    bool open(const Predicates& p) noexcept;

    // Call immediately before the real full-forward token execution.
    bool token_begin() noexcept;

    // Call immediately after the same token's full forward completes.
    bool token_end() noexcept;

    // No more timing samples may be added after this.
    bool close() noexcept;

    // Validation + metrics do not mint authority.
    bool validate() noexcept;
    bool calculate() noexcept;

    // Requires SCOPE_SEAL and a valid closed run.
    bool seal() noexcept;

    // Requires SCOPE_MINT_TPS plus a sealed, valid receipt.
    bool mint_tps_authority() noexcept;

    const State& state() const noexcept { return state_; }
    const Receipt& receipt() const noexcept { return receipt_; }
    const Sample* samples() const noexcept { return samples_; }

private:
    bool has_scope(std::uint32_t bit) const noexcept;
    static bool copy_ascii(char* dst, std::size_t cap, const char* src) noexcept;
    static bool valid_sha256_hex(const char* s) noexcept;
    static std::uint64_t qpc_to_ns(std::uint64_t ticks,
                                   std::uint64_t frequency) noexcept;
    void hash_receipt(std::uint8_t out[32]) const noexcept;

    Grant grant_{};
    QpcProvider qpc_{};
    State state_{};
    Receipt receipt_{};
    Sample samples_[D2_QPC_MAX_TOKENS]{};
    std::uint32_t sample_count_ = 0;
    std::uint64_t pending_begin_ = 0;
};

} // namespace d2qpc
