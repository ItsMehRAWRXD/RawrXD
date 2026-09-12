#pragma once
#include <cstdint>
#include <cstddef>

#ifndef D2_AUTH_MAX_TOKENS
#define D2_AUTH_MAX_TOKENS 256u
#endif

namespace d2auth {

enum ScopeBits : std::uint32_t {
    SCOPE_NONE              = 0,
    SCOPE_OBSERVE           = 1u << 0,
    SCOPE_SEAL              = 1u << 1,
    SCOPE_MINT_TPS          = 1u << 2,
    SCOPE_AUTHORIZE_PROMOTE = 1u << 3,
    SCOPE_COMMIT_PROMOTE    = 1u << 4
};

enum class Op : std::uint8_t {
    GRANT_AUTHORITY = 1,
    BIND_GATE = 2,
    BIND_CERT = 3,
    BEGIN_OBSERVATION = 4,
    OBSERVE_TOKEN = 5,
    CLOSE_OBSERVATION = 6,
    VALIDATE_CARDINALITY = 7,
    VALIDATE_INTEGRITY = 8,
    VALIDATE_QPC = 9,
    CALCULATE_METRICS = 10,
    VALIDATE_PREDICATES = 11,
    SEAL_RECEIPT = 12,
    MINT_TPS_AUTHORITY = 13,
    AUTHORIZE_PROMOTE = 14,
    COMMIT_PROMOTE = 15
};

struct AuthorityGrant {
    std::uint64_t magic;          // must equal kGrantMagic
    std::uint64_t nonce;          // non-zero, one-shot caller supplied value
    std::uint32_t scope;          // ScopeBits
    std::uint32_t reserved;
    char authority_name[64];      // e.g. "Deep2ProductAuthority"
};

struct PredicateSet {
    bool full_model_forward;
    bool real_autoregressive_decode;
    bool warmup_excluded;
    bool sealed_logits_reuse_zero;
    bool synthetic_logits_zero;
    bool device_lost_zero;
    bool cert_binary_unchanged;
};

struct TokenTiming {
    std::uint64_t qpc_begin;
    std::uint64_t qpc_end;
};

struct Metrics {
    std::uint64_t generated_tokens;
    std::uint64_t wall_qpc_ticks;
    std::uint64_t min_qpc_ticks;
    std::uint64_t max_qpc_ticks;
    std::uint64_t mean_qpc_ticks;
    std::uint64_t p50_qpc_ticks;
    std::uint64_t p95_qpc_ticks;
    double sustained_tps;
};

struct Receipt {
    char gate_id[96];
    char cert_sha256_hex[65];
    std::uint64_t qpc_frequency;
    std::uint32_t target_tokens;
    std::uint32_t observed_tokens;
    PredicateSet predicates;
    Metrics metrics;
    std::uint8_t receipt_sha256[32];
};

struct State {
    bool grant_bound;
    bool gate_bound;
    bool cert_bound;
    bool observation_open;
    bool observation_closed;
    bool cardinality_valid;
    bool integrity_valid;
    bool qpc_valid;
    bool metrics_ready;
    bool predicates_valid;
    bool receipt_sealed;
    bool full_model_tps_authority;
    bool promote_authorized;
    bool promote;
    std::uint16_t op_mask_low;
    std::uint64_t grant_nonce;
};

class AuthorityMint15 {
public:
    static constexpr std::uint64_t kGrantMagic = 0x4432415554483135ull; // "D2AUTH15"

    AuthorityMint15() noexcept;

    // 1
    bool grant_authority(const AuthorityGrant& g) noexcept;
    // 2
    bool bind_gate(const char* gate_id, std::uint32_t target_tokens) noexcept;
    // 3
    bool bind_cert_sha256(const char* sha256_hex) noexcept;
    // 4
    bool begin_observation(std::uint64_t qpc_frequency,
                           const PredicateSet& predicates) noexcept;
    // 5
    bool observe_token(std::uint64_t qpc_begin, std::uint64_t qpc_end) noexcept;
    // 6
    bool close_observation() noexcept;
    // 7
    bool validate_cardinality() noexcept;
    // 8
    bool validate_integrity() noexcept;
    // 9
    bool validate_qpc() noexcept;
    // 10
    bool calculate_metrics() noexcept;
    // 11
    bool validate_predicates() noexcept;
    // 12
    bool seal_receipt() noexcept;
    // 13
    bool mint_tps_authority() noexcept;
    // 14
    bool authorize_promote() noexcept;
    // 15
    bool commit_promote() noexcept;

    const State& state() const noexcept { return state_; }
    const Receipt& receipt() const noexcept { return receipt_; }

private:
    bool has_scope(std::uint32_t bit) const noexcept;
    void mark(Op op) noexcept;
    bool prior(Op op) const noexcept;
    static bool copy_ascii(char* dst, std::size_t cap, const char* src) noexcept;
    static bool valid_sha256_hex(const char* s) noexcept;
    void hash_receipt(std::uint8_t out[32]) const noexcept;

    AuthorityGrant grant_{};
    State state_{};
    Receipt receipt_{};
    TokenTiming timings_[D2_AUTH_MAX_TOKENS]{};
    std::uint32_t timing_count_ = 0;
};

} // namespace d2auth
