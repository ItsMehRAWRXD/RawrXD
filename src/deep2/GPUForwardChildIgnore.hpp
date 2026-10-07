#pragma once
// Deep2 GPU-forward one-child-ignore diagnostic ladder.
// Header-only, standard C++17, no third-party dependencies.
// Diagnostic law: one ignored child per run; runtime emission owns only itself;
// this module never promotes a result and never manufactures child evidence.

#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace RawrXD::Deep2::GpuForwardIgnore {

enum class Child : std::uint8_t {
    None = 0,
    InputNorm,
    QKV,
    RoPE,
    KVUpdate,
    DeviceAttention,
    AttentionOutputProj,
    PostAttentionNorm,
    FFN,
    FFNUpGate,
    FFNActivation,
    FFNDown,
    MoERoute,
    MoEExperts,
    Residual,
    QuantGEMV,
    UploadH2D,
    CommandSubmit,
    SyncWait,
    ReadbackD2H,
    Other,
    Count
};

struct Counter {
    std::atomic<std::uint64_t> attempted{0};
    std::atomic<std::uint64_t> executed{0};
    std::atomic<std::uint64_t> ignored{0};
    std::atomic<std::uint64_t> elapsedNs{0};
};

struct Config {
    bool armed = false;
    bool valid = true;
    Child ignored = Child::None;
    const char* raw = nullptr;
};

inline const char* Name(Child c) noexcept {
    switch (c) {
    case Child::None:                return "NONE";
    case Child::InputNorm:           return "INPUT_NORM";
    case Child::QKV:                 return "QKV";
    case Child::RoPE:                return "ROPE";
    case Child::KVUpdate:            return "KV_UPDATE";
    case Child::DeviceAttention:     return "DEVICE_ATTN";
    case Child::AttentionOutputProj: return "ATTN_OUTPUT_PROJ";
    case Child::PostAttentionNorm:   return "POST_ATTN_NORM";
    case Child::FFN:                 return "FFN";
    case Child::FFNUpGate:           return "FFN_UP_GATE";
    case Child::FFNActivation:       return "FFN_ACTIVATION";
    case Child::FFNDown:             return "FFN_DOWN";
    case Child::MoERoute:            return "MOE_ROUTE";
    case Child::MoEExperts:          return "MOE_EXPERTS";
    case Child::Residual:            return "RESIDUAL";
    case Child::QuantGEMV:           return "QUANT_GEMV";
    case Child::UploadH2D:           return "UPLOAD_H2D";
    case Child::CommandSubmit:       return "COMMAND_SUBMIT";
    case Child::SyncWait:            return "SYNC_WAIT";
    case Child::ReadbackD2H:         return "READBACK_D2H";
    case Child::Other:               return "OTHER";
    default:                         return "INVALID";
    }
}

inline bool EqAsciiNoCase(const char* a, const char* b) noexcept {
    if (!a || !b) return a == b;
    while (*a && *b) {
        const unsigned char ca = static_cast<unsigned char>(*a++);
        const unsigned char cb = static_cast<unsigned char>(*b++);
        if (std::toupper(ca) != std::toupper(cb)) return false;
    }
    return *a == 0 && *b == 0;
}

inline bool HasMultipleSelector(const char* s) noexcept {
    if (!s) return false;
    for (; *s; ++s) {
        if (*s == ',' || *s == ';' || *s == '|' || *s == '+') return true;
    }
    return false;
}

inline Child ParseChild(const char* s) noexcept {
    if (!s || !*s || EqAsciiNoCase(s, "NONE") || EqAsciiNoCase(s, "0")) return Child::None;
    if (EqAsciiNoCase(s, "INPUT_NORM") || EqAsciiNoCase(s, "NORM")) return Child::InputNorm;
    if (EqAsciiNoCase(s, "QKV") || EqAsciiNoCase(s, "GPU_QKV")) return Child::QKV;
    if (EqAsciiNoCase(s, "ROPE")) return Child::RoPE;
    if (EqAsciiNoCase(s, "KV_UPDATE") || EqAsciiNoCase(s, "KV_CONSUMER")) return Child::KVUpdate;
    if (EqAsciiNoCase(s, "DEVICE_ATTN") || EqAsciiNoCase(s, "ATTENTION") || EqAsciiNoCase(s, "GPU_ATTN")) return Child::DeviceAttention;
    if (EqAsciiNoCase(s, "ATTN_OUTPUT_PROJ") || EqAsciiNoCase(s, "OUTPUT_PROJ")) return Child::AttentionOutputProj;
    if (EqAsciiNoCase(s, "POST_ATTN_NORM")) return Child::PostAttentionNorm;
    if (EqAsciiNoCase(s, "FFN") || EqAsciiNoCase(s, "GPU_FFN")) return Child::FFN;
    if (EqAsciiNoCase(s, "FFN_UP_GATE") || EqAsciiNoCase(s, "UP_GATE")) return Child::FFNUpGate;
    if (EqAsciiNoCase(s, "FFN_ACTIVATION") || EqAsciiNoCase(s, "ACTIVATION")) return Child::FFNActivation;
    if (EqAsciiNoCase(s, "FFN_DOWN") || EqAsciiNoCase(s, "DOWN_PROJ")) return Child::FFNDown;
    if (EqAsciiNoCase(s, "MOE_ROUTE")) return Child::MoERoute;
    if (EqAsciiNoCase(s, "MOE_EXPERTS") || EqAsciiNoCase(s, "EXPERT_DISPATCH")) return Child::MoEExperts;
    if (EqAsciiNoCase(s, "RESIDUAL")) return Child::Residual;
    if (EqAsciiNoCase(s, "QUANT_GEMV") || EqAsciiNoCase(s, "GEMV")) return Child::QuantGEMV;
    if (EqAsciiNoCase(s, "UPLOAD_H2D") || EqAsciiNoCase(s, "H2D")) return Child::UploadH2D;
    if (EqAsciiNoCase(s, "COMMAND_SUBMIT") || EqAsciiNoCase(s, "SUBMIT")) return Child::CommandSubmit;
    if (EqAsciiNoCase(s, "SYNC_WAIT") || EqAsciiNoCase(s, "SYNC") || EqAsciiNoCase(s, "WAIT")) return Child::SyncWait;
    if (EqAsciiNoCase(s, "READBACK_D2H") || EqAsciiNoCase(s, "READBACK") || EqAsciiNoCase(s, "D2H")) return Child::ReadbackD2H;
    if (EqAsciiNoCase(s, "OTHER")) return Child::Other;
    return Child::Count;
}

class State {
public:
    static State& Get() noexcept {
        static State s;
        return s;
    }

    void ConfigureFromEnvironment() noexcept {
        const char* raw = std::getenv("DEEP2_GPU_FORWARD_IGNORE");
        config_.raw = raw;
        config_.armed = raw && *raw;
        config_.valid = true;
        config_.ignored = Child::None;

        if (!config_.armed) return;
        if (HasMultipleSelector(raw)) {
            config_.valid = false;
            return;
        }
        const Child parsed = ParseChild(raw);
        if (parsed == Child::Count) {
            config_.valid = false;
            return;
        }
        config_.ignored = parsed;
    }

    const Config& config() const noexcept { return config_; }

    void ResetCounters() noexcept {
        gpuForwardLayers_.store(0, std::memory_order_relaxed);
        for (auto& c : counters_) {
            c.attempted.store(0, std::memory_order_relaxed);
            c.executed.store(0, std::memory_order_relaxed);
            c.ignored.store(0, std::memory_order_relaxed);
            c.elapsedNs.store(0, std::memory_order_relaxed);
        }
    }

    void BeginRun() noexcept {
        ResetCounters();
        ConfigureFromEnvironment();
    }

    void MarkForwardLayer() noexcept {
        gpuForwardLayers_.fetch_add(1, std::memory_order_relaxed);
    }

    std::uint64_t gpuForwardLayers() const noexcept {
        return gpuForwardLayers_.load(std::memory_order_relaxed);
    }

    bool Decide(Child child) noexcept {
        if (child == Child::None || child == Child::Count) return false;
        Counter& c = counters_[Index(child)];
        c.attempted.fetch_add(1, std::memory_order_relaxed);
        const bool skip = config_.armed && config_.valid && config_.ignored == child;
        if (skip) c.ignored.fetch_add(1, std::memory_order_relaxed);
        return skip;
    }

    void MarkExecuted(Child child, std::uint64_t elapsedNs) noexcept {
        if (child == Child::None || child == Child::Count) return;
        Counter& c = counters_[Index(child)];
        c.executed.fetch_add(1, std::memory_order_relaxed);
        c.elapsedNs.fetch_add(elapsedNs, std::memory_order_relaxed);
    }

    const Counter& counter(Child child) const noexcept {
        return counters_[Index(child)];
    }

    bool EvidenceFired(Child child) const noexcept {
        if (child == Child::None || child == Child::Count) return false;
        const Counter& c = counters_[Index(child)];
        return c.attempted.load(std::memory_order_relaxed) != 0;
    }

    void Emit(FILE* out = stderr) const noexcept {
        if (!out) return;
        std::fprintf(out, "GPU_FORWARD_CHILD_IGNORE_DROP=1\n");
        std::fprintf(out, "GPU_FORWARD_IGNORE_ARMED=%d\n", config_.armed ? 1 : 0);
        std::fprintf(out, "GPU_FORWARD_IGNORE_VALID=%d\n", config_.valid ? 1 : 0);
        std::fprintf(out, "GPU_FORWARD_IGNORE_CHILD=%s\n", config_.valid ? Name(config_.ignored) : "INVALID");
        std::fprintf(out, "GPU_FORWARD_ONE_IGNORE_ONLY=1\n");
        std::fprintf(out, "GPU_FORWARD_LAYERS=%llu\n", static_cast<unsigned long long>(gpuForwardLayers()));

        for (std::size_t i = 1; i < static_cast<std::size_t>(Child::Count); ++i) {
            const Child child = static_cast<Child>(i);
            const Counter& c = counters_[i];
            const auto a = c.attempted.load(std::memory_order_relaxed);
            const auto e = c.executed.load(std::memory_order_relaxed);
            const auto g = c.ignored.load(std::memory_order_relaxed);
            const auto n = c.elapsedNs.load(std::memory_order_relaxed);
            if (a == 0 && e == 0 && g == 0 && n == 0) continue; // no invented evidence
            std::fprintf(out,
                "GPU_CHILD=%s ATTEMPTED=%llu EXECUTED=%llu IGNORED=%llu NS=%llu MS=%.3f\n",
                Name(child),
                static_cast<unsigned long long>(a),
                static_cast<unsigned long long>(e),
                static_cast<unsigned long long>(g),
                static_cast<unsigned long long>(n),
                static_cast<double>(n) / 1000000.0);
        }

        const Child selected = config_.ignored;
        const int selectedFired = (config_.valid && selected != Child::None && selected != Child::Count && EvidenceFired(selected)) ? 1 : 0;
        std::fprintf(out, "SELECTED_CHILD_EVIDENCE_FIRED=%d\n", selectedFired);
        std::fprintf(out, "CLAIM_AUTHORITY=OWN_RUNTIME_EMISSION_ONLY\n");
        std::fprintf(out, "PROMOTE=0\n");
    }

private:
    static constexpr std::size_t Index(Child c) noexcept {
        return static_cast<std::size_t>(c);
    }

    State() noexcept { ConfigureFromEnvironment(); }

    Config config_{};
    std::atomic<std::uint64_t> gpuForwardLayers_{0};
    std::array<Counter, static_cast<std::size_t>(Child::Count)> counters_{};
};

class Scope {
public:
    explicit Scope(Child child) noexcept
        : state_(State::Get()), child_(child), skipped_(state_.Decide(child)), start_(Clock::now()) {}

    ~Scope() noexcept {
        if (!skipped_) {
            const auto end = Clock::now();
            const auto ns = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_).count());
            state_.MarkExecuted(child_, ns);
        }
    }

    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

    bool skipped() const noexcept { return skipped_; }
    Child child() const noexcept { return child_; }

private:
    using Clock = std::chrono::steady_clock;
    State& state_;
    Child child_;
    bool skipped_;
    Clock::time_point start_;
};

// Use at the outer Vulkan-resident layer-forward entry.
inline void MarkGpuForwardLayer() noexcept { State::Get().MarkForwardLayer(); }

// Call once immediately before the model run, after env vars are fixed.
inline void BeginRun() noexcept { State::Get().BeginRun(); }

// Call once after the run; only fired counters are printed.
inline void EmitReceipt(FILE* out = stderr) noexcept { State::Get().Emit(out); }

} // namespace RawrXD::Deep2::GpuForwardIgnore
