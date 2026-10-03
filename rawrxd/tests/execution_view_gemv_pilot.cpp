// ============================================================================
// execution_view_gemv_pilot.cpp
// RAWRXD_SPACELESS_EXECUTION_VIEW_GEMV_001 — A/B parity test
//
// Verifies that gemvF32 produces IDENTICAL output when called through the
// ExecutionView path vs the legacy WeightTensor path.
// The ExecutionView points at the SAME bytes as the WeightTensor.
// No residency change. No relocation. Just the abstraction.
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cmath>
#include <vector>
#include <string>

// Minimal WeightTensor stand-in (same layout as Deep2Engine.h)
struct WeightTensor {
    void*       data      = nullptr;
    int         type      = 0;        // 0 = F32
    std::size_t rows      = 0;
    std::size_t cols      = 0;
    std::size_t sizeBytes = 0;
};

// Minimal TensorIdentity
struct TensorIdentity {
    uint64_t model   = 0;
    uint64_t tensor  = 0;
    uint32_t layer   = 0;
    uint16_t role    = 0;
    uint16_t variant = 0;
    bool operator==(const TensorIdentity& o) const noexcept {
        return model == o.model && tensor == o.tensor && layer == o.layer
            && role == o.role && variant == o.variant;
    }
};

struct LeaseToken {
    uint64_t generation = 0;
    uint64_t owner      = 0;
    uint32_t epoch      = 0;
    bool operator==(const LeaseToken& o) const noexcept {
        return generation == o.generation && owner == o.owner && epoch == o.epoch;
    }
};

struct ExecutionView {
    TensorIdentity identity;
    void*          transientAddress = nullptr;
    std::size_t    bytes            = 0;
    LeaseToken     lease;

    bool hasBytes() const noexcept { return transientAddress != nullptr && bytes > 0; }
    template<typename T> const T* as() const noexcept { return static_cast<const T*>(transientAddress); }
};

// ============================================================================
// NEW path: ExecutionView GEMV
// ============================================================================
bool gemvF32(const ExecutionView& ev, const float* x, float* y, std::size_t rows,
             std::size_t cols, const char* what)
{
    if (!ev.hasBytes()) {
        std::fprintf(stderr, "[EV_GEMV] %s ExecutionView has no bytes\n", what);
        return false;
    }
    const float* p = ev.as<float>();
    for (std::size_t r = 0; r < rows; ++r) {
        double acc = 0.0;
        for (std::size_t c = 0; c < cols; ++c) acc += double(p[r * cols + c]) * double(x[c]);
        y[r] = float(acc);
    }
    return true;
}

// ============================================================================
// LEGACY A/B reference path: delegates to ExecutionView with same pointer
// ============================================================================
static ExecutionView MakeExecutionView(const WeightTensor& wt, uint32_t layer, uint16_t role)
{
    ExecutionView ev;
    ev.identity.model   = 1;
    ev.identity.tensor  = wt.sizeBytes;
    ev.identity.layer   = layer;
    ev.identity.role    = role;
    ev.identity.variant = 0;
    ev.transientAddress = wt.data;
    ev.bytes            = wt.sizeBytes;
    ev.lease.generation = 1;
    ev.lease.owner      = 1;
    ev.lease.epoch      = 0;
    return ev;
}

bool gemvF32_legacy(const WeightTensor& w, const float* x, float* y, std::size_t rows,
                    std::size_t cols, const char* what)
{
    if (!w.data || w.type != 0) {
        std::fprintf(stderr, "[LEGACY] %s not F32\n", what);
        return false;
    }
    if (w.rows != rows || w.cols != cols) {
        std::fprintf(stderr, "[LEGACY] %s geometry mismatch\n", what);
        return false;
    }
    ExecutionView ev = MakeExecutionView(w, /*layer*/0, /*role*/0);
    return gemvF32(ev, x, y, rows, cols, what);
}

// ============================================================================
// Direct legacy (no ExecutionView) — for A/B comparison
// ============================================================================
bool gemvF32_direct(const WeightTensor& w, const float* x, float* y, std::size_t rows,
                    std::size_t cols, const char* what)
{
    if (!w.data || w.type != 0) return false;
    if (w.rows != rows || w.cols != cols) return false;
    const float* p = static_cast<const float*>(w.data);
    for (std::size_t r = 0; r < rows; ++r) {
        double acc = 0.0;
        for (std::size_t c = 0; c < cols; ++c) acc += double(p[r * cols + c]) * double(x[c]);
        y[r] = float(acc);
    }
    return true;
}

// ============================================================================
// Test harness
// ============================================================================
struct Receipt {
    int checksTotal   = 0;
    int checksPass    = 0;
    int checksFail    = 0;
    int identityBytes = sizeof(TensorIdentity);
    int evBytes       = sizeof(ExecutionView);
};

int main()
{
    std::fprintf(stderr,
        "RAWRXD_SPACELESS_EXECUTION_VIEW_GEMV_001\n"
        "A/B parity: ExecutionView vs direct pointer\n"
        "TensorIdentity_size=%zu ExecutionView_size=%zu\n",
        sizeof(TensorIdentity), sizeof(ExecutionView));

    Receipt r{};

    // --- Synthetic dense F32 weight matrix [3, 4] ---
    const std::size_t R = 3, C = 4;
    std::vector<float> weights = {
        1.0f, 2.0f, 3.0f, 4.0f,
        5.0f, 6.0f, 7.0f, 8.0f,
        9.0f, 10.0f, 11.0f, 12.0f
    };
    std::vector<float> input = { 0.5f, 1.0f, 1.5f, 2.0f };
    std::vector<float> out_legacy(R, 0.0f);
    std::vector<float> out_direct(R, 0.0f);

    WeightTensor wt;
    wt.data      = weights.data();
    wt.type      = 0;
    wt.rows      = R;
    wt.cols      = C;
    wt.sizeBytes = weights.size() * sizeof(float);

    // --- C1: ExecutionView path (new) ---
    ++r.checksTotal;
    bool ok1 = gemvF32_legacy(wt, input.data(), out_legacy.data(), R, C, "test");
    if (ok1) {
        ++r.checksPass;
        std::fprintf(stderr, "C1_EXECUTION_VIEW_PATH=OK\n");
    } else {
        ++r.checksFail;
        std::fprintf(stderr, "C1_EXECUTION_VIEW_PATH=FAIL\n");
    }

    // --- C2: Direct pointer path (A/B reference) ---
    ++r.checksTotal;
    bool ok2 = gemvF32_direct(wt, input.data(), out_direct.data(), R, C, "test");
    if (ok2) {
        ++r.checksPass;
        std::fprintf(stderr, "C2_DIRECT_PATH=OK\n");
    } else {
        ++r.checksFail;
        std::fprintf(stderr, "C2_DIRECT_PATH=FAIL\n");
    }

    // --- C3: Output parity ---
    ++r.checksTotal;
    bool match = true;
    double maxDiff = 0.0;
    for (std::size_t i = 0; i < R; ++i) {
        double diff = std::abs(double(out_legacy[i]) - double(out_direct[i]));
        if (diff > maxDiff) maxDiff = diff;
        if (diff > 1e-9) match = false;
    }
    if (match) {
        ++r.checksPass;
        std::fprintf(stderr, "C3_OUTPUT_PARITY=PASS max_diff=%.3e\n", maxDiff);
    } else {
        ++r.checksFail;
        std::fprintf(stderr, "C3_OUTPUT_PARITY=FAIL max_diff=%.3e\n", maxDiff);
    }

    // --- C4: Identity has no pointer ---
    ++r.checksTotal;
    bool noPtr = (sizeof(TensorIdentity) == sizeof(uint64_t)*2 + sizeof(uint32_t) + sizeof(uint16_t)*2);
    if (noPtr) {
        ++r.checksPass;
        std::fprintf(stderr, "C4_IDENTITY_NO_POINTER=PASS size=%d\n", r.identityBytes);
    } else {
        ++r.checksFail;
        std::fprintf(stderr, "C4_IDENTITY_NO_POINTER=FAIL size=%d\n", r.identityBytes);
    }

    // --- C5: ExecutionView contains pointer but identity does not ---
    ++r.checksTotal;
    // ExecutionView is larger because it carries the transient address
    bool viewHasPtr = (sizeof(ExecutionView) > sizeof(TensorIdentity));
    if (viewHasPtr) {
        ++r.checksPass;
        std::fprintf(stderr, "C5_VIEW_HAS_POINTER=PASS ev=%d identity=%d\n", r.evBytes, r.identityBytes);
    } else {
        ++r.checksFail;
        std::fprintf(stderr, "C5_VIEW_HAS_POINTER=FAIL ev=%d identity=%d\n", r.evBytes, r.identityBytes);
    }

    // --- C6: LeaseToken is trivial (<= 24 bytes with alignment padding) ---
    ++r.checksTotal;
    bool leaseTrivial = sizeof(LeaseToken) <= 24;
    if (leaseTrivial) {
        ++r.checksPass;
        std::fprintf(stderr, "C6_LEASE_TRIVIAL=PASS size=%zu\n", sizeof(LeaseToken));
    } else {
        ++r.checksFail;
        std::fprintf(stderr, "C6_LEASE_TRIVIAL=FAIL size=%zu\n", sizeof(LeaseToken));
    }

    // --- Verdict ---
    const char* verdict = (r.checksFail == 0) ? "PASS" : "FAIL";
    std::fprintf(stderr,
        "CHECKS_TOTAL=%d CHECKS_PASS=%d CHECKS_FAIL=%d\n"
        "VERDICT=%s\n",
        r.checksTotal, r.checksPass, r.checksFail, verdict);

    return r.checksFail;
}
