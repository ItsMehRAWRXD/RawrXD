// ============================================================================
// MARSController_test.cpp — Isolated certification tests
// ============================================================================
#include <cstdio>
#include <cmath>
#include <vector>
#include "deep2/mars/MARSController.hpp"

using Deep2::MARSController;
using Deep2::MARSConfig;
using Deep2::MARSStats;

// --------------------------------------------------------------------------
// 1) basic_lifecycle
// --------------------------------------------------------------------------
bool test_basic_lifecycle() {
    MARSController m;
    if (m.isInitialized()) return false;
    if (!m.initialize(1024, 1024)) return false;
    if (!m.isInitialized()) return false;
    m.shutdown();
    if (m.isInitialized()) return false;
    return true;
}

// --------------------------------------------------------------------------
// 2) place_tensor
// --------------------------------------------------------------------------
bool test_place_tensor() {
    MARSController m;
    m.initialize(1024, 1024);
    auto* lease = m.placeTensor(1, "t1", 256, 1.0f);
    if (!lease) return false;
    if (lease->bytes != 256) return false;
    if (lease->gpu != 0 && lease->gpu != 1) return false;
    m.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// 3) redirect_tensor
// --------------------------------------------------------------------------
bool test_redirect_tensor() {
    MARSController m;
    m.initialize(1024, 1024);
    m.placeTensor(1, "t1", 256, 1.0f);
    auto res = m.redirectTensor(1, 1);
    if (!res.ok) return false;
    if (res.toGpu != 1) return false;
    m.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// 4) rebalance
// --------------------------------------------------------------------------
bool test_rebalance() {
    MARSController m;
    m.initialize(1000, 1000);
    m.placeTensor(1, "t1", 900, 1.0f); // heavy on GPU0
    m.placeTensor(2, "t2", 50,  1.0f); // light on GPU1
    auto dp1 = m.getDynamicParity();
    if (dp1.balanced) return false; // should be unbalanced
    m.resetStats();
    bool moved = m.rebalance();
    if (!moved) return false;
    auto st = m.stats();
    if (st.rebalances != 1) return false;
    m.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// 5) handle_tensor_fault
// --------------------------------------------------------------------------
bool test_handle_tensor_fault() {
    MARSController m;
    m.initialize(1024, 1024);
    m.placeTensor(1, "t1", 256, 1.0f);
    if (!m.handleTensorFault(1)) return false;
    auto* lease = m.getLease(1);
    if (!lease || lease->gpu != -1) return false;
    m.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// 6) handle_gpu_failure
// --------------------------------------------------------------------------
bool test_handle_gpu_failure() {
    MARSController m;
    m.initialize(1024, 1024);
    m.placeTensor(1, "t1", 256, 1.0f);
    m.placeTensor(2, "t2", 128, 1.0f);
    if (!m.handleGPUFailure(0)) return false;
    auto* l1 = m.getLease(1);
    auto* l2 = m.getLease(2);
    if (!l1 || l1->gpu != 1) return false;
    if (!l2 || l2->gpu != 1) return false;
    m.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// 7) parity_test
// --------------------------------------------------------------------------
bool test_parity_test() {
    MARSController m;
    m.initialize(1024, 1024);
    m.placeTensor(1, "t1", 256, 1.0f);
    m.placeTensor(2, "t2", 256, 1.0f);
    if (!m.parityTest(0.5f)) return false;
    m.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// 8) stats_accounted
// --------------------------------------------------------------------------
bool test_stats_accounted() {
    MARSController m;
    m.initialize(1024, 1024);
    m.resetStats();
    m.placeTensor(1, "t1", 256, 1.0f);
    m.redirectTensor(1, 1);
    auto st = m.stats();
    if (st.placements != 1) return false;
    if (st.redirects != 1) return false;
    m.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// main
// --------------------------------------------------------------------------
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    struct Case { const char* name; bool (*fn)(); };
    Case cases[] = {
        {"basic_lifecycle",    test_basic_lifecycle},
        {"place_tensor",       test_place_tensor},
        {"redirect_tensor",    test_redirect_tensor},
        {"rebalance",          test_rebalance},
        {"handle_tensor_fault", test_handle_tensor_fault},
        {"handle_gpu_failure", test_handle_gpu_failure},
        {"parity_test",        test_parity_test},
        {"stats_accounted",    test_stats_accounted},
    };
    int passed = 0, failed = 0;
    for (const auto& c : cases) {
        bool ok = c.fn();
        if (ok) { std::printf("PASS: %s\n", c.name); ++passed; }
        else    { std::printf("FAIL: %s\n", c.name); ++failed; }
    }
    std::printf("=== %d passed, %d failed ===\n", passed, failed);
    return failed ? 1 : 0;
}
