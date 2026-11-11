// MockPatcher.hpp
// Deterministic CI/CD patcher implementation
// Part of the Sovereign PatchRegistry abstraction layer

#ifndef MOCKPATCHER_HPP
#define MOCKPATCHER_HPP

#include "IPatcher.hpp"
#include <iostream>
#include <chrono>

namespace Sovereign {

/**
 * @class MockPatcher
 * @brief Deterministic patcher for CI/CD testing
 * 
 * This implementation simulates patch operations without
 * modifying actual process memory. It provides:
 *   - Deterministic timing for regression testing
 *   - No side effects on the host process
 *   - Configurable success/failure modes
 * 
 * Usage:
 *   PatchRegistry registry;
 *   registry.Register(std::make_shared<MockPatcher>());
 *   auto result = registry.Apply("mock", request);
 */
class MockPatcher : public IPatcher {
    bool deterministicMode = true;
    bool forceFailure = false;
    size_t patchCount = 0;

public:
    /**
     * @brief Set deterministic mode (default: true)
     * @param enabled If true, uses fixed timing; if false, uses actual sleep
     */
    void SetDeterministicMode(bool enabled) {
        deterministicMode = enabled;
    }

    /**
     * @brief Force all patches to fail (for error handling tests)
     * @param enabled If true, all Apply() calls return failure
     */
    void SetForceFailure(bool enabled) {
        forceFailure = enabled;
    }

    /**
     * @brief Get number of patches "applied" since construction
     * @return Patch count
     */
    size_t GetPatchCount() const {
        return patchCount;
    }

    PatchResult Apply(const PatchRequest& r) override {
        if (forceFailure) {
            return {
                false,
                r.address,
                "MOCK_FORCED_FAILURE"
            };
        }

        // Simulate patch latency (deterministic for CI)
        if (!deterministicMode) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }

        // Verify expected bytes match (mock validation)
        if (r.expected.empty()) {
            return {
                false,
                r.address,
                "MOCK_EXPECTED_EMPTY"
            };
        }

        patchCount++;

        return {
            true,
            r.address,
            "MOCK_PATCH_APPLIED: " + r.reason
        };
    }

    PatchResult Rollback(const PatchRequest& r) override {
        if (forceFailure) {
            return {
                false,
                r.address,
                "MOCK_FORCED_ROLLBACK_FAILURE"
            };
        }

        if (patchCount > 0) {
            patchCount--;
        }

        return {
            true,
            r.address,
            "MOCK_ROLLBACK: " + r.reason
        };
    }

    const char* Name() const override {
        return "mock";
    }
};

} // namespace Sovereign

#endif // MOCKPATCHER_HPP
