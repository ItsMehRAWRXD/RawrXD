#include "reap/ReapRuntimePlan.hpp"

#include <iostream>
#include <string>

int main() {
    using RawrXD::Reap::ParseRuntimeTarget;
    RawrXD::Reap::RuntimeTarget target{};
    std::string error;

    if (!ParseRuntimeTarget("30B/8", target, error) ||
        target.parameterCount != 30000000000ULL || target.expertCount != 8) {
        std::cerr << "RUNTIME_TARGET_BASIC_FAIL " << error << "\n";
        return 1;
    }
    if (!ParseRuntimeTarget("2T/384E", target, error) ||
        target.parameterCount != 2000000000000ULL || target.expertCount != 384) {
        std::cerr << "RUNTIME_TARGET_SUFFIX_FAIL " << error << "\n";
        return 2;
    }
    // This is intentionally larger than common local models.  The parser has
    // no product-size ceiling; physical admission remains a later gate.
    if (!ParseRuntimeTarget("100T/1000000", target, error) ||
        target.parameterCount != 100000000000000ULL || target.expertCount != 1000000) {
        std::cerr << "RUNTIME_TARGET_NO_CAP_FAIL " << error << "\n";
        return 3;
    }
    if (!ParseRuntimeTarget("1B/18446744073709551615E", target, error) ||
        target.expertCount != UINT64_MAX) {
        std::cerr << "RUNTIME_TARGET_UINT64_EXPERT_FAIL " << error << "\n";
        return 4;
    }
    if (!ParseRuntimeTarget("30GB/8", target, error) ||
        target.parameterCount != 30000000000ULL || target.expertCount != 8) {
        std::cerr << "RUNTIME_TARGET_DECIMAL_GB_FAIL " << error << "\n";
        return 5;
    }
    if (ParseRuntimeTarget("1B/8.5", target, error) ||
        error != "EXPERT_TARGET_MUST_BE_INTEGER") {
        std::cerr << "RUNTIME_TARGET_FRACTIONAL_EXPERT_FAIL " << error << "\n";
        return 6;
    }
    if (ParseRuntimeTarget("30B/8/2", target, error) ||
        error != "RUNTIME_TARGET_EXPECTED_PARAMETERS_SLASH_EXPERTS") {
        std::cerr << "RUNTIME_TARGET_MALFORMED_FAIL " << error << "\n";
        return 7;
    }
    std::cout << "REAP_RUNTIME_PLAN_TEST_PASS\n";
    return 0;
}
