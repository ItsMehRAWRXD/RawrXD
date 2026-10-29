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
    if (ParseRuntimeTarget("30B/8/2", target, error) ||
        error != "RUNTIME_TARGET_EXPECTED_PARAMETERS_SLASH_EXPERTS") {
        std::cerr << "RUNTIME_TARGET_MALFORMED_FAIL " << error << "\n";
        return 4;
    }
    std::cout << "REAP_RUNTIME_PLAN_TEST_PASS\n";
    return 0;
}
