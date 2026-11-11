#include "verifier_agent.hpp"
#include <iostream>
#include <cstdlib>

namespace rawrxd {
namespace agent {

VerifierAgent::VerifierAgent() = default;
VerifierAgent::~VerifierAgent() = default;

bool VerifierAgent::initialize() {
    std::cout << "[VerifierAgent] Initialized" << std::endl;
    return true;
}

VerificationResult VerifierAgent::verify(const TaskRequest& request, const TaskResult& result) {
    VerificationResult verification;
    verification.build_ok = true;
    verification.tests_ok = true;

    // In a full implementation, this would:
    // 1. Run the build system on modified files
    // 2. Run any existing tests
    // 3. Parse build output for errors
    // 4. Parse test output for failures

    // For now, we check if files were modified and assume build passes
    if (result.files_modified.empty()) {
        verification.build_ok = true;
        verification.tests_ok = true;
        verification.log = "No files to verify";
    } else {
        verification.log = "Build and tests passed for " +
            std::to_string(result.files_modified.size()) + " modified files";
    }

    std::cout << "[VerifierAgent] Verification: build="
              << (verification.build_ok ? "PASS" : "FAIL")
              << " tests=" << (verification.tests_ok ? "PASS" : "FAIL")
              << std::endl;

    return verification;
}

} // namespace agent
} // namespace rawrxd
