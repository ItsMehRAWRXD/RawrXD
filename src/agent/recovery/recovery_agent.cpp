#include "recovery_agent.hpp"
#include <iostream>

namespace rawrxd {
namespace agent {

RecoveryAgent::RecoveryAgent() = default;
RecoveryAgent::~RecoveryAgent() = default;

bool RecoveryAgent::initialize() {
    std::cout << "[RecoveryAgent] Initialized" << std::endl;
    return true;
}

bool RecoveryAgent::canRecover(const ReviewResult& review) {
    // Can recover if there are fixable issues
    for (const auto& issue : review.issues) {
        if (issue.severity == "error") {
            // Check if it's a fixable error
            if (issue.description.find("No files were modified") != std::string::npos) {
                return true; // Can retry generation
            }
            if (issue.description.find("Path traversal") != std::string::npos) {
                return false; // Security issue, cannot auto-recover
            }
        }
    }
    return !review.issues.empty();
}

bool RecoveryAgent::canRecoverFromVerification(const VerificationResult& verification) {
    // Can recover from build/test failures
    if (!verification.build_ok) {
        return true; // Can retry with build fix
    }
    if (!verification.tests_ok) {
        return true; // Can retry with test fix
    }
    return false;
}

CodeChange RecoveryAgent::generateFix(const ReviewResult& review) {
    CodeChange fix;
    fix.description = "Auto-fix for review issues";

    for (const auto& issue : review.issues) {
        if (issue.description.find("No files were modified") != std::string::npos) {
            fix.description = "Retrying code generation - no files were modified";
            break;
        }
    }

    fix.valid = true;
    std::cout << "[RecoveryAgent] Generated fix: " << fix.description << std::endl;
    return fix;
}

CodeChange RecoveryAgent::generateFixFromVerification(const VerificationResult& verification) {
    CodeChange fix;
    fix.valid = true;

    if (!verification.build_ok) {
        fix.description = "Fixing build errors";
    } else if (!verification.tests_ok) {
        fix.description = "Fixing test failures";
    }

    std::cout << "[RecoveryAgent] Generated fix from verification: " << fix.description << std::endl;
    return fix;
}

} // namespace agent
} // namespace rawrxd
