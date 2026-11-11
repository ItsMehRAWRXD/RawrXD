#pragma once

#include <string>
#include "../core/agent_controller.hpp"
#include "../reviewer/reviewer_agent.hpp"
#include "../verifier/verifier_agent.hpp"
#include "../coder/coder_agent.hpp"

namespace rawrxd {
namespace agent {

class RecoveryAgent {
public:
    RecoveryAgent();
    ~RecoveryAgent();

    bool initialize();
    bool canRecover(const ReviewResult& review);
    bool canRecoverFromVerification(const VerificationResult& verification);
    CodeChange generateFix(const ReviewResult& review);
    CodeChange generateFixFromVerification(const VerificationResult& verification);
};

} // namespace agent
} // namespace rawrxd
