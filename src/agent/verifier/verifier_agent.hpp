#pragma once

#include <string>
#include "../core/agent_controller.hpp"

namespace rawrxd {
namespace agent {

struct VerificationResult {
    bool build_ok;
    bool tests_ok;
    std::string log;
    std::string error;
};

class VerifierAgent {
public:
    VerifierAgent();
    ~VerifierAgent();

    bool initialize();
    VerificationResult verify(const TaskRequest& request, const TaskResult& result);
};

} // namespace agent
} // namespace rawrxd
