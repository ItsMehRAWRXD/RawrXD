#pragma once

#include <string>
#include <vector>
#include "../core/agent_controller.hpp"

namespace rawrxd {
namespace agent {

struct ReviewIssue {
    std::string file;
    std::string description;
    std::string severity; // "error", "warning", "info"
};

struct ReviewResult {
    bool accepted;
    std::vector<ReviewIssue> issues;
    std::string summary;
};

class ReviewerAgent {
public:
    ReviewerAgent();
    ~ReviewerAgent();

    bool initialize();
    ReviewResult review(const TaskRequest& request, const TaskResult& result);
};

} // namespace agent
} // namespace rawrxd
