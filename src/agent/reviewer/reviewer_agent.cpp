#include "reviewer_agent.hpp"
#include <iostream>

namespace rawrxd {
namespace agent {

ReviewerAgent::ReviewerAgent() = default;
ReviewerAgent::~ReviewerAgent() = default;

bool ReviewerAgent::initialize() {
    std::cout << "[ReviewerAgent] Initialized" << std::endl;
    return true;
}

ReviewResult ReviewerAgent::review(const TaskRequest& request, const TaskResult& result) {
    ReviewResult review;
    review.accepted = true;

    // Check if files were modified
    if (result.files_modified.empty()) {
        review.issues.push_back({"", "No files were modified", "warning"});
        review.accepted = false;
    }

    // Check for errors
    if (!result.error.empty()) {
        review.issues.push_back({"", "Task has errors: " + result.error, "error"});
        review.accepted = false;
    }

    // Check for suspicious patterns in modified files
    for (const auto& file : result.files_modified) {
        if (file.find("..") != std::string::npos) {
            review.issues.push_back({file, "Path traversal detected", "error"});
            review.accepted = false;
        }
    }

    if (review.accepted) {
        review.summary = "Review passed: " + std::to_string(result.files_modified.size()) + " files modified";
    } else {
        review.summary = "Review failed: " + std::to_string(review.issues.size()) + " issues found";
    }

    std::cout << "[ReviewerAgent] Review " << (review.accepted ? "PASSED" : "FAILED")
              << " (" << review.issues.size() << " issues)" << std::endl;
    return review;
}

} // namespace agent
} // namespace rawrxd
