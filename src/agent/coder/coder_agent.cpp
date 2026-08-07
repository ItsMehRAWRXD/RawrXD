#include "coder_agent.hpp"
#include <iostream>
#include <fstream>
#include <sstream>

namespace rawrxd {
namespace agent {

CoderAgent::CoderAgent() = default;
CoderAgent::~CoderAgent() = default;

bool CoderAgent::initialize() {
    std::cout << "[CoderAgent] Initialized" << std::endl;
    return true;
}

CodeChange CoderAgent::generate(const PlanStep& step) {
    CodeChange change;
    change.file = step.target;
    change.description = step.description;

    if (step.action == "read_context") {
        // Read the target file for context
        std::ifstream file(step.target);
        if (file) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            change.before = buffer.str();
            change.valid = true;
        } else {
            change.valid = true; // File may not exist yet (new file)
        }
    } else if (step.action == "generate_code" || step.action == "generate_fix") {
        // In a full implementation, this would call Deep2 for code generation
        // For now, mark as valid and let the controller handle it
        change.valid = true;
    } else if (step.action == "apply_patch") {
        // Apply the generated patch to the file
        if (!change.patch.empty()) {
            std::ofstream file(step.target);
            if (file) {
                file << change.after;
                change.valid = true;
            }
        } else {
            change.valid = true; // No patch to apply
        }
    } else {
        change.valid = true; // Non-code step
    }

    return change;
}

bool CoderAgent::apply(const CodeChange& change) {
    if (!change.valid || change.file.empty()) {
        return false;
    }

    std::ofstream file(change.file);
    if (!file) {
        std::cerr << "[CoderAgent] Failed to write: " << change.file << std::endl;
        return false;
    }

    file << change.after;
    std::cout << "[CoderAgent] Applied changes to: " << change.file << std::endl;
    return true;
}

} // namespace agent
} // namespace rawrxd
