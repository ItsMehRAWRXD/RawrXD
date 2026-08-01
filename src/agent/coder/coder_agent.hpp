#pragma once

#include <string>
#include "../core/agent_controller.hpp"

namespace rawrxd {
namespace agent {

struct CodeChange {
    std::string file;
    std::string before;
    std::string after;
    std::string patch;
    std::string description;
    bool valid;

    CodeChange() : valid(false) {}
};

class CoderAgent {
public:
    CoderAgent();
    ~CoderAgent();

    bool initialize();
    CodeChange generate(const PlanStep& step);
    bool apply(const CodeChange& change);
};

} // namespace agent
} // namespace rawrxd
