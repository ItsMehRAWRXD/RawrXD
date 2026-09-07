// rawr_session_state.hpp
#pragma once
#include "rawr_safety_policy.hpp"
#include <string>
#include <vector>

namespace rawr {

struct ChatTurn {
    std::string role; // user|assistant|system|tool
    std::string content;
};

struct SessionState {
    std::string id;
    std::string modelAlias;
    std::string modelPath;
    std::string workspace;
    AutonomyLevel autonomy = AutonomyLevel::Off;
    std::vector<ChatTurn> history;
    std::string lastPlan;
    std::string lastDiff;
    std::string lastPatchId;
    bool paused = false;
    bool alive = true;
};

} // namespace rawr
