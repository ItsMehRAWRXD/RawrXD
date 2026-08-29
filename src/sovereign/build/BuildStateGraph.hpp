#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace Sovereign {

enum class BuildState {
    IDLE = 0,
    CONFIGURING,
    BUILDING,
    LINKING,
    TESTING,
    SUCCEEDED,
    FAILED,
    CANCELLED
};

struct BuildConfiguration {
    std::string name;
    std::string generator;
    std::string buildType = "Release";
    std::vector<std::string> extraArgs;
};

class BuildStateGraph {
public:
    struct CurrentBuild {
        BuildState state = BuildState::IDLE;
        std::string target;
        BuildConfiguration config;
        std::uint32_t percent = 0;
        std::string lastError;
    };

    static BuildStateGraph& Instance();

    void TransitionTo(BuildState newState);
    bool StartBuild(const std::string& target, const BuildConfiguration& config);
    bool CancelBuild();

    CurrentBuild GetCurrent() const;
    BuildState GetState() const;

private:
    BuildStateGraph() = default;

    mutable std::mutex mutex_;
    CurrentBuild current_;
};

inline BuildStateGraph& GetGlobalBuildStateGraph() {
    return BuildStateGraph::Instance();
}

} // namespace Sovereign
