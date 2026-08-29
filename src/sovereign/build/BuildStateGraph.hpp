// BuildStateGraph.hpp
// Coordination Primitive #3: Build State Graph
// No more "is it building?" - explicit state machine with causal edges

#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <optional>
#include <functional>
#include <variant>
#include <memory>

namespace Sovereign {

// Build states - explicit, no ambiguity
enum class BuildState {
    IDLE,               // Nothing happening
    CONFIGURING,        // CMake/configure running
    GENERATING,         // Build files being generated
    COMPILING,          // Actual compilation
    LINKING,            // Linking phase
    PACKAGING,          // Creating installers/packages
    VERIFYING,          // Running tests/validation
    SUCCEEDED,          // Build complete, success
    FAILED,             // Build complete, failure
    CANCELLED,          // User or system cancelled
    RECOVERING          // Attempting auto-recovery
};

// State transition - causal edge in the graph
struct StateTransition {
    BuildState from;
    BuildState to;
    std::string trigger;        // What caused the transition
    std::string actor;          // Who/what triggered it
    std::chrono::time_point<std::chrono::steady_clock> timestamp;
    std::optional<std::string> error_message;
    std::map<std::string, std::string> metadata;
};

// Build artifact node
struct ArtifactNode {
    std::string path;
    std::string hash;           // SHA256
    size_t size_bytes;
    std::chrono::time_point<std::chrono::steady_clock> modified;
    std::vector<std::string> dependencies;  // Other artifacts this depends on
    bool is_output;             // True if this is a build output
    bool is_input;              // True if this is a source/input
};

// Build target node
struct TargetNode {
    std::string name;
    std::string type;           // executable, library, custom
    BuildState state;
    std::vector<std::string> source_files;
    std::vector<std::string> output_files;
    std::vector<std::string> dependencies;  // Other targets
    std::optional<std::string> error_output;
    uint64_t compile_time_ms;
    uint64_t link_time_ms;
};

// Build configuration
struct BuildConfiguration {
    std::string name;           // Debug, Release, RelWithDebInfo
    std::string generator;      // Ninja, MSBuild, Make
    std::string toolchain;    // MSVC, Clang, GCC
    std::map<std::string, std::string> defines;
    std::map<std::string, std::string> options;
};

// Build event types
enum class BuildEventType {
    STATE_CHANGED,
    TARGET_STARTED,
    TARGET_COMPLETED,
    TARGET_FAILED,
    ARTIFACT_CREATED,
    ARTIFACT_MODIFIED,
    ERROR_DETECTED,
    WARNING_EMITTED,
    PROGRESS_UPDATE
};

// Build event
struct BuildEvent {
    BuildEventType type;
    std::chrono::time_point<std::chrono::steady_clock> timestamp;
    std::variant<
        StateTransition,
        TargetNode,
        ArtifactNode,
        std::string  // Generic message
    > data;
};

// The Build State Graph - tracks everything
class BuildStateGraph {
public:
    BuildStateGraph();
    ~BuildStateGraph();

    // State machine operations
    bool TransitionTo(BuildState new_state, const std::string& trigger, const std::string& actor);
    BuildState GetCurrentState() const { return current_state_; }
    bool IsTerminalState() const;
    bool CanTransitionTo(BuildState state) const;
    std::vector<BuildState> GetValidTransitions() const;
    
    // History
    std::vector<StateTransition> GetTransitionHistory(size_t limit = 100) const;
    std::optional<StateTransition> GetLastTransition() const;
    std::optional<StateTransition> FindTransitionTo(BuildState state) const;
    
    // Target management
    void RegisterTarget(const TargetNode& target);
    void UpdateTargetState(const std::string& target_name, BuildState state);
    std::optional<TargetNode> GetTarget(const std::string& name) const;
    std::vector<TargetNode> GetTargetsInState(BuildState state) const;
    std::vector<TargetNode> GetAllTargets() const;
    
    // Artifact tracking
    void RegisterArtifact(const ArtifactNode& artifact);
    void UpdateArtifactHash(const std::string& path, const std::string& hash);
    std::optional<ArtifactNode> GetArtifact(const std::string& path) const;
    std::vector<ArtifactNode> GetStaleArtifacts() const;  // Modified since last build
    std::vector<ArtifactNode> GetOrphanedArtifacts() const;  // No longer referenced
    
    // Dependency graph
    std::vector<std::string> GetDependencies(const std::string& target) const;
    std::vector<std::string> GetDependents(const std::string& target) const;
    std::vector<std::string> GetBuildOrder() const;  // Topologically sorted
    bool HasCircularDependency() const;
    std::vector<std::vector<std::string>> FindCycles() const;
    
    // Configuration
    void SetConfiguration(const BuildConfiguration& config);
    BuildConfiguration GetConfiguration() const { return config_; }
    
    // Event subscription
    using EventCallback = std::function<void(const BuildEvent&)>;
    std::string Subscribe(EventCallback callback);
    void Unsubscribe(const std::string& subscription_id);
    
    // Queries
    struct BuildMetrics {
        uint64_t total_builds;
        uint64_t successful_builds;
        uint64_t failed_builds;
        uint64_t cancelled_builds;
        uint64_t total_compile_time_ms;
        uint64_t total_link_time_ms;
        uint64_t artifacts_produced;
        uint64_t artifacts_from_cache;
        double cache_hit_rate;
    };
    BuildMetrics GetMetrics() const;
    
    // Current build info
    struct CurrentBuild {
        bool is_active;
        BuildState state;
        std::chrono::time_point<std::chrono::steady_clock> started;
        std::chrono::milliseconds elapsed;
        size_t total_targets;
        size_t completed_targets;
        size_t failed_targets;
        double progress_percent;
    };
    CurrentBuild GetCurrentBuild() const;
    
    // Persistence
    bool SaveToFile(const std::string& path) const;
    bool LoadFromFile(const std::string& path);
    
    // Reset
    void Clear();
    void ResetMetrics();

private:
    BuildState current_state_;
    BuildConfiguration config_;
    std::vector<StateTransition> transitions_;
    std::map<std::string, TargetNode> targets_;
    std::map<std::string, ArtifactNode> artifacts_;
    std::map<std::string, std::vector<std::string>> dependency_graph_;
    std::map<std::string, EventCallback> subscribers_;
    BuildMetrics metrics_;
    
    std::chrono::time_point<std::chrono::steady_clock> build_start_time_;
    bool build_active_;
    uint64_t subscription_counter_;
    
    void EmitEvent(const BuildEvent& event);
    bool IsValidTransition(BuildState from, BuildState to) const;
    void UpdateMetrics(const StateTransition& transition);
};

// Global build state graph
BuildStateGraph& GetGlobalBuildStateGraph();

// Helper to convert state to string
const char* BuildStateToString(BuildState state);
BuildState BuildStateFromString(const std::string& str);

} // namespace Sovereign
