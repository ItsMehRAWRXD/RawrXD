// ============================================================================
// ExecutionPolicyStore.hpp — Session > Model > Global > AutoDetect
// One source of truth for IDE + file + CLI + tuner.
// ============================================================================
#pragma once

#include "ExecutionPolicy.hpp"
#include <functional>
#include <mutex>
#include <string>

namespace Deep2 {
namespace Exec {

enum class PolicyLayer : uint8_t {
    AutoDetect = 0,
    Global,
    Model,
    Session
};

struct PolicyCommitResult {
    bool ok = false;
    bool rejected = false;
    uint64_t version = 0;
    std::string detail;
    std::string policySha;
};

class ExecutionPolicyStore {
public:
    static ExecutionPolicyStore& Instance();

    void setPaths(std::string globalYaml, std::string profilesDir);

    // Load Global + optional model profile (by fingerprint). Session cleared.
    bool load(const std::string& modelFingerprint = {});

    // Save Global and/or active model profile.
    bool saveGlobal();
    bool saveModelProfile();

    const ExecutionPolicy& effective() const { return effective_; }
    uint64_t version() const { return effective_.version; }

    // Apply a delta with authority. Fail-closed if Validate fails or locks block.
    PolicyCommitResult apply(const ExecutionPolicy& deltaOverlay,
                             SettingAuthority authority,
                             const std::string& reason);

    // Hot-reload from watched files (call from IDE watchdog).
    PolicyCommitResult reloadFromDisk();

    void setModelFingerprint(const std::string& fp);
    std::string modelFingerprint() const;

    using Listener = std::function<void(const ExecutionPolicy&, const PolicyCommitResult&)>;
    void addListener(Listener fn);

    // Serialize / parse minimal YAML subset used by RawrXD.
    static std::string ToYaml(const ExecutionPolicy& p);
    static bool FromYaml(const std::string& text, ExecutionPolicy& out, std::string& err);

private:
    ExecutionPolicyStore();
    void rebuildEffective();
    bool readFile(const std::string& path, std::string& out) const;
    bool writeFile(const std::string& path, const std::string& data) const;
    std::string profilePath() const;

    mutable std::mutex mu_;
    std::string globalPath_;
    std::string profilesDir_;
    std::string modelFp_;

    ExecutionPolicy autoDetect_;
    ExecutionPolicy global_;
    ExecutionPolicy model_;
    ExecutionPolicy session_;
    ExecutionPolicy effective_;

    bool haveGlobal_ = false;
    bool haveModel_ = false;
    bool haveSession_ = false;

    std::vector<Listener> listeners_;
};

} // namespace Exec
} // namespace Deep2
