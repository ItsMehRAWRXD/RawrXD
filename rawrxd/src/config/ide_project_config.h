// ide_project_config.h — RAWRXD_PER_PROJECT_CONFIG_001
//
// src/config/IDEConfig.h was three lines whose entire content was
// `// Stub header`, and IDEConfig.cpp was one line: `#include "IDEConfig.h"`.
// Both were listed in three CMake targets, so the build compiled a 909-byte
// object with no code in it, and CMakeLists.txt:2571 even annotates the entry
// "required by OrchestratorBridge", which it cannot be.
//
// Per-project configuration therefore had no implementation. `.rawrxd/` IS used
// across the product, but only for agent and authority infrastructure --
// leases, index, checkpoints, sessions, memory, state, logs -- never for project
// settings the IDE reads.
//
// This is that authority. One canonical model, layered over the user settings
// that Win32IDE_Settings already owns:
//
//   layer 1  user      %LOCALAPPDATA%\RawrXD\settings.ini        (existing)
//   layer 2  workspace <ws>/.rawrxd/workspace.json                (existing)
//   layer 3  project   <ws>/.rawrxd/project.json                  (this file)
//
// Lookup order is project over workspace over user. Project wins because it is
// the most specific statement of intent. Nothing is merged blindly: a value
// present in the project layer shadows the layer below, and a value absent falls
// through. Unknown keys are counted, not silently accepted, on the same
// fail-closed principle as the settings authority.

#pragma once
#include <string>
#include <vector>
#include <map>
#include <cstddef>

namespace RawrXD {

// Measured outcome of loading the project layer. Same rule as everywhere else in
// this pass: absent, refused and applied must be distinguishable.
struct ProjectConfigDiagnostics {
    bool        loadCalled = false;
    bool        fileExisted = false;
    bool        parsed = false;
    bool        refused = false;
    std::size_t keysProject = 0;
    std::size_t keysWorkspace = 0;
    std::size_t keysUser = 0;
    std::size_t keysUnknown = 0;
    std::size_t keysShadowed = 0;
    std::string projectPath;
    std::string projectName;
    std::string lastError;
};

class IDEProjectConfig {
public:
    // Loads <workspaceRoot>/.rawrxd/project.json.
    ProjectConfigDiagnostics load(const std::string& workspaceRoot);

    // Writes the project layer back out. Atomic.
    bool save(const std::string& workspaceRoot) const;

    // Layered lookup. `user` is the flat map the settings authority owns; it is
    // passed in rather than read here so there is exactly one settings authority.
    std::string resolve(const std::string& key,
                        const std::string& userValue,
                        const std::string& def = std::string()) const;

    bool hasProjectOverride(const std::string& key) const;

    std::size_t size() const { return values_.size(); }
    const std::map<std::string, std::string>& values() const { return values_; }
    const std::string& name() const { return name_; }
    void setValue(const std::string& k, const std::string& v) { values_[k] = v; }
    void clear() { values_.clear(); name_.clear(); }

    // The keys this authority understands. Anything else in a project document is
    // counted as unknown rather than accepted as if it had been honoured.
    static const std::vector<std::string>& knownKeys();

private:
    std::map<std::string, std::string> values_;
    std::string name_;
};

} // namespace RawrXD
