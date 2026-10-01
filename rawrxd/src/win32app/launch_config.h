// launch_config.h — RAWRXD_LAUNCH_CONFIGS_001
//
// Launch configurations were the one genuinely ABSENT capability in the Item 7
// audit: a repo-wide search for `launch.json`, `LaunchConfig`, and `launchConfig`
// across src/**.cpp, *.hpp, *.h returned zero matches, and `launch.json` is
// absent from the shipping binary. `IDM_LAUNCH` in Win32IDE_Commands.cpp is a
// command-id range macro, not a launch-configuration system.
//
// This is that system. Shape is deliberately compatible with a .vscode/launch.json
// so an existing workspace file is readable without conversion:
//
//   { "version": "0.2.0", "configurations": [
//       { "name": "debug exe", "type": "cppdbg", "request": "launch",
//         "program": "${workspaceFolder}/build/a.exe",
//         "args": ["--verbose"],
//         "cwd": "${workspaceFolder}",
//         "env": { "MODE": "debug" },
//         "preLaunchTask": "build",
//         "stopAtEntry": true,
//         "console": "integratedTerminal" } ] }
//
// accepted forms for the binary: "program", or "args"[0] when "program" is
// absent, or a bare string entry as a bare program path.
//
// Design notes that matter for correctness:
//   * Variable expansion supports ${workspaceFolder}, ${file}, ${fileDirname},
//     ${fileBasename}, ${fileBasenameNoExtension}, ${cwd}, ${env:NAME} and
//     ${config:NAME}. An unknown variable is REFUSED, not silently expanded to
//     an empty string -- an empty program path is the classic way a launch
//     config "runs" nothing and looks like it worked.
//   * A configuration with no resolvable program is REFUSED at load time and
//     counted, not adopted as a broken entry.

#pragma once
#include <string>
#include <vector>
#include <map>
#include <cstddef>

namespace RawrXD::IDE {

enum class LaunchRequest { Launch, Attach };

struct LaunchConfiguration {
    std::string name;
    std::string type;                 // cppdbg, cppvsdbg, node, python, ...
    LaunchRequest request = LaunchRequest::Launch;
    std::string program;
    std::vector<std::string> args;
    std::string cwd;
    std::map<std::string, std::string> env;
    std::string preLaunchTask;
    std::string console = "integratedTerminal";
    bool        stopAtEntry = false;
    bool        noDebug = false;
};

// Measured outcome. An absent file, a malformed file, and a file whose entries
// were all refused are three different situations and must not report alike.
struct LaunchConfigDiagnostics {
    bool        loadCalled = false;
    bool        fileExisted = false;
    bool        parsed = false;
    bool        refused = false;
    std::size_t entriesSeen = 0;
    std::size_t entriesAdopted = 0;
    std::size_t entriesRefused = 0;
    std::size_t variablesExpanded = 0;
    std::size_t variablesUnresolved = 0;
    std::string version;
    std::string lastError;
};

class LaunchConfigAuthority {
public:
    // Reads a launch.json-shaped document. Returns the measured result; the
    // caller decides whether an empty configuration set is fatal.
    LaunchConfigDiagnostics load(const std::string& path);

    // Writes the current set back out in the same shape. Atomic.
    bool save(const std::string& path) const;

    // Resolves ${...} variables against the supplied context. Returns false and
    // leaves `out` untouched if any variable cannot be resolved, because a
    // partially expanded command line is worse than a refused one.
    static bool expandVariables(const std::string& in,
                                const std::string& workspaceFolder,
                                const std::string& currentFile,
                                const std::map<std::string, std::string>& configValues,
                                std::string& out,
                                std::size_t& expanded,
                                std::size_t& unresolved);

    // Re-expands every loaded configuration. Called once the workspace root and
    // the active file are known, since ${workspaceFolder} and ${file} cannot be
    // known at parse time.
    void resolve(const std::string& workspaceFolder,
                 const std::string& currentFile,
                 const std::map<std::string, std::string>& configValues);

    const std::vector<LaunchConfiguration>& configurations() const { return configs_; }
    bool has(const std::string& name) const;
    const LaunchConfiguration* find(const std::string& name) const;
    std::size_t size() const { return configs_.size(); }

    std::vector<std::string> names() const;

    // Drops every configuration whose program did not resolve, and records why.
    // Applied at the end of resolve() so a broken entry cannot be run.
    std::size_t dropUnresolved(std::string* firstReason = nullptr);

    void clear() { configs_.clear(); }

private:
    std::vector<LaunchConfiguration> configs_;
};

} // namespace RawrXD::IDE
