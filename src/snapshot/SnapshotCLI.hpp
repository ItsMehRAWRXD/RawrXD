// snapshot/SnapshotCLI.hpp
//
// Command-line interface for the snapshot engine.
//
// Provides: create, list, diff, restore, delete, optimize, gc, verify, git-state.
//
// GENERATED SCAFFOLD. The structure is real; the bodies marked
// TODO(impl) are not. See tools/scaffold.py --status.

#pragma once

#include <vector>
#include <string>
#include "snapshot/SnapshotEngine.hpp"
#include "snapshot/SnapshotConfig.hpp"

namespace kartgib {

class SnapshotCLI {
public:
    // Command-line interface for the snapshot engine.
    //
    // Provides: create, list, diff, restore, delete, optimize, gc, verify, git-state.

    int Run(int argc, char** argv);                                    // Run the CLI with argc/argv
    int Run(const std::vector<std::string>& args);                     // Run the CLI with a string vector

private:
    SnapshotEngine engine_;
    SnapshotConfig config_;

    int CmdCreate(const std::vector<std::string>& args);
    int CmdList(const std::vector<std::string>& args);
    int CmdDiff(const std::vector<std::string>& args);
    int CmdRestore(const std::vector<std::string>& args);
    int CmdDelete(const std::vector<std::string>& args);
    int CmdOptimize(const std::vector<std::string>& args);
    int CmdGC(const std::vector<std::string>& args);
    int CmdVerify(const std::vector<std::string>& args);
    int CmdGitState(const std::vector<std::string>& args);
    void PrintUsage();
    void PrintManifest(const SnapshotManifest& manifest);
};

} // namespace kartgib