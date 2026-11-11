// snapshot/SnapshotCLI.cpp
//
// Command-line interface for the snapshot engine.
//
// Provides: create, list, diff, restore, delete, optimize, gc, verify, git-state.

#include "snapshot/SnapshotCLI.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <filesystem>

namespace kartgib {

int SnapshotCLI::Run(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.push_back(argv[i]);
    }
    return Run(args);
}

int SnapshotCLI::Run(const std::vector<std::string>& args) {
    if (args.empty()) {
        PrintUsage();
        return 1;
    }

    std::string cmd = args[0];
    std::vector<std::string> cmdArgs(args.begin() + 1, args.end());

    if (cmd == "create") return CmdCreate(cmdArgs);
    if (cmd == "list") return CmdList(cmdArgs);
    if (cmd == "diff") return CmdDiff(cmdArgs);
    if (cmd == "restore") return CmdRestore(cmdArgs);
    if (cmd == "delete") return CmdDelete(cmdArgs);
    if (cmd == "optimize") return CmdOptimize(cmdArgs);
    if (cmd == "gc") return CmdGC(cmdArgs);
    if (cmd == "verify") return CmdVerify(cmdArgs);
    if (cmd == "git-state") return CmdGitState(cmdArgs);

    std::cerr << "Unknown command: " << cmd << "\n";
    PrintUsage();
    return 1;
}

void SnapshotCLI::PrintUsage() {
    std::cout << "RawrXD Snapshot Engine CLI\n\n";
    std::cout << "Usage: rawr-snapshot <command> [args...]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  create [--name NAME] [--mode MODE] [--agent ID] [--task ID] [--desc DESC]\n";
    std::cout << "  list [--agent ID]\n";
    std::cout << "  diff <snapshot-id>\n";
    std::cout << "  restore <snapshot-id> [--policy POLICY]\n";
    std::cout << "  delete <snapshot-id>\n";
    std::cout << "  optimize --model MODEL --metric METRIC --iterations N [--snapshot-each] [--rollback-on-regression]\n";
    std::cout << "  gc\n";
    std::cout << "  verify <snapshot-id>\n";
    std::cout << "  git-state\n";
    std::cout << "\nModes: lightweight, agent-transaction, performance-experiment\n";
    std::cout << "Policies: abort, force, merge\n";
}

void SnapshotCLI::PrintManifest(const SnapshotManifest& manifest) {
    auto timeToStr = [](std::chrono::system_clock::time_point tp) -> std::string {
        if (tp == std::chrono::system_clock::time_point{}) return "N/A";
        auto time_t = std::chrono::system_clock::to_time_t(tp);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S UTC");
        return oss.str();
    };

    std::cout << "ID: " << manifest.id << "\n";
    std::cout << "Name: " << manifest.name << "\n";
    std::cout << "Mode: " << static_cast<int>(manifest.mode) << "\n";
    std::cout << "Status: " << static_cast<int>(manifest.status) << "\n";
    std::cout << "Created: " << timeToStr(manifest.created_time) << "\n";
    std::cout << "Committed: " << timeToStr(manifest.committed_time) << "\n";
    std::cout << "Git Commit: " << manifest.git_commit << "\n";
    std::cout << "Git Branch: " << manifest.git_branch << "\n";
    std::cout << "Git Dirty: " << (manifest.git_dirty ? "yes" : "no") << "\n";
    std::cout << "Agent: " << manifest.agent_id << "\n";
    std::cout << "Task: " << manifest.task_id << "\n";
    std::cout << "Files: " << manifest.files.size() << "\n";
    std::cout << "Parent: " << manifest.parent_snapshot_id << "\n";
    std::cout << "---" << "\n";
}

int SnapshotCLI::CmdCreate(const std::vector<std::string>& args) {
    std::string name = "snapshot-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    SnapshotMode mode = SnapshotMode::Lightweight;
    std::string agent_id = "cli";
    std::string task_id = "manual";
    std::string description = "";

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--name" && i + 1 < args.size()) name = args[++i];
        else if (args[i] == "--mode" && i + 1 < args.size()) {
            std::string m = args[++i];
            if (m == "lightweight") mode = SnapshotMode::Lightweight;
            else if (m == "agent-transaction") mode = SnapshotMode::AgentTransaction;
            else if (m == "performance-experiment") mode = SnapshotMode::PerformanceExperiment;
        }
        else if (args[i] == "--agent" && i + 1 < args.size()) agent_id = args[++i];
        else if (args[i] == "--task" && i + 1 < args.size()) task_id = args[++i];
        else if (args[i] == "--desc" && i + 1 < args.size()) description = args[++i];
    }

    config_.repository_root = std::filesystem::current_path();
    if (!engine_.Initialize(config_)) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }

    auto manifest = engine_.CreateSnapshot(name, mode, agent_id, task_id, description);
    std::cout << "Created snapshot: " << manifest.id << "\n";
    std::cout << "Name: " << manifest.name << "\n";

    engine_.Shutdown();
    return 0;
}

int SnapshotCLI::CmdList(const std::vector<std::string>& args) {
    std::string agent_id = "";

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--agent" && i + 1 < args.size()) agent_id = args[++i];
    }

    config_.repository_root = std::filesystem::current_path();
    if (!engine_.Initialize(config_)) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }

    auto snapshots = engine_.ListSnapshots(agent_id);
    std::cout << "Found " << snapshots.size() << " snapshot(s)\n\n";

    for (const auto& manifest : snapshots) {
        PrintManifest(manifest);
    }

    engine_.Shutdown();
    return 0;
}

int SnapshotCLI::CmdDiff(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: diff <snapshot-id>\n";
        return 1;
    }

    config_.repository_root = std::filesystem::current_path();
    if (!engine_.Initialize(config_)) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }

    std::string diff = engine_.DiffSnapshot(args[0]);
    if (diff.empty()) {
        std::cerr << "Snapshot not found: " << args[0] << "\n";
        return 1;
    }

    std::cout << diff;
    engine_.Shutdown();
    return 0;
}

int SnapshotCLI::CmdRestore(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: restore <snapshot-id> [--policy POLICY]\n";
        return 1;
    }

    ConflictPolicy policy = ConflictPolicy::Abort;
    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--policy" && i + 1 < args.size()) {
            std::string p = args[++i];
            if (p == "abort") policy = ConflictPolicy::Abort;
            else if (p == "force") policy = ConflictPolicy::Force;
            else if (p == "merge") policy = ConflictPolicy::Merge;
        }
    }

    config_.repository_root = std::filesystem::current_path();
    if (!engine_.Initialize(config_)) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }

    if (engine_.RestoreSnapshot(args[0], policy)) {
        std::cout << "Restored snapshot: " << args[0] << "\n";
    } else {
        std::cerr << "Failed to restore snapshot: " << args[0] << "\n";
        return 1;
    }

    engine_.Shutdown();
    return 0;
}

int SnapshotCLI::CmdDelete(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: delete <snapshot-id>\n";
        return 1;
    }

    config_.repository_root = std::filesystem::current_path();
    if (!engine_.Initialize(config_)) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }

    if (engine_.DeleteSnapshot(args[0])) {
        std::cout << "Deleted snapshot: " << args[0] << "\n";
    } else {
        std::cerr << "Failed to delete snapshot: " << args[0] << "\n";
        return 1;
    }

    engine_.Shutdown();
    return 0;
}

int SnapshotCLI::CmdOptimize(const std::vector<std::string>& args) {
    std::string model, metric;
    int iterations = 100;
    bool snapshotEach = false;
    bool rollbackOnRegression = false;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--model" && i + 1 < args.size()) model = args[++i];
        else if (args[i] == "--metric" && i + 1 < args.size()) metric = args[++i];
        else if (args[i] == "--iterations" && i + 1 < args.size()) iterations = std::stoi(args[++i]);
        else if (args[i] == "--snapshot-each") snapshotEach = true;
        else if (args[i] == "--rollback-on-regression") rollbackOnRegression = true;
    }

    if (model.empty() || metric.empty()) {
        std::cerr << "Usage: optimize --model MODEL --metric METRIC --iterations N [--snapshot-each] [--rollback-on-regression]\n";
        return 1;
    }

    config_.repository_root = std::filesystem::current_path();
    if (!engine_.Initialize(config_)) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }

    std::cout << "Running optimization experiment...\n";
    std::cout << "Model: " << model << "\n";
    std::cout << "Metric: " << metric << "\n";
    std::cout << "Iterations: " << iterations << "\n";
    std::cout << "Snapshot each: " << (snapshotEach ? "yes" : "no") << "\n";
    std::cout << "Rollback on regression: " << (rollbackOnRegression ? "yes" : "no") << "\n";

    // This is a placeholder for the actual optimization loop
    // In practice, this would integrate with the agent system
    std::string buildCmd = "cmake --build build --target KartGib";
    std::string testCmd = "ctest --output-on-failure";
    std::string benchCmd = "KartGib --benchmark --model " + model + " --metric " + metric;

    std::string agent_id = "optimizer";
    std::string task_id = "optimize-" + model;

    for (int i = 0; i < iterations; ++i) {
        std::cout << "\nIteration " << (i + 1) << "/" << iterations << "\n";

        if (snapshotEach) {
            std::string iterName = "optimization-iter-" + std::to_string(i);
            auto manifest = engine_.RunPerformanceExperiment(iterName, agent_id, task_id + "-iter-" + std::to_string(i), buildCmd, testCmd, benchCmd, 0.0);

            if (manifest.status == SnapshotStatus::Committed) {
                std::cout << "  Iteration " << (i + 1) << " PASSED\n";
            } else {
                std::cout << "  Iteration " << (i + 1) << " FAILED";
                if (rollbackOnRegression) {
                    std::cout << " (rolled back)";
                }
                std::cout << "\n";
                if (rollbackOnRegression) break;
            }
        }
    }

    engine_.Shutdown();
    return 0;
}

int SnapshotCLI::CmdGC(const std::vector<std::string>& args) {
    config_.repository_root = std::filesystem::current_path();
    if (!engine_.Initialize(config_)) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }

    uint64_t freed = engine_.storage_.GarbageCollect();
    std::cout << "Garbage collection freed " << freed << " bytes (" << (freed / (1024.0 * 1024.0)) << " MB)\n";

    engine_.Shutdown();
    return 0;
}

int SnapshotCLI::CmdVerify(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: verify <snapshot-id>\n";
        return 1;
    }

    config_.repository_root = std::filesystem::current_path();
    if (!engine_.Initialize(config_)) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }

    if (engine_.VerifyIntegrity(args[0])) {
        std::cout << "Snapshot " << args[0] << " verified OK\n";
    } else {
        std::cerr << "Snapshot " << args[0] << " verification FAILED\n";
        return 1;
    }

    engine_.Shutdown();
    return 0;
}

int SnapshotCLI::CmdGitState(const std::vector<std::string>& args) {
    config_.repository_root = std::filesystem::current_path();
    if (!engine_.Initialize(config_)) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }

    std::cout << engine_.GetGitState() << "\n";
    engine_.Shutdown();
    return 0;
}

} // namespace kartgib