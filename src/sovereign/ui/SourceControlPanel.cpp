// ============================================================================
// SourceControlPanel.cpp - Source Control Panel Implementation
// ============================================================================

#include "SourceControlPanel.hpp"
#include <cstdio>
#include <sstream>
#include <array>
#include <algorithm>
#include <iostream>

namespace Sovereign {

SourceControlPanel::SourceControlPanel() = default;
SourceControlPanel::~SourceControlPanel() { Shutdown(); }

bool SourceControlPanel::Initialize(const std::string& repoPath) {
    repoPath_ = repoPath;
    return true;
}

void SourceControlPanel::Shutdown() {}

std::string SourceControlPanel::ExecGit(const std::vector<std::string>& args) const {
    std::string cmd = "git -C \"" + repoPath_ + "\"";
    for (const auto& a : args) cmd += " " + a;
    cmd += " 2>&1";
    
    std::array<char, 4096> buffer;
    std::string result;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buffer.data(), buffer.size(), pipe)) result += buffer.data();
    _pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) result.pop_back();
    return result;
}

std::vector<SCMChange> SourceControlPanel::GetChanges() {
    std::vector<SCMChange> changes;
    auto lines = ExecGit({"status", "--porcelain"});
    std::stringstream ss(lines);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.size() < 3) continue;
        SCMChange c;
        c.status = line.substr(0, 2);
        c.file = line.substr(3);
        changes.push_back(c);
    }
    stats_.totalChanges = changes.size();
    if (changeCallback_) changeCallback_(changes);
    return changes;
}

std::vector<SCMCommit> SourceControlPanel::GetLog(int count) {
    std::vector<SCMCommit> commits;
    auto lines = ExecGit({"log", "--oneline", "-" + std::to_string(count)});
    std::stringstream ss(lines);
    std::string line;
    while (std::getline(ss, line)) {
        SCMCommit c;
        auto space = line.find(' ');
        if (space != std::string::npos) {
            c.hash = line.substr(0, space);
            c.message = line.substr(space + 1);
        }
        commits.push_back(c);
    }
    return commits;
}

std::vector<SCMBranch> SourceControlPanel::GetBranches() {
    std::vector<SCMBranch> branches;
    auto lines = ExecGit({"branch", "-a"});
    std::stringstream ss(lines);
    std::string line;
    while (std::getline(ss, line)) {
        SCMBranch b;
        b.isCurrent = line[0] == '*';
        b.name = line.substr(2);
        branches.push_back(b);
    }
    stats_.totalBranches = branches.size();
    return branches;
}

bool SourceControlPanel::Stage(const std::string& file) {
    stats_.operations++;
    return ExecGit({"add", file}).empty();
}

bool SourceControlPanel::Commit(const std::string& message) {
    stats_.totalCommits++;
    stats_.operations++;
    return ExecGit({"commit", "-m", "\"" + message + "\""}).empty();
}

std::string SourceControlPanel::GetCurrentBranch() {
    return ExecGit({"rev-parse", "--abbrev-ref", "HEAD"});
}

bool SourceControlPanel::HasUncommittedChanges() {
    return !ExecGit({"status", "--porcelain"}).empty();
}

bool SourceControlPanel::IsRepository() {
    return !ExecGit({"rev-parse", "--git-dir"}).empty();
}

} // namespace Sovereign
