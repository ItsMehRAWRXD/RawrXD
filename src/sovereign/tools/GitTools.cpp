// ============================================================================
// GitTools.cpp - Git Integration Tools Implementation
// ============================================================================

#include "GitTools.hpp"
#include <cstdio>
#include <iostream>
#include <sstream>
#include <array>

namespace Sovereign {

GitTools::GitTools(const std::string& repoPath) : repoPath_(repoPath) {}
GitTools::~GitTools() = default;

std::string GitTools::ExecGit(const std::vector<std::string>& args) {
    std::string cmd = "git -C \"" + repoPath_ + "\"";
    for (const auto& arg : args) {
        cmd += " " + arg;
    }
    cmd += " 2>&1";
    
    std::array<char, 4096> buffer;
    std::string result;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "";
    
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    _pclose(pipe);
    
    // Trim trailing newline
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    
    return result;
}

std::vector<std::string> GitTools::ExecGitLines(const std::vector<std::string>& args) {
    std::string output = ExecGit(args);
    std::vector<std::string> lines;
    std::stringstream ss(output);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty()) lines.push_back(line);
    }
    return lines;
}

GitStatus GitTools::GetStatus() {
    GitStatus status;
    status.branch = GetBranch();
    
    auto lines = ExecGitLines({"status", "--porcelain"});
    for (const auto& line : lines) {
        if (line.size() < 3) continue;
        std::string flag = line.substr(0, 2);
        std::string file = line.substr(3);
        
        if (flag == "M " || flag == "A " || flag == "D " || flag == "R ") {
            status.staged.push_back(file);
        } else if (flag == " M" || flag == " D" || flag == "??") {
            status.unstaged.push_back(file);
        }
        if (flag == "??") {
            status.untracked.push_back(file);
        }
        if (flag == "UU" || flag == "AA" || flag == "DD") {
            status.hasConflicts = true;
        }
    }
    
    // Check ahead/behind
    auto branchLines = ExecGitLines({"rev-list", "--left-right", "--count", "HEAD...@{u}"});
    if (!branchLines.empty()) {
        auto counts = branchLines[0];
        auto space = counts.find('\t');
        if (space != std::string::npos) {
            status.ahead = std::stoi(counts.substr(0, space));
            status.behind = std::stoi(counts.substr(space + 1));
        }
    }
    
    return status;
}

std::string GitTools::GetBranch() {
    return ExecGit({"rev-parse", "--abbrev-ref", "HEAD"});
}

std::string GitTools::GetCurrentHash() {
    return ExecGit({"rev-parse", "HEAD"});
}

GitDiff GitTools::GetDiff(const std::string& file) {
    GitDiff diff;
    diff.file = file;
    diff.oldContent = ExecGit({"show", "HEAD:" + file});
    diff.newContent = ExecGit({"show", ":" + file});
    
    auto lines = ExecGitLines({"diff", "--stat", file});
    for (const auto& line : lines) {
        if (line.find("insertion") != std::string::npos) {
            sscanf(line.c_str(), "%*d file changed, %d insertion", &diff.additions);
        }
        if (line.find("deletion") != std::string::npos) {
            sscanf(line.c_str(), "%*d file changed, %*d insertion, %d deletion", &diff.deletions);
        }
    }
    
    return diff;
}

std::vector<GitDiff> GitTools::GetAllDiffs() {
    std::vector<GitDiff> diffs;
    auto files = ExecGitLines({"diff", "--name-only"});
    for (const auto& file : files) {
        diffs.push_back(GetDiff(file));
    }
    return diffs;
}

std::string GitTools::GetUnifiedDiff(const std::string& file) {
    return ExecGit({"diff", file});
}

std::vector<GitCommit> GitTools::GetLog(int count) {
    std::vector<GitCommit> commits;
    auto lines = ExecGitLines({"log", "--oneline", "-" + std::to_string(count)});
    
    for (const auto& line : lines) {
        GitCommit commit;
        auto space = line.find(' ');
        if (space != std::string::npos) {
            commit.hash = line.substr(0, space);
            commit.message = line.substr(space + 1);
        }
        commits.push_back(commit);
    }
    
    return commits;
}

GitCommit GitTools::GetCommit(const std::string& hash) {
    GitCommit commit;
    commit.hash = hash;
    commit.message = ExecGit({"log", "-1", "--format=%s", hash});
    commit.author = ExecGit({"log", "-1", "--format=%an", hash});
    return commit;
}

bool GitTools::Stage(const std::string& file) {
    return ExecGit({"add", file}).empty();
}

bool GitTools::Unstage(const std::string& file) {
    return ExecGit({"reset", "HEAD", file}).empty();
}

bool GitTools::Commit(const std::string& message) {
    return ExecGit({"commit", "-m", "\"" + message + "\""}).empty();
}

bool GitTools::Push(const std::string& remote, const std::string& branch) {
    std::vector<std::string> args = {"push", remote};
    if (!branch.empty()) args.push_back(branch);
    return ExecGit(args).empty();
}

bool GitTools::Checkout(const std::string& branch) {
    return ExecGit({"checkout", branch}).empty();
}

bool GitTools::CreateBranch(const std::string& name) {
    return ExecGit({"checkout", "-b", name}).empty();
}

bool GitTools::HasUncommittedChanges() {
    auto status = ExecGit({"status", "--porcelain"});
    return !status.empty();
}

bool GitTools::IsRepo() {
    auto result = ExecGit({"rev-parse", "--git-dir"});
    return !result.empty();
}

std::string GitTools::GetRootPath() {
    return ExecGit({"rev-parse", "--show-toplevel"});
}

} // namespace Sovereign
