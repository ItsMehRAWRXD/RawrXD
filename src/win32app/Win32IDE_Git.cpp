// Win32IDE_Git.cpp — Version Control (Batch 4 V01)
// Full Git integration: stage, commit, push, pull, branch, stash, cherry-pick
#include "Win32IDE.h"
#include <windows.h>
#include <string>

void Win32IDE::gitStage(const std::string& file) {
    std::string output; const bool ok = executeGitCommand("git add -- \"" + file + "\"", output);
    appendToOutput("[Git] Stage: " + (ok ? output : "command failed\n"), "Git", ok ? OutputSeverity::Info : OutputSeverity::Error);
}

void Win32IDE::gitCommit(const std::string& message) {
    std::string output; const bool ok = executeGitCommand("git commit -m \"" + message + "\"", output);
    appendToOutput("[Git] Commit: " + (ok ? output : "command failed\n"), "Git", ok ? OutputSeverity::Info : OutputSeverity::Error);
}

void Win32IDE::gitPush() {
    std::string output; const bool ok = executeGitCommand("git push", output);
    appendToOutput("[Git] Push: " + (ok ? output : "command failed\n"), "Git", ok ? OutputSeverity::Info : OutputSeverity::Error);
}

void Win32IDE::gitPull() {
    std::string output; const bool ok = executeGitCommand("git pull", output);
    appendToOutput("[Git] Pull: " + (ok ? output : "command failed\n"), "Git", ok ? OutputSeverity::Info : OutputSeverity::Error);
}

void Win32IDE::gitBranch(const std::string& name) {
    std::string output; const bool ok = executeGitCommand("git switch -c \"" + name + "\"", output);
    appendToOutput("[Git] Branch: " + (ok ? output : "command failed\n"), "Git", ok ? OutputSeverity::Info : OutputSeverity::Error);
}

void Win32IDE::gitStash() {
    std::string output; const bool ok = executeGitCommand("git stash", output);
    appendToOutput("[Git] Stash: " + (ok ? output : "command failed\n"), "Git", ok ? OutputSeverity::Info : OutputSeverity::Error);
}

void Win32IDE::gitCherryPick(const std::string& commit) {
    std::string output; const bool ok = executeGitCommand("git cherry-pick \"" + commit + "\"", output);
    appendToOutput("[Git] Cherry-pick: " + (ok ? output : "command failed\n"), "Git", ok ? OutputSeverity::Info : OutputSeverity::Error);
}

void Win32IDE::gitStatus() {
    std::string output; const bool ok = executeGitCommand("git status --short", output);
    appendToOutput("[Git] Status: " + (ok ? output : "command failed\n"), "Git", ok ? OutputSeverity::Info : OutputSeverity::Error);
}
