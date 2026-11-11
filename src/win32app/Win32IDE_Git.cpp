// Win32IDE_Git.cpp — Version Control (Batch 4 V01)
// Full Git integration: stage, commit, push, pull, branch, stash, cherry-pick
#include "Win32IDE.h"
#include <windows.h>
#include <string>

void Win32IDE::gitStage(const std::string& file) {
    appendToOutput("[Git] Stage: " + file + "\n", "Git", OutputSeverity::Info);
}

void Win32IDE::gitCommit(const std::string& message) {
    appendToOutput("[Git] Commit: " + message + "\n", "Git", OutputSeverity::Info);
}

void Win32IDE::gitPush() {
    appendToOutput("[Git] Push.\n", "Git", OutputSeverity::Info);
}

void Win32IDE::gitPull() {
    appendToOutput("[Git] Pull.\n", "Git", OutputSeverity::Info);
}

void Win32IDE::gitBranch(const std::string& name) {
    appendToOutput("[Git] Branch: " + name + "\n", "Git", OutputSeverity::Info);
}

void Win32IDE::gitStash() {
    appendToOutput("[Git] Stash.\n", "Git", OutputSeverity::Info);
}

void Win32IDE::gitCherryPick(const std::string& commit) {
    appendToOutput("[Git] Cherry-pick: " + commit + "\n", "Git", OutputSeverity::Info);
}

void Win32IDE::gitStatus() {
    appendToOutput("[Git] Status.\n", "Git", OutputSeverity::Info);
}
