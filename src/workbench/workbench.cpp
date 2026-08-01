#include "workbench.hpp"
#include <iostream>
#include <fstream>
#include <sstream>

namespace rawrxd {
namespace workbench {

EditorBridge::EditorBridge() = default;
EditorBridge::~EditorBridge() = default;

bool EditorBridge::openFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) return false;
    std::stringstream buf;
    buf << file.rdbuf();
    content_ = buf.str();
    current_file_ = path;
    return true;
}

bool EditorBridge::saveFile(const std::string& path) {
    std::ofstream file(path);
    if (!file) return false;
    file << content_;
    return true;
}

EditorContext EditorBridge::getContext() const {
    EditorContext ctx;
    ctx.file_path = current_file_;
    ctx.content = content_;
    return ctx;
}

bool EditorBridge::applySuggestion(const AISuggestion& suggestion) {
    // In a full implementation, this would modify the editor buffer
    std::cout << "[EditorBridge] Applied suggestion: " << suggestion.type << std::endl;
    return true;
}

bool EditorBridge::applyDiff(const DiffEntry& diff) {
    std::ofstream file(diff.file);
    if (!file) return false;
    file << diff.after;
    std::cout << "[EditorBridge] Applied diff to: " << diff.file << std::endl;
    return true;
}

AIPanel::AIPanel() = default;
AIPanel::~AIPanel() = default;

void AIPanel::showMessage(const std::string& role, const std::string& content) {
    std::cout << "[" << role << "] " << content << std::endl;
}

void AIPanel::showProgress(const std::string& status, double progress) {
    std::cout << "[Progress] " << status << " (" << (int)(progress * 100) << "%)" << std::endl;
}

void AIPanel::showSuggestions(const std::vector<AISuggestion>& suggestions) {
    for (const auto& s : suggestions) {
        std::cout << "[Suggestion] " << s.type << ": " << s.text.substr(0, 80) << "..." << std::endl;
    }
}

void AIPanel::clear() {}

DiffView::DiffView() = default;
DiffView::~DiffView() = default;

void DiffView::showDiff(const DiffEntry& diff) {
    std::cout << "=== Diff: " << diff.file << " ===" << std::endl;
    std::cout << diff.patch << std::endl;
}

bool DiffView::acceptDiff() { return true; }
bool DiffView::rejectDiff() { return false; }

TerminalPanel::TerminalPanel() = default;
TerminalPanel::~TerminalPanel() = default;

bool TerminalPanel::executeCommand(const std::string& command) {
    return system(command.c_str()) == 0;
}

std::string TerminalPanel::getOutput() const { return ""; }
void TerminalPanel::clear() {}

BuildView::BuildView() = default;
BuildView::~BuildView() = default;

void BuildView::showBuildOutput(const std::string& output) {
    std::cout << "[Build] " << output << std::endl;
}

void BuildView::showTestResults(const std::string& results) {
    std::cout << "[Tests] " << results << std::endl;
}

void BuildView::showErrors(const std::vector<std::string>& errors) {
    for (const auto& e : errors) {
        std::cerr << "[Error] " << e << std::endl;
    }
}

void BuildView::clear() {}

} // namespace workbench
} // namespace rawrxd
