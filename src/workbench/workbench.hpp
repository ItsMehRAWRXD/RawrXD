#pragma once

#include <string>
#include <functional>
#include <vector>

namespace rawrxd {
namespace workbench {

struct EditorContext {
    std::string file_path;
    std::string content;
    std::string selected_text;
    std::string language;
    uint32_t cursor_line;
    uint32_t cursor_column;
    uint32_t selection_start;
    uint32_t selection_end;
};

struct AISuggestion {
    std::string text;
    std::string type;       // "completion", "explanation", "refactor"
    uint32_t start_line;
    uint32_t start_column;
    uint32_t end_line;
    uint32_t end_column;
    double confidence;
};

struct DiffEntry {
    std::string file;
    std::string before;
    std::string after;
    std::string patch;
};

class EditorBridge {
public:
    EditorBridge();
    ~EditorBridge();

    bool openFile(const std::string& path);
    bool saveFile(const std::string& path);
    EditorContext getContext() const;
    bool applySuggestion(const AISuggestion& suggestion);
    bool applyDiff(const DiffEntry& diff);

private:
    std::string current_file_;
    std::string content_;
};

class AIPanel {
public:
    AIPanel();
    ~AIPanel();

    void showMessage(const std::string& role, const std::string& content);
    void showProgress(const std::string& status, double progress);
    void showSuggestions(const std::vector<AISuggestion>& suggestions);
    void clear();
};

class DiffView {
public:
    DiffView();
    ~DiffView();

    void showDiff(const DiffEntry& diff);
    bool acceptDiff();
    bool rejectDiff();
};

class TerminalPanel {
public:
    TerminalPanel();
    ~TerminalPanel();

    bool executeCommand(const std::string& command);
    std::string getOutput() const;
    void clear();
};

class BuildView {
public:
    BuildView();
    ~BuildView();

    void showBuildOutput(const std::string& output);
    void showTestResults(const std::string& results);
    void showErrors(const std::vector<std::string>& errors);
    void clear();
};

} // namespace workbench
} // namespace rawrxd
