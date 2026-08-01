// editor_api.hpp — VS Code Editor API
#pragma once
#include <string>
#include <vector>
#include <functional>
#include <filesystem>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

struct Position {
    int line = 0;
    int character = 0;
};

struct Range {
    Position start;
    Position end;
};

struct Selection {
    Position anchor;
    Position active;
};

struct TextEdit {
    Range range;
    std::string newText;
};

class TextEditor {
public:
    std::filesystem::path GetDocumentPath() const { return m_documentPath; }
    std::string GetText() const { return m_text; }
    void SetText(const std::string& text) { m_text = text; m_dirty = true; }

    Position GetCursorPosition() const { return m_cursor; }
    void SetCursorPosition(Position pos) { m_cursor = pos; }

    Selection GetSelection() const { return m_selection; }
    void SetSelection(Selection sel) { m_selection = sel; }

    void Edit(const std::vector<TextEdit>& edits);
    void InsertAt(Position pos, const std::string& text);
    void DeleteRange(Range range);
    std::string GetTextAtRange(Range range) const;

    bool IsDirty() const { return m_dirty; }
    void Save();

private:
    std::filesystem::path m_documentPath;
    std::string m_text;
    Position m_cursor;
    Selection m_selection;
    bool m_dirty = false;
};

class Editor {
public:
    static Editor& Get();

    TextEditor* GetActiveEditor() const { return m_activeEditor; }
    void SetActiveEditor(TextEditor* editor) { m_activeEditor = editor; }

    std::vector<TextEditor*> GetVisibleEditors() const { return m_editors; }
    TextEditor* OpenEditor(const std::filesystem::path& path);
    void CloseEditor(TextEditor* editor);

    // Events
    using EditorChangeCallback = std::function<void(TextEditor* editor)>;
    void OnDidChangeActiveEditor(EditorChangeCallback callback) { m_onChange = callback; }

private:
    Editor() = default;
    TextEditor* m_activeEditor = nullptr;
    std::vector<TextEditor*> m_editors;
    EditorChangeCallback m_onChange;
};

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
