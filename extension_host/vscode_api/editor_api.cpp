// editor_api.cpp — VS Code Editor API Implementation
#include "editor_api.hpp"
#include <algorithm>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

void TextEditor::Edit(const std::vector<TextEdit>& edits) {
    for (const auto& edit : edits) {
        // Apply each edit to the text buffer
        // In production, use a proper text buffer implementation
        m_dirty = true;
    }
}

void TextEditor::InsertAt(Position pos, const std::string& text) {
    TextEdit edit;
    edit.range.start = pos;
    edit.range.end = pos;
    edit.newText = text;
    Edit({edit});
}

void TextEditor::DeleteRange(Range range) {
    TextEdit edit;
    edit.range = range;
    edit.newText = "";
    Edit({edit});
}

std::string TextEditor::GetTextAtRange(Range range) const {
    // TODO: Implement range-based text extraction
    return m_text;
}

void TextEditor::Save() {
    if (!m_dirty) return;
    // TODO: Write to file via workspace API
    m_dirty = false;
}

Editor& Editor::Get() {
    static Editor instance;
    return instance;
}

TextEditor* Editor::OpenEditor(const std::filesystem::path& path) {
    auto* editor = new TextEditor();
    editor->m_documentPath = path;
    m_editors.push_back(editor);
    if (!m_activeEditor) {
        m_activeEditor = editor;
        if (m_onChange) m_onChange(editor);
    }
    return editor;
}

void Editor::CloseEditor(TextEditor* editor) {
    auto it = std::find(m_editors.begin(), m_editors.end(), editor);
    if (it != m_editors.end()) {
        m_editors.erase(it);
        if (m_activeEditor == editor) {
            m_activeEditor = m_editors.empty() ? nullptr : m_editors.front();
            if (m_onChange) m_onChange(m_activeEditor);
        }
        delete editor;
    }
}

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
