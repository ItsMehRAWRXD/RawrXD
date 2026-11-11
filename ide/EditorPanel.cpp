#include "ide/EditorPanel.hpp"
#include "ide/PanelState.hpp"
#include "ide/FileDialog.hpp"
#include "ide/Clipboard.hpp"
#include <imgui.h>
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace IDE {

// TextBuffer implementation
TextBuffer::TextBuffer() 
    : m_modified(false)
    , m_cursorLine(0)
    , m_cursorCol(0)
    , m_hasSelection(false)
    , m_undoIndex(0) {
    m_filePath[0] = '\0';
    m_lines.push_back(""); // Always have at least one line
}

TextBuffer::~TextBuffer() {}

bool TextBuffer::LoadFromFile(const char* path) {
    FILE* file = fopen(path, "r");
    if (!file) return false;
    
    m_lines.clear();
    char line[4096];
    while (fgets(line, sizeof(line), file)) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        m_lines.push_back(line);
    }
    fclose(file);
    
    if (m_lines.empty()) {
        m_lines.push_back("");
    }
    
    strncpy(m_filePath, path, sizeof(m_filePath) - 1);
    m_modified = false;
    m_cursorLine = 0;
    m_cursorCol = 0;
    ClearSelection();
    
    return true;
}

bool TextBuffer::SaveToFile(const char* path) {
    const char* savePath = path ? path : m_filePath;
    if (!savePath || !savePath[0]) return false;
    
    FILE* file = fopen(savePath, "w");
    if (!file) return false;
    
    for (size_t i = 0; i < m_lines.size(); i++) {
        fprintf(file, "%s\n", m_lines[i].c_str());
    }
    fclose(file);
    
    if (!path) {
        m_modified = false;
    }
    return true;
}

void TextBuffer::Clear() {
    m_lines.clear();
    m_lines.push_back("");
    m_modified = false;
    m_cursorLine = 0;
    m_cursorCol = 0;
    ClearSelection();
}

const char* TextBuffer::GetLine(int line) const {
    if (line < 0 || line >= (int)m_lines.size()) return "";
    return m_lines[line].c_str();
}

int TextBuffer::GetLineCount() const {
    return (int)m_lines.size();
}

int TextBuffer::GetLineLength(int line) const {
    if (line < 0 || line >= (int)m_lines.size()) return 0;
    return (int)m_lines[line].length();
}

void TextBuffer::SetCursor(int line, int col) {
    m_cursorLine = std::max(0, std::min(line, (int)m_lines.size() - 1));
    m_cursorCol = std::max(0, std::min(col, GetLineLength(m_cursorLine)));
}

void TextBuffer::GetCursor(int& line, int& col) const {
    line = m_cursorLine;
    col = m_cursorCol;
}

void TextBuffer::SetSelection(int startLine, int startCol, int endLine, int endCol) {
    m_selStartLine = startLine;
    m_selStartCol = startCol;
    m_selEndLine = endLine;
    m_selEndCol = endCol;
    m_hasSelection = true;
}

void TextBuffer::ClearSelection() {
    m_hasSelection = false;
}

bool TextBuffer::HasSelection() const {
    return m_hasSelection;
}

const char* TextBuffer::GetFileName() const {
    const char* lastSlash = strrchr(m_filePath, '\\');
    const char* lastForward = strrchr(m_filePath, '/');
    const char* name = lastSlash > lastForward ? lastSlash + 1 : (lastForward ? lastForward + 1 : m_filePath);
    return name;
}

// EditorPanel static members
static TextBuffer* s_currentBuffer = nullptr;
static bool s_initialized = false;
static bool s_visible = true;
static char s_findBuffer[256] = {};
static bool s_showFind = false;
static bool s_showLineNumbers = true;
static bool s_wordWrap = false;

const char* EditorPanel::Id() { return "EditorPanel"; }
void EditorPanel::Toggle() { PanelState::Toggle(Id()); }
bool EditorPanel::IsVisible() { return PanelState::Visible(Id()); }

void EditorPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_currentBuffer = new TextBuffer();
}

void EditorPanel::Shutdown() {
    if (!s_initialized) return;
    if (s_currentBuffer) {
        delete s_currentBuffer;
        s_currentBuffer = nullptr;
    }
    s_initialized = false;
}

void EditorPanel::OpenFile(const char* path) {
    if (!s_currentBuffer) return;
    
    if (path && path[0]) {
        // Direct path provided (from File Explorer)
        if (s_currentBuffer->IsModified()) {
            // TODO: Prompt to save current file
        }
        if (s_currentBuffer->LoadFromFile(path)) {
            RecentFiles::Add(path);
        }
    } else {
        // Show file dialog
        if (s_currentBuffer->IsModified()) {
            // TODO: Prompt to save current file
        }
        std::string selected = FileDialog::OpenFile("Open Source File", FileDialog::GetDefaultFilters());
        if (!selected.empty()) {
            if (s_currentBuffer->LoadFromFile(selected.c_str())) {
                RecentFiles::Add(selected.c_str());
            }
        }
    }
}

void EditorPanel::SaveCurrentFile() {
    if (!s_currentBuffer) return;
    
    const char* path = s_currentBuffer->GetFilePath();
    if (!path || !path[0]) {
        // No file path - show save dialog
        SaveAsFile();
    } else {
        s_currentBuffer->SaveToFile(nullptr);
    }
}

void EditorPanel::SaveAsFile() {
    if (!s_currentBuffer) return;
    
    std::string selected = FileDialog::SaveFile("Save File As", FileDialog::GetDefaultFilters(), 
                                                  s_currentBuffer->GetFileName());
    if (!selected.empty()) {
        if (s_currentBuffer->SaveToFile(selected.c_str())) {
            RecentFiles::Add(selected.c_str());
        }
    }
}

void EditorPanel::CloseCurrentFile() {
    if (!s_currentBuffer) return;
    s_currentBuffer->Clear();
}

bool EditorPanel::IsFileOpen() {
    return s_currentBuffer && s_currentBuffer->GetFilePath()[0] != '\0';
}

bool EditorPanel::IsModified() {
    return s_currentBuffer && s_currentBuffer->IsModified();
}

const char* EditorPanel::GetCurrentFilePath() {
    return s_currentBuffer ? s_currentBuffer->GetFilePath() : "";
}

void EditorPanel::GoToLine(int line) {
    if (!s_currentBuffer) return;
    s_currentBuffer->SetCursor(line - 1, 0); // 1-based to 0-based
}

void EditorPanel::FindInFile(const char* text) {
    strncpy(s_findBuffer, text, sizeof(s_findBuffer) - 1);
    s_showFind = true;
}

void EditorPanel::Render() {
    if (!PanelState::Visible(Id())) return;
    if (!s_currentBuffer) return;
    
    // Main editor window - takes up center dock space
    ImGuiWindowFlags flags = ImGuiWindowFlags_MenuBar;
    
    ImGui::Begin("Editor", nullptr, flags);
    
    // Menu bar
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("New", "Ctrl+N")) {
                CloseCurrentFile();
            }
            if (ImGui::MenuItem("Open...", "Ctrl+O")) {
                OpenFile(nullptr);
            }
            if (ImGui::MenuItem("Open Recent", nullptr, false, !RecentFiles::GetList().empty())) {
                ImGui::OpenPopup("RecentFilesPopup");
            }
            if (ImGui::MenuItem("Save", "Ctrl+S", false, s_currentBuffer->IsModified() || IsFileOpen())) {
                SaveCurrentFile();
            }
            if (ImGui::MenuItem("Save As...", "Ctrl+Shift+S")) {
                SaveAsFile();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Close", "Ctrl+W")) {
                CloseCurrentFile();
            }
            ImGui::EndMenu();
        }
        
        if (ImGui::BeginMenu("Edit")) {
            if (ImGui::MenuItem("Undo", "Ctrl+Z", false, s_currentBuffer->CanUndo())) {
                s_currentBuffer->Undo();
            }
            if (ImGui::MenuItem("Redo", "Ctrl+Y", false, s_currentBuffer->CanRedo())) {
                s_currentBuffer->Redo();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Cut", "Ctrl+X", false, s_currentBuffer->HasSelection())) {
                CutSelection();
            }
            if (ImGui::MenuItem("Copy", "Ctrl+C", false, s_currentBuffer->HasSelection())) {
                CopySelection();
            }
            if (ImGui::MenuItem("Paste", "Ctrl+V", false, Clipboard::HasText())) {
                PasteFromClipboard();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Find...", "Ctrl+F")) {
                s_showFind = true;
            }
            ImGui::EndMenu();
        }
        
        if (ImGui::BeginMenu("View")) {
            if (ImGui::MenuItem("Line Numbers", nullptr, s_showLineNumbers)) {
                s_showLineNumbers = !s_showLineNumbers;
            }
            if (ImGui::MenuItem("Word Wrap", nullptr, s_wordWrap)) {
                s_wordWrap = !s_wordWrap;
            }
            ImGui::EndMenu();
        }
        
        ImGui::EndMenuBar();
    }
    
    // Find bar
    if (s_showFind) {
        ImGui::InputText("Find", s_findBuffer, sizeof(s_findBuffer));
        ImGui::SameLine();
        if (ImGui::Button("Find Next")) {
            FindNext();
        }
        ImGui::SameLine();
        if (ImGui::Button("Close")) {
            s_showFind = false;
        }
        ImGui::Separator();
    }
    
    // Editor content
    RenderEditorContent();
    
    // Status bar at bottom
    ImGui::Separator();
    RenderStatusBar();
    
    ImGui::End();
}

void EditorPanel::RenderEditorContent() {
    if (!s_currentBuffer) return;
    
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
    
    // Calculate line number width
    int lineCount = s_currentBuffer->GetLineCount();
    int maxDigits = 1;
    int temp = lineCount;
    while (temp >= 10) {
        temp /= 10;
        maxDigits++;
    }
    float lineNumWidth = ImGui::CalcTextSize("0").x * (maxDigits + 2);
    
    // Get available space
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float editorHeight = avail.y - 25; // Reserve space for status bar
    
    // Begin child for scrolling
    ImGui::BeginChild("EditorScroll", ImVec2(0, editorHeight), false, 
                      ImGuiWindowFlags_HorizontalScrollbar);
    
    // Render each line
    for (int i = 0; i < lineCount; i++) {
        // Line number
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "%*d  ", maxDigits, i + 1);
        ImGui::SameLine(0, 0);
        
        // Line content
        const char* lineText = s_currentBuffer->GetLine(i);
        
        // Check if this is the current line
        int cursorLine, cursorCol;
        s_currentBuffer->GetCursor(cursorLine, cursorCol);
        
        if (i == cursorLine) {
            // Highlight current line
            ImVec2 pos = ImGui::GetCursorScreenPos();
            ImVec2 size = ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetTextLineHeight());
            ImGui::GetWindowDrawList()->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), 
                                                      IM_COL32(40, 40, 40, 255));
        }
        
        ImGui::TextUnformatted(lineText);
        
        // Handle click to position cursor
        if (ImGui::IsItemClicked()) {
            ImVec2 clickPos = ImGui::GetMousePos();
            ImVec2 textPos = ImGui::GetItemRectMin();
            float relX = clickPos.x - textPos.x;
            int col = (int)(relX / ImGui::CalcTextSize(" ").x);
            col = std::max(0, std::min(col, s_currentBuffer->GetLineLength(i)));
            s_currentBuffer->SetCursor(i, col);
        }
    }
    
    ImGui::EndChild();
    ImGui::PopStyleVar();
}

void EditorPanel::RenderStatusBar() {
    if (!s_currentBuffer) return;
    
    int cursorLine, cursorCol;
    s_currentBuffer->GetCursor(cursorLine, cursorCol);
    
    ImGui::Text("Ln %d, Col %d  |  %s  |  %s", 
                cursorLine + 1, 
                cursorCol + 1,
                s_currentBuffer->IsModified() ? "Modified" : "Saved",
                s_currentBuffer->GetFileName()[0] ? s_currentBuffer->GetFileName() : "Untitled");
}

void EditorPanel::GoToDefinition() {
    // TODO: Language service integration
}

void EditorPanel::CutSelection() {
    if (!s_currentBuffer || !s_currentBuffer->HasSelection()) return;
    
    std::string selected = s_currentBuffer->GetSelectedText();
    if (!selected.empty()) {
        Clipboard::SetText(selected);
        s_currentBuffer->DeleteSelection();
    }
}

void EditorPanel::CopySelection() {
    if (!s_currentBuffer || !s_currentBuffer->HasSelection()) return;
    
    std::string selected = s_currentBuffer->GetSelectedText();
    if (!selected.empty()) {
        Clipboard::SetText(selected);
    }
}

void EditorPanel::PasteFromClipboard() {
    if (!s_currentBuffer) return;
    
    std::string text = Clipboard::GetText();
    if (!text.empty()) {
        int line, col;
        s_currentBuffer->GetCursor(line, col);
        s_currentBuffer->InsertText(line, col, text.c_str());
    }
}

void EditorPanel::FindNext() {
    if (!s_findBuffer[0] || !s_currentBuffer) return;
    
    int lineCount = s_currentBuffer->GetLineCount();
    int cursorLine, cursorCol;
    s_currentBuffer->GetCursor(cursorLine, cursorCol);
    
    // Simple linear search from cursor
    for (int i = cursorLine; i < lineCount; i++) {
        const char* line = s_currentBuffer->GetLine(i);
        const char* found = strstr(line + (i == cursorLine ? cursorCol : 0), s_findBuffer);
        if (found) {
            int col = (int)(found - line);
            s_currentBuffer->SetCursor(i, col);
            s_currentBuffer->SetSelection(i, col, i, col + (int)strlen(s_findBuffer));
            return;
        }
    }
}

void EditorPanel::FindPrevious() {
    // TODO: Reverse search
}

} // namespace IDE
