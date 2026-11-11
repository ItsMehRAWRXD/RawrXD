// ai_ui_integration.cpp - UI Integration Layer for AI Features
#include "ai_ui_integration.h"
#include "ai_inline_editor.h"
#include "ai_smart_completion.h"
#include "ai_debugger.h"
#include "ai_code_review.h"
#include <windows.h>
#include <commctrl.h>

namespace RawrXD {
namespace AI {

// Keybinding handler
LRESULT CALLBACK AIKeyProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* pKbd = (KBDLLHOOKSTRUCT*)lParam;
        
        // Cmd+K for inline editor (Ctrl+K on Windows)
        if (pKbd->vkCode == 'K' && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
            if (wParam == WM_KEYDOWN) {
                AIUIManager::GetInstance().ShowInlineEditor();
                return 1; // Block default handling
            }
        }
        
        // Tab for accepting completion
        if (pKbd->vkCode == VK_TAB) {
            if (wParam == WM_KEYDOWN) {
                if (AIUIManager::GetInstance().HasActiveCompletion()) {
                    AIUIManager::GetInstance().AcceptCompletion();
                    return 1;
                }
            }
        }
        
        // Escape to dismiss
        if (pKbd->vkCode == VK_ESCAPE) {
            if (wParam == WM_KEYDOWN) {
                AIUIManager::GetInstance().DismissAll();
            }
        }
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

// AIUIManager Implementation
class AIUIManager::Impl {
public:
    HWND m_hwndMain = nullptr;
    HWND m_hwndInlineEditor = nullptr;
    HWND m_hwndCompletionPopup = nullptr;
    HWND m_hwndDebuggerPanel = nullptr;
    HWND m_hwndReviewPanel = nullptr;
    
    HHOOK m_hKeyboardHook = nullptr;
    
    std::string m_currentFile;
    int m_currentLine = 0;
    int m_currentColumn = 0;
    std::string m_selectedText;
    
    bool m_hasActiveCompletion = false;
    std::string m_pendingCompletion;
    
    // Ghost text overlay
    std::string m_ghostText;
    bool m_showGhostText = false;
    
    void Initialize(HWND hwndMain) {
        m_hwndMain = hwndMain;
        
        // Install keyboard hook
        m_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, AIKeyProc, 
                                            GetModuleHandle(nullptr), 0);
        
        // Create child windows
        CreateInlineEditorWindow();
        CreateCompletionWindow();
        CreateDebuggerPanel();
        CreateReviewPanel();
    }
    
    void Shutdown() {
        if (m_hKeyboardHook) {
            UnhookWindowsHookEx(m_hKeyboardHook);
            m_hKeyboardHook = nullptr;
        }
        
        DestroyWindow(m_hwndInlineEditor);
        DestroyWindow(m_hwndCompletionPopup);
        DestroyWindow(m_hwndDebuggerPanel);
        DestroyWindow(m_hwndReviewPanel);
    }
    
    void CreateInlineEditorWindow() {
        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = InlineEditorWndProc;
        wc.hInstance = GetModuleHandle(nullptr);
        wc.lpszClassName = "RawrXDInlineEditor";
        RegisterClassExA(&wc);
        
        m_hwndInlineEditor = CreateWindowExA(
            WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            "RawrXDInlineEditor",
            "AI Inline Editor",
            WS_POPUP | WS_BORDER,
            0, 0, 600, 200,
            m_hwndMain, nullptr, GetModuleHandle(nullptr), nullptr
        );
    }
    
    void CreateCompletionWindow() {
        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = CompletionWndProc;
        wc.hInstance = GetModuleHandle(nullptr);
        wc.lpszClassName = "RawrXDCompletion";
        RegisterClassExA(&wc);
        
        m_hwndCompletionPopup = CreateWindowExA(
            WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            "RawrXDCompletion",
            "AI Completion",
            WS_POPUP | WS_BORDER,
            0, 0, 400, 150,
            m_hwndMain, nullptr, GetModuleHandle(nullptr), nullptr
        );
    }
    
    void CreateDebuggerPanel() {
        // Create as child of main window or dockable panel
        m_hwndDebuggerPanel = CreateWindowExA(
            WS_EX_CLIENTEDGE,
            "EDIT",
            "AI Debugger",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 0, 400, 300,
            m_hwndMain, (HMENU)IDC_AI_DEBUGGER_PANEL,
            GetModuleHandle(nullptr), nullptr
        );
    }
    
    void CreateReviewPanel() {
        m_hwndReviewPanel = CreateWindowExA(
            WS_EX_CLIENTEDGE,
            "SysListView32",
            "AI Code Review",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
            0, 0, 400, 300,
            m_hwndMain, (HMENU)IDC_AI_REVIEW_PANEL,
            GetModuleHandle(nullptr), nullptr
        );
        
        // Add columns
        LVCOLUMNA lvc = {};
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;
        
        lvc.pszText = (LPSTR)"Line";
        lvc.cx = 50;
        ListView_InsertColumn(m_hwndReviewPanel, 0, &lvc);
        
        lvc.pszText = (LPSTR)"Severity";
        lvc.cx = 80;
        ListView_InsertColumn(m_hwndReviewPanel, 1, &lvc);
        
        lvc.pszText = (LPSTR)"Category";
        lvc.cx = 100;
        ListView_InsertColumn(m_hwndReviewPanel, 2, &lvc);
        
        lvc.pszText = (LPSTR)"Message";
        lvc.cx = 300;
        ListView_InsertColumn(m_hwndReviewPanel, 3, &lvc);
    }
    
    void ShowInlineEditor() {
        // Get cursor position
        POINT pt;
        GetCaretPos(&pt);
        ClientToScreen(m_hwndMain, &pt);
        
        SetWindowPos(m_hwndInlineEditor, HWND_TOPMOST,
                     pt.x, pt.y + 20, 600, 200, SWP_SHOWWINDOW);
        
        // Set focus to input field
        SetFocus(m_hwndInlineEditor);
    }
    
    void ShowCompletion(const std::string& text) {
        m_pendingCompletion = text;
        m_hasActiveCompletion = true;
        
        // Show ghost text
        m_ghostText = text;
        m_showGhostText = true;
        
        // Position completion popup
        POINT pt;
        GetCaretPos(&pt);
        ClientToScreen(m_hwndMain, &pt);
        
        SetWindowPos(m_hwndCompletionPopup, HWND_TOPMOST,
                     pt.x, pt.y + 20, 400, 150, SWP_SHOWWINDOW);
        
        InvalidateRect(m_hwndMain, nullptr, FALSE);
    }
    
    void AcceptCompletion() {
        if (m_hasActiveCompletion) {
            // Insert completion text at cursor
            SendMessage(m_hwndMain, WM_AI_INSERT_TEXT, 
                       (WPARAM)m_pendingCompletion.c_str(), 0);
            
            m_hasActiveCompletion = false;
            m_pendingCompletion.clear();
            m_ghostText.clear();
            m_showGhostText = false;
            
            ShowWindow(m_hwndCompletionPopup, SW_HIDE);
            InvalidateRect(m_hwndMain, nullptr, FALSE);
        }
    }
    
    void DismissAll() {
        m_hasActiveCompletion = false;
        m_pendingCompletion.clear();
        m_ghostText.clear();
        m_showGhostText = false;
        
        ShowWindow(m_hwndInlineEditor, SW_HIDE);
        ShowWindow(m_hwndCompletionPopup, SW_HIDE);
    }
    
    void UpdateDebuggerPanel(const std::string& text) {
        SetWindowTextA(m_hwndDebuggerPanel, text.c_str());
    }
    
    void UpdateReviewPanel(const std::vector<ReviewComment>& comments) {
        ListView_DeleteAllItems(m_hwndReviewPanel);
        
        for (size_t i = 0; i < comments.size(); ++i) {
            const auto& comment = comments[i];
            
            LVITEMA lvi = {};
            lvi.mask = LVIF_TEXT;
            lvi.iItem = (int)i;
            
            // Line number
            std::string lineStr = std::to_string(comment.line);
            lvi.pszText = (LPSTR)lineStr.c_str();
            ListView_InsertItem(m_hwndReviewPanel, &lvi);
            
            // Severity
            const char* severityStr = "Info";
            switch (comment.severity) {
                case ReviewSeverity::Warning: severityStr = "Warning"; break;
                case ReviewSeverity::Error: severityStr = "Error"; break;
                case ReviewSeverity::Critical: severityStr = "Critical"; break;
                default: break;
            }
            ListView_SetItemText(m_hwndReviewPanel, i, 1, (LPSTR)severityStr);
            
            // Category
            const char* categoryStr = "Other";
            switch (comment.category) {
                case ReviewCategory::Security: categoryStr = "Security"; break;
                case ReviewCategory::Performance: categoryStr = "Performance"; break;
                case ReviewCategory::Maintainability: categoryStr = "Maintainability"; break;
                case ReviewCategory::Style: categoryStr = "Style"; break;
                default: break;
            }
            ListView_SetItemText(m_hwndReviewPanel, i, 2, (LPSTR)categoryStr);
            
            // Message
            ListView_SetItemText(m_hwndReviewPanel, i, 3, (LPSTR)comment.message.c_str());
        }
    }
    
    void SetCurrentContext(const std::string& file, int line, int col) {
        m_currentFile = file;
        m_currentLine = line;
        m_currentColumn = col;
    }
    
    void SetSelectedText(const std::string& text) {
        m_selectedText = text;
    }
};

// Window procedures
LRESULT CALLBACK InlineEditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hwndEdit;
    static HWND hwndBtnAccept;
    static HWND hwndBtnReject;
    
    switch (msg) {
        case WM_CREATE: {
            // Create input edit
            hwndEdit = CreateWindowExA(
                WS_EX_CLIENTEDGE,
                "EDIT",
                "",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
                5, 5, 580, 140,
                hwnd, (HMENU)IDC_AI_INLINE_INPUT,
                GetModuleHandle(nullptr), nullptr
            );
            
            // Create buttons
            hwndBtnAccept = CreateWindowA(
                "BUTTON",
                "Accept (Ctrl+Enter)",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                5, 155, 120, 25,
                hwnd, (HMENU)IDC_AI_INLINE_ACCEPT,
                GetModuleHandle(nullptr), nullptr
            );
            
            hwndBtnReject = CreateWindowA(
                "BUTTON",
                "Reject (Esc)",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                135, 155, 100, 25,
                hwnd, (HMENU)IDC_AI_INLINE_REJECT,
                GetModuleHandle(nullptr), nullptr
            );
            
            return 0;
        }
        
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_AI_INLINE_ACCEPT:
                    AIUIManager::GetInstance().AcceptInlineEdit();
                    return 0;
                    
                case IDC_AI_INLINE_REJECT:
                    AIUIManager::GetInstance().RejectInlineEdit();
                    return 0;
            }
            break;
            
        case WM_SIZE: {
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            
            SetWindowPos(hwndEdit, nullptr, 5, 5, width - 10, height - 45, SWP_NOZORDER);
            SetWindowPos(hwndBtnAccept, nullptr, 5, height - 35, 120, 25, SWP_NOZORDER);
            SetWindowPos(hwndBtnReject, nullptr, 135, height - 35, 100, 25, SWP_NOZORDER);
            return 0;
        }
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK CompletionWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Draw completion text
            RECT rc;
            GetClientRect(hwnd, &rc);
            
            SetBkColor(hdc, RGB(45, 45, 45));
            SetTextColor(hdc, RGB(200, 200, 200));
            
            std::string text = "AI Suggestion:\n";
            text += AIUIManager::GetInstance().GetGhostText();
            
            DrawTextA(hdc, text.c_str(), -1, &rc, DT_LEFT | DT_WORDBREAK);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// AIUIManager public interface
AIUIManager::AIUIManager() : m_impl(std::make_unique<Impl>()) {}
AIUIManager::~AIUIManager() = default;

AIUIManager& AIUIManager::GetInstance() {
    static AIUIManager instance;
    return instance;
}

void AIUIManager::Initialize(HWND hwndMain) {
    m_impl->Initialize(hwndMain);
}

void AIUIManager::Shutdown() {
    m_impl->Shutdown();
}

void AIUIManager::ShowInlineEditor() {
    m_impl->ShowInlineEditor();
}

void AIUIManager::ShowCompletion(const std::string& text) {
    m_impl->ShowCompletion(text);
}

void AIUIManager::AcceptCompletion() {
    m_impl->AcceptCompletion();
}

void AIUIManager::DismissAll() {
    m_impl->DismissAll();
}

bool AIUIManager::HasActiveCompletion() const {
    return m_impl->m_hasActiveCompletion;
}

std::string AIUIManager::GetGhostText() const {
    return m_impl->m_ghostText;
}

void AIUIManager::AcceptInlineEdit() {
    // Get text from inline editor and apply
    char buffer[4096];
    GetWindowTextA(GetDlgItem(m_impl->m_hwndInlineEditor, IDC_AI_INLINE_INPUT), 
                   buffer, sizeof(buffer));
    
    // Apply the edit
    SendMessage(m_impl->m_hwndMain, WM_AI_INSERT_TEXT, (WPARAM)buffer, 0);
    
    ShowWindow(m_impl->m_hwndInlineEditor, SW_HIDE);
}

void AIUIManager::RejectInlineEdit() {
    ShowWindow(m_impl->m_hwndInlineEditor, SW_HIDE);
}

void AIUIManager::UpdateDebuggerPanel(const std::string& text) {
    m_impl->UpdateDebuggerPanel(text);
}

void AIUIManager::UpdateReviewPanel(const std::vector<ReviewComment>& comments) {
    m_impl->UpdateReviewPanel(comments);
}

void AIUIManager::SetCurrentContext(const std::string& file, int line, int col) {
    m_impl->SetCurrentContext(file, line, col);
}

void AIUIManager::SetSelectedText(const std::string& text) {
    m_impl->SetSelectedText(text);
}

// AI Feature Triggers
void AIUIManager::TriggerInlineEdit(const std::string& instruction) {
    auto& editor = GetAIInlineEditor();
    
    InlineEditContext ctx;
    ctx.filePath = m_impl->m_currentFile;
    ctx.selectedCode = m_impl->m_selectedText;
    ctx.userInstruction = instruction;
    ctx.cursorLine = m_impl->m_currentLine;
    ctx.cursorColumn = m_impl->m_currentColumn;
    ctx.language = "cpp";
    
    auto result = editor.generateEdit(ctx);
    
    if (result) {
        ShowCompletion(result->suggestedCode);
    }
}

void AIUIManager::TriggerSmartCompletion() {
    auto& completion = GetSmartCodeCompletion();
    
    CompletionContext ctx;
    ctx.filePath = m_impl->m_currentFile;
    ctx.line = m_impl->m_currentLine;
    ctx.column = m_impl->m_currentColumn;
    
    // Get completions
    auto results = completion.getCompletions(ctx, 3);
    
    if (!results.empty()) {
        ShowCompletion(results[0].text);
    }
}

void AIUIManager::TriggerCodeReview() {
    auto& reviewer = GetAICodeReview();
    
    ReviewRequest req;
    req.filePath = m_impl->m_currentFile;
    req.code = m_impl->m_selectedText;
    req.language = "cpp";
    
    auto comments = reviewer.reviewCode(req);
    UpdateReviewPanel(comments);
}

void AIUIManager::TriggerDebuggerAnalysis() {
    auto& debugger = GetAIDebugger();
    
    DebugSession session;
    session.executablePath = m_impl->m_currentFile;
    session.currentFunction = "current";
    session.currentLine = m_impl->m_currentLine;
    
    auto analysis = debugger.analyzeCrash(session, "User requested analysis");
    
    if (analysis) {
        UpdateDebuggerPanel(analysis->probableCause);
    }
}

// Message handlers for IDE integration
void AIUIManager::OnEditorTextChanged(const std::string& file, 
                                       const std::string& text,
                                       int cursorLine, int cursorCol) {
    SetCurrentContext(file, cursorLine, cursorCol);
    
    // Trigger real-time completion
    auto& completion = GetSmartCodeCompletion();
    
    CompletionContext ctx;
    ctx.filePath = file;
    ctx.line = cursorLine;
    ctx.column = cursorCol;
    
    auto result = completion.getRealtimeCompletion(ctx);
    
    if (result) {
        ShowCompletion(result->text);
    }
}

void AIUIManager::OnEditorSelectionChanged(const std::string& file,
                                              const std::string& selectedText,
                                              int startLine, int startCol,
                                              int endLine, int endCol) {
    SetCurrentContext(file, startLine, startCol);
    SetSelectedText(selectedText);
}

void AIUIManager::OnDebuggerBreakpointHit(const DebugSession& session) {
    auto& debugger = GetAIDebugger();
    
    auto analysis = debugger.analyzeVariables(session);
    
    std::stringstream ss;
    ss << "Breakpoint hit at " << session.currentFunction << ":" << session.currentLine << "\n\n";
    ss << "Variable Analysis:\n";
    
    for (const auto& var : analysis) {
        ss << "  " << var.name << " = " << var.value;
        if (!var.anomaly.empty()) {
            ss << " [ANOMALY: " << var.anomaly << "]";
        }
        ss << "\n";
    }
    
    UpdateDebuggerPanel(ss.str());
}

void AIUIManager::OnFileSaved(const std::string& file, const std::string& content) {
    // Auto-trigger code review on save (if enabled)
    // TriggerCodeReview();
}

} // namespace AI
} // namespace RawrXD
