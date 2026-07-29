// ============================================================================
// editor_agent_integration.hpp — Pure Win32 Native Editor Agent Integration
// ============================================================================
// Ghost text suggestions triggered by TAB key, acceptance via ENTER,
// overlay rendering on editor HWND. No Qt dependencies.
//
// Pattern: C-style extern "C" API + OOP internal
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================
#pragma once

<<<<<<< HEAD
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

// ============================================================================
// Structs
// ============================================================================

struct GhostTextContext {
    wchar_t fileType[64];
    wchar_t currentLine[1024];
    wchar_t previousLines[4096];
    int     cursorColumn;
=======
#include "../agent/ide_agent_bridge.hpp"


#include "RawrXD_EditorWindow.h"
#include <atomic>
#include <thread>

// Forward declaration
namespace RawrXD { class EditorWindow; }

/**
 * @struct GhostTextContext
 * @brief Context for ghost text generation
 */
struct GhostTextContext {
    std::string currentLine;                    ///< Current line being edited
    std::string previousLines;                  ///< Context from previous lines
    int cursorColumn = 0;                   ///< Cursor column in line
    std::string fileType;                       ///< File type (cpp, python, etc)
    int maxSuggestionLength = 200;          ///< Max chars for ghost text
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

struct GhostTextSuggestion {
<<<<<<< HEAD
    wchar_t text[2048];
    wchar_t explanation[512];
    int     confidence;        // 0..100
};

// ============================================================================
// Callback types — agent bridge
// ============================================================================
typedef void (*PFN_AGENT_PLAN_WISH)(const wchar_t* wish, void* userdata);
typedef void (*PFN_AGENT_COMPLETED)(const GhostTextSuggestion* suggestion, int elapsedMs, void* userdata);
=======
    std::string text;                           ///< Suggested code
    std::string explanation;                    ///< Why this suggestion
    int confidence = 100;                   ///< Confidence 0-100
    bool isComplete = false;                ///< Is this a complete statement?
};

/**
 * @class EditorAgentIntegration
 * @brief Integrates agentic features into the code editor
 *
 * Handles:
 * - TAB key event → trigger ghost text
 * - ENTER key event → accept ghost text
 * - Periodic background suggestions
 * - Ghost text rendering overlay
 *
 * @note Works with RawrXD::EditorWindow
 * @note Non-blocking suggestion generation
 *
 * @example
 * @code
 * EditorAgentIntegration agentEditor(m_editorWindow);
 * agentEditor.setAgentBridge(&agentBridge);
 *
 * // TAB and ENTER now trigger agent suggestions
 * @endcode
 */
class EditorAgentIntegration {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

// ============================================================================
// Class: EditorAgentIntegration
// ============================================================================
class EditorAgentIntegration {
public:
<<<<<<< HEAD
    explicit EditorAgentIntegration(HWND editorHwnd);
    ~EditorAgentIntegration();

    // Agent bridge
    void setAgentCallback(PFN_AGENT_PLAN_WISH planFn, PFN_AGENT_COMPLETED completedFn, void* userdata);
=======
    /**
     * @brief Constructor - attach to code editor
     * @param editor Target code editor widget
     */
    explicit EditorAgentIntegration(RawrXD::EditorWindow* editor);

    /**
     * @brief Destructor
     */
    virtual ~EditorAgentIntegration();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    // Configuration
    void setGhostTextEnabled(bool enabled);
<<<<<<< HEAD
    void setFileType(const wchar_t* fileType);
=======

    /**
     * @brief Get whether ghost text is enabled
     * @return true if enabled
     */
    bool isGhostTextEnabled() const { return m_ghostTextEnabled; }

    /**
     * @brief Set file type for context (cpp, python, java, etc)
     * @param fileType Language/file type
     */
    void setFileType(const std::string& fileType);

    /**
     * @brief Enable/disable automatic suggestions (periodic)
     * @param enabled If true, generate suggestions while typing
     */
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    void setAutoSuggestions(bool enabled);

    // Trigger/Accept/Dismiss
    void triggerSuggestion(const GhostTextContext* ctx = nullptr);
    bool acceptSuggestion();
    void dismissSuggestion();
    void clearGhostText();

<<<<<<< HEAD
    // Called by agent when suggestion arrives
    void onSuggestionGenerated(const GhostTextSuggestion* suggestion, int elapsedMs);

    // Paint ghost text on editor DC (call from editor's WM_PAINT after normal paint)
    void paintGhostOverlay(HDC hdc, int editorWidth, int editorHeight);

    // Resize overlay
    void resize(int x, int y, int w, int h);
=======
    /**
     * @brief Set the visual style for ghost text
     * @param font Font to use for ghost text display
     * @param color Color for ghost text
     */
    void setGhostTextStyle(const std::string& font, const uint32_t& color);

    /**
     * @brief Emitted when suggestion generation starts
     */
    void suggestionGenerating();

    /**
     * @brief Emitted when new suggestion is available
     * @param suggestion The generated suggestion
     */
    void suggestionAvailable(const GhostTextSuggestion& suggestion);

    /**
     * @brief Emitted when user accepts suggestion
     * @param text Accepted text
     */
    void suggestionAccepted(const std::string& text);

    /**
     * @brief Emitted when suggestion is dismissed
     */
    void suggestionDismissed();

    /**
     * @brief Emitted if suggestion generation fails
     * @param error Error message
     */
    void suggestionError(const std::string& error);

private:
    /**
     * @brief Handle editor key press events
     * @param event Key event
     */
    void onEditorKeyPressed(void*  event);

    /**
     * @brief Handle agent suggestion completion
     * @param result Agent's suggested action plan
     * @param elapsedMs Time taken
     */
    void onSuggestionGenerated(const void*& result, int elapsedMs);

    /**
     * @brief Periodic timer for automatic suggestions
     */
    void onAutoSuggestionTimer();

    /**
     * @brief Handle text edit completion
     * @param text Completed text
     */
    void onTextCompleted(const std::string& text);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

private:
    // Subclass procedure for editor HWND
    static LRESULT CALLBACK EditorSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                                                UINT_PTR subclassId, DWORD_PTR refData);

    // Internal
    GhostTextContext extractContext() const;
    void generateSuggestion(const GhostTextContext& ctx);

    // Editor handle
    HWND m_editorHwnd = nullptr;

<<<<<<< HEAD
    // Overlay window (transparent child for ghost text rendering)
    HWND m_overlayHwnd = nullptr;
    static LRESULT CALLBACK OverlayWndProc(HWND, UINT, WPARAM, LPARAM);

    // Fonts
    HFONT m_ghostFont = nullptr;
    HFONT m_normalFont = nullptr;
=======
    /**
     * @brief Parse LLM response into suggestion
     * @param response LLM response
     * @return Parsed suggestion
     */
    GhostTextSuggestion parseSuggestion(const void*& response) const;

    /**
     * @brief Render ghost text overlay in editor
     * @param text Ghost text to display
     * @param row Line to display at
     * @param column Column to display at
     */
    void renderGhostText(const std::string& text, int row, int column);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    // State
    bool m_ghostTextEnabled = true;
    bool m_autoSuggestions = false;
    wchar_t m_fileType[64] = {};
    GhostTextSuggestion m_currentSuggestion = {};
    bool m_hasSuggestion = false;
    int  m_ghostRow = -1;
    int  m_ghostCol = -1;

<<<<<<< HEAD
    // Auto-suggestion timer
    UINT_PTR m_autoTimer = 0;

    // Agent callbacks
    PFN_AGENT_PLAN_WISH m_pfnPlanWish = nullptr;
    PFN_AGENT_COMPLETED m_pfnCompleted = nullptr;
    void* m_agentUserdata = nullptr;

    // Metrics
    DWORD m_suggestionsGenerated = 0;
    DWORD m_suggestionsAccepted = 0;
    DWORD m_suggestionsDismissed = 0;

    static bool s_overlayClassRegistered;
};

// ============================================================================
// C API
// ============================================================================
extern "C" {
    EditorAgentIntegration* EditorAgent_Create(HWND editorHwnd);
    void EditorAgent_SetCallback(EditorAgentIntegration* ea, PFN_AGENT_PLAN_WISH planFn,
                                  PFN_AGENT_COMPLETED completedFn, void* userdata);
    void EditorAgent_SetGhostTextEnabled(EditorAgentIntegration* ea, int enabled);
    void EditorAgent_SetFileType(EditorAgentIntegration* ea, const wchar_t* fileType);
    void EditorAgent_SetAutoSuggestions(EditorAgentIntegration* ea, int enabled);
    void EditorAgent_TriggerSuggestion(EditorAgentIntegration* ea);
    int  EditorAgent_AcceptSuggestion(EditorAgentIntegration* ea);
    void EditorAgent_DismissSuggestion(EditorAgentIntegration* ea);
    void EditorAgent_OnSuggestionGenerated(EditorAgentIntegration* ea, const GhostTextSuggestion* s, int ms);
    void EditorAgent_PaintOverlay(EditorAgentIntegration* ea, HDC hdc, int w, int h);
    void EditorAgent_Destroy(EditorAgentIntegration* ea);
}
=======
    /**
     * @brief Get cursor position in editor
     * @return (row, column) pair
     */
    std::pair<int, int> getCursorPosition() const;

    /**
     * @brief Get text under cursor
     * @return Current word/token
     */
    std::string getWordUnderCursor() const;

    /**
     * @brief Qt event filter override
     */
    bool eventFilter(void* obj, QEvent* event) override;

    // ─────────────────────────────────────────────────────────────────────
    // Member Variables
    // ─────────────────────────────────────────────────────────────────────

    QPlainTextEdit* m_editor = nullptr;     ///< Target editor widget
    IDEAgentBridge* m_agentBridge = nullptr; ///< Agent communication

    bool m_ghostTextEnabled = true;         ///< Ghost text feature enabled
    bool m_autoSuggestions = false;         ///< Auto-generate suggestions
    std::string m_fileType = "cpp";             ///< Current file type

    GhostTextSuggestion m_currentSuggestion; ///< Current ghost text
    int m_ghostTextRow = -1;                ///< Where ghost text is displayed
    int m_ghostTextColumn = -1;

    std::string m_ghostTextFont;                  ///< Font for ghost text display
    uint32_t m_ghostTextColor;                ///< Color for ghost text (usually dim)

    void** m_autoSuggestionTimer = nullptr; ///< Timer for periodic suggestions

    // Threading
    std::atomic<bool> m_monitoringThreadActive{false};
    std::atomic<bool> m_contentDirty{false};
    std::thread m_monitorThread;
};

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
