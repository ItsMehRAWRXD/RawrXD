// ============================================================================
// Win32IDE_SettingsGUI.cpp — Tier 1 Cosmetic #5: Visual Settings Editor
// ============================================================================
// Replaces the read-only settings dialog with a proper VS Code-style Settings UI:
//   - Left-side category tree (General, Editor, AI/Model, Theme, Server)
//   - Right-side property panel with checkboxes, spinners, dropdowns
//   - Real-time search/filter bar at top
//   - Apply + Save + Reset buttons
//
// Pattern:  Win32 Tab Control + property grid, no exceptions
// Threading: UI thread only (DialogBoxParam)
// ============================================================================

#include "Win32IDE.h"
#include "../deep2/execution_policy/IdePolicySet.hpp"
#include "../deep2/execution_policy/ResourceMap.hpp"
#include "../deep2/execution_policy/TunerSuggest.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>


// Settings GUI control IDs
#define IDC_SETTINGS_SEARCH 9900
#define IDC_SETTINGS_TREE 9901
#define IDC_SETTINGS_PANEL 9902
#define IDC_SETTINGS_TABS 9903
#define IDC_SETTINGS_APPLY 9904
#define IDC_SETTINGS_RESET 9905
#define IDC_SETTINGS_CLOSE 9906
#define IDC_SETTINGS_PROP_BASE 9950  // base for dynamic property controls

// Settings GUI colors
static const COLORREF SGUI_BG = RGB(30, 30, 30);
static const COLORREF SGUI_PANEL_BG = RGB(37, 37, 38);
static const COLORREF SGUI_TEXT = RGB(204, 204, 204);
static const COLORREF SGUI_HEADER = RGB(0, 122, 204);
static const COLORREF SGUI_INPUT_BG = RGB(60, 60, 60);
static const COLORREF SGUI_INPUT_TEXT = RGB(220, 220, 220);

// ============================================================================
// BUILD SETTINGS SCHEMA — Define all configurable settings by category
// ============================================================================

void Win32IDE::buildSettingsSchema()
{
    m_settingsSchema.clear();

    // General
    {
        SettingsCategory cat;
        cat.name = "General";
        cat.keys = {"autoSave", "autoSaveInterval", "lineNumbers",     "wordWrap",
                    "fontSize", "fontName",         "workingDirectory"};
        m_settingsSchema.push_back(cat);
    }

    // Editor
    {
        SettingsCategory cat;
        cat.name = "Editor";
        cat.keys = {"tabSize", "useSpaces",    "encoding",       "eolStyle",   "syntaxColoring",
                    "minimap", "smoothScroll", "caretAnimation", "breadcrumbs"};
        m_settingsSchema.push_back(cat);
    }

    // AI / Model
    {
        SettingsCategory cat;
        cat.name = "AI / Model";
        cat.keys = {"aiTemperature",
                    "aiTopP",
                    "aiTopK",
                    "aiMaxTokens",
                    "aiContextWindow",
                    "aiModelPath",
                    "aiOllamaUrl",
                    "ghostText",
                    "failureDetector",
                    "failureMaxRetries",
                    "amdUnifiedMemory",
                    "modelPrefetchEnabled",
                    "modelWorkingSetLockEnabled",
                    "silencePrivilegeWarnings"};
        m_settingsSchema.push_back(cat);
    }

    // Model Execution — same store as config/rawrxd.settings.yaml
    {
        SettingsCategory cat;
        cat.name = "Model Execution";
        cat.keys = {"exec.mode",
                    "exec.vramGb",
                    "exec.ramGb",
                    "exec.objective",
                    "exec.streaming",
                    "exec.chunkMb",
                    "exec.prefetch",
                    "exec.buffers",
                    "exec.layersGpu0",
                    "exec.layersGpu1",
                    "exec.layersStream",
                    "exec.attention",
                    "exec.ffn",
                    "exec.lmHead",
                    "exec.kv",
                    "exec.kvGpuGb",
                    "exec.kvQuant",
                    "exec.workAvoid",
                    "exec.reuse",
                    "exec.autoTune",
                    "exec.respectOverrides",
                    "exec.hotpatch",
                    "exec.persist",
                    "exec.policySha"};
        m_settingsSchema.push_back(cat);
    }

    // Theme
    {
        SettingsCategory cat;
        cat.name = "Theme";
        cat.keys = {"themeId", "windowAlpha", "fileIconTheme"};
        m_settingsSchema.push_back(cat);
    }

    // Server
    {
        SettingsCategory cat;
        cat.name = "Server";
        cat.keys = {"localServer", "localServerPort"};
        m_settingsSchema.push_back(cat);
    }

    // Auto-Update
    {
        SettingsCategory cat;
        cat.name = "Update";
        cat.keys = {"autoUpdateCheck", "updateChannel", "showWelcomeOnStartup"};
        m_settingsSchema.push_back(cat);
    }
}

// ============================================================================
// Settings value helpers — get/set string representation of a setting
// ============================================================================

static std::string getSettingType(const std::string& key)
{
    if (key.size() >= 5 && key.compare(0, 5, "exec.") == 0) {
        if (key == "exec.streaming" || key == "exec.workAvoid" ||
            key == "exec.autoTune" || key == "exec.respectOverrides" ||
            key == "exec.persist" || key == "exec.hotpatch")
            return "bool";
        if (key == "exec.chunkMb" || key == "exec.prefetch" ||
            key == "exec.buffers")
            return "int";
        if (key == "exec.vramGb" || key == "exec.ramGb" || key == "exec.kvGpuGb")
            return "float";
        return "string";
    }
    if (key == "autoSave" || key == "lineNumbers" || key == "wordWrap" || key == "useSpaces" ||
        key == "syntaxColoring" || key == "minimap" || key == "smoothScroll" || key == "caretAnimation" ||
        key == "breadcrumbs" || key == "ghostText" || key == "failureDetector" || key == "amdUnifiedMemory" ||
        key == "localServer" || key == "modelPrefetchEnabled" || key == "modelWorkingSetLockEnabled" ||
        key == "silencePrivilegeWarnings" || key == "autoUpdateCheck" || key == "showWelcomeOnStartup")
    {
        return "bool";
    }
    if (key == "fontSize" || key == "tabSize" || key == "autoSaveInterval" || key == "aiTopK" || key == "aiMaxTokens" ||
        key == "aiContextWindow" || key == "failureMaxRetries" || key == "localServerPort" || key == "windowAlpha" ||
        key == "themeId" || key == "uiScalePercent")
    {
        return "int";
    }
    if (key == "aiTemperature" || key == "aiTopP")
    {
        return "float";
    }
    return "string";
}

static std::string getSettingLabel(const std::string& key)
{
    static const std::map<std::string, std::string> labels = {
        {"autoSave", "Auto Save"},
        {"autoSaveInterval", "Auto Save Interval (seconds)"},
        {"lineNumbers", "Show Line Numbers"},
        {"wordWrap", "Word Wrap"},
        {"fontSize", "Font Size"},
        {"fontName", "Font Family"},
        {"workingDirectory", "Working Directory"},
        {"tabSize", "Tab Size"},
        {"useSpaces", "Insert Spaces"},
        {"encoding", "File Encoding"},
        {"eolStyle", "End of Line"},
        {"syntaxColoring", "Syntax Highlighting"},
        {"minimap", "Minimap"},
        {"smoothScroll", "Smooth Scrolling"},
        {"caretAnimation", "Cursor Blinking"},
        {"breadcrumbs", "Breadcrumbs"},
        {"aiTemperature", "Temperature"},
        {"aiTopP", "Top-P"},
        {"aiTopK", "Top-K"},
        {"aiMaxTokens", "Max Tokens"},
        {"aiContextWindow", "Context Window Size"},
        {"aiModelPath", "Model Path"},
        {"aiOllamaUrl", "Ollama Server URL"},
        {"ghostText", "Ghost Text (Inline Suggestions)"},
        {"failureDetector", "Failure Detector"},
        {"failureMaxRetries", "Max Retries"},
        {"amdUnifiedMemory", "AMD Unified Memory (SAM)"},
        {"modelPrefetchEnabled", "High-Performance Streaming: Prefetch"},
        {"modelWorkingSetLockEnabled", "High-Performance Streaming: Working Set Lock (best-effort)"},
        {"silencePrivilegeWarnings", "Silence Privilege Warnings (1314)"},
        {"exec.mode", "Execution Mode (auto|guided|expert)"},
        {"exec.vramGb", "VRAM Hard Cap (GB)"},
        {"exec.ramGb", "RAM Cap (GB)"},
        {"exec.objective", "Scheduler Objective"},
        {"exec.streaming", "Streaming Enabled"},
        {"exec.chunkMb", "Stream Chunk (MB)"},
        {"exec.prefetch", "Prefetch Depth"},
        {"exec.buffers", "Stream Buffers"},
        {"exec.layersGpu0", "GPU0 Layers (e.g. 0-11)"},
        {"exec.layersGpu1", "GPU1 Layers (e.g. 12-19)"},
        {"exec.layersStream", "Streamed Layers (e.g. 20-*)"},
        {"exec.attention", "Attention Placement"},
        {"exec.ffn", "FFN Placement"},
        {"exec.lmHead", "LM Head Placement"},
        {"exec.kv", "KV Placement"},
        {"exec.kvGpuGb", "KV GPU Budget (GB)"},
        {"exec.kvQuant", "KV Quantization"},
        {"exec.workAvoid", "Work Avoidance"},
        {"exec.reuse", "Reuse Policy (off|exact|certified)"},
        {"exec.autoTune", "Auto-Tune Inside Caps"},
        {"exec.respectOverrides", "Auto Respects Locked Overrides"},
        {"exec.hotpatch", "Adaptive Hotpatch"},
        {"exec.persist", "Persist Runtime Changes"},
        {"exec.policySha", "Policy SHA (read-only)"},
        {"themeId", "Color Theme"},
        {"windowAlpha", "Window Transparency (0-255)"},
        {"fileIconTheme", "File Icon Theme"},
        {"localServer", "Enable Local Server"},
        {"localServerPort", "Local Server Port"},
        {"autoUpdateCheck", "Check for Updates"},
        {"updateChannel", "Update Channel"},
        {"showWelcomeOnStartup", "Show Welcome Page on Startup"}};
    auto it = labels.find(key);
    return it != labels.end() ? it->second : key;
}

static std::string getSettingDescription(const std::string& key)
{
    static const std::map<std::string, std::string> desc = {
        {"autoSave", "Automatically save files after a delay."},
        {"fontSize", "Controls the font size in pixels for the editor."},
        {"tabSize", "The number of spaces a tab is equal to."},
        {"minimap", "Show a minimap (code outline) of the source code."},
        {"smoothScroll", "Animate scrolling for a smoother experience."},
        {"caretAnimation", "Controls the cursor animation style."},
        {"breadcrumbs", "Enable breadcrumb navigation above the editor."},
        {"aiTemperature", "Controls randomness: lower is more focused, higher is more creative."},
        {"ghostText", "Show inline AI completions as ghost text."},
        {"amdUnifiedMemory",
         "Enable RawrXD unified memory executor (Resizable BAR when available; else host-backed arena). "
         "Requires Apply + Save. Toggle off to release the arena."},
        {"modelPrefetchEnabled",
         "Use PrefetchVirtualMemory to reduce first-touch latency and tail jitter when streaming large GGUF files."},
        {"modelWorkingSetLockEnabled", "Best-effort SetProcessWorkingSetSizeEx hard-min to reduce trimming under "
                                       "memory pressure (may require rights)."},
        {"silencePrivilegeWarnings",
         "Suppress common privilege warnings (e.g. ERROR_PRIVILEGE_NOT_HELD/1314) during high-iteration benchmarks."},
        {"exec.mode",
         "AUTO plans Expert knobs inside locks. EXPERT edits them. GUIDED exposes budgets + layers + target."},
        {"exec.vramGb", "Hard VRAM budget. Partition sum must fit; rejected if live working set cannot shrink."},
        {"exec.ramGb", "Host RAM budget for mapped weights, KV spill, and staging."},
        {"exec.objective", "throughput | latency | lowest_memory | power | balanced"},
        {"exec.streaming", "Allow NVMe→RAM→GPU streaming for overflow layers/tensors."},
        {"exec.layersGpu0", "Layer range permanently / preferentially on GPU0."},
        {"exec.kv", "gpu | gpu_paged | ram | hybrid | disk_paged"},
        {"exec.reuse", "Certified reuse only skips work with verified invariants."},
        {"exec.respectOverrides", "AUTO — RESPECT OVERRIDES: keep UserLocked fields, optimize the rest."},
        {"exec.persist", "Write IDE/session changes back to rawrxd.settings.yaml / model profile."},
        {"exec.policySha", "Reproducible digest of the effective execution contract."},
        {"windowAlpha", "Window transparency level (255 = fully opaque)."},
        {"autoUpdateCheck", "Periodically check for application updates."},
        {"fileIconTheme", "Icon theme for file explorer (seti, material, none)."}};
    auto it = desc.find(key);
    return it != desc.end() ? it->second : "";
}

// ============================================================================
// GET/SET SETTING VALUE
// ============================================================================

std::string Win32IDE_GetSettingValue(const IDESettings& s, const std::string& key)
{
    if (key.size() >= 5 && key.compare(0, 5, "exec.") == 0)
        return Deep2::Exec::Ide::Get(key);
    if (key == "autoSave")
        return s.autoSaveEnabled ? "true" : "false";
    if (key == "autoSaveInterval")
        return std::to_string(s.autoSaveIntervalSec);
    if (key == "lineNumbers")
        return s.lineNumbersVisible ? "true" : "false";
    if (key == "wordWrap")
        return s.wordWrapEnabled ? "true" : "false";
    if (key == "fontSize")
        return std::to_string(s.fontSize);
    if (key == "fontName")
        return s.fontName;
    if (key == "workingDirectory")
        return s.workingDirectory;
    if (key == "tabSize")
        return std::to_string(s.tabSize);
    if (key == "useSpaces")
        return s.useSpaces ? "true" : "false";
    if (key == "encoding")
        return s.encoding;
    if (key == "eolStyle")
        return s.eolStyle;
    if (key == "syntaxColoring")
        return s.syntaxColoringEnabled ? "true" : "false";
    if (key == "minimap")
        return s.minimapEnabled ? "true" : "false";
    if (key == "smoothScroll")
        return s.smoothScrollEnabled ? "true" : "false";
    if (key == "caretAnimation")
        return s.caretAnimationEnabled ? "true" : "false";
    if (key == "breadcrumbs")
        return s.breadcrumbsEnabled ? "true" : "false";
    if (key == "aiTemperature")
    {
        char b[32];
        snprintf(b, 32, "%.2f", s.aiTemperature);
        return b;
    }
    if (key == "aiTopP")
    {
        char b[32];
        snprintf(b, 32, "%.2f", s.aiTopP);
        return b;
    }
    if (key == "aiTopK")
        return std::to_string(s.aiTopK);
    if (key == "aiMaxTokens")
        return std::to_string(s.aiMaxTokens);
    if (key == "aiContextWindow")
        return std::to_string(s.aiContextWindow);
    if (key == "aiModelPath")
        return s.aiModelPath;
    if (key == "aiOllamaUrl")
        return s.aiOllamaUrl;
    if (key == "ghostText")
        return s.ghostTextEnabled ? "true" : "false";
    if (key == "failureDetector")
        return s.failureDetectorEnabled ? "true" : "false";
    if (key == "failureMaxRetries")
        return std::to_string(s.failureMaxRetries);
    if (key == "amdUnifiedMemory")
        return s.amdUnifiedMemoryEnabled ? "true" : "false";
    if (key == "modelPrefetchEnabled")
        return s.modelPrefetchEnabled ? "true" : "false";
    if (key == "modelWorkingSetLockEnabled")
        return s.modelWorkingSetLockEnabled ? "true" : "false";
    if (key == "silencePrivilegeWarnings")
        return s.silencePrivilegeWarnings ? "true" : "false";
    if (key == "themeId")
        return std::to_string(s.themeId);
    if (key == "windowAlpha")
        return std::to_string((int)s.windowAlpha);
    if (key == "fileIconTheme")
        return s.fileIconTheme;
    if (key == "localServer")
        return s.localServerEnabled ? "true" : "false";
    if (key == "localServerPort")
        return std::to_string(s.localServerPort);
    if (key == "autoUpdateCheck")
        return s.autoUpdateCheckEnabled ? "true" : "false";
    if (key == "updateChannel")
        return s.updateChannel;
    if (key == "showWelcomeOnStartup")
        return s.showWelcomeOnStartup ? "true" : "false";
    return "";
}

static void Win32IDE_SetSettingValue(IDESettings& s, const std::string& key, const std::string& value)
{
    if (key.size() >= 5 && key.compare(0, 5, "exec.") == 0) {
        if (key != "exec.policySha")
            Deep2::Exec::Ide::Set(key, value);
        return;
    }
    auto toBool = [](const std::string& v) { return v == "true" || v == "1"; };
    auto toInt = [](const std::string& v)
    {
        try
        {
            return std::stoi(v);
        }
        catch (...)
        {
            return 0;
        }
    };
    auto toFloat = [](const std::string& v)
    {
        try
        {
            return std::stof(v);
        }
        catch (...)
        {
            return 0.0f;
        }
    };

    if (key == "autoSave")
        s.autoSaveEnabled = toBool(value);
    else if (key == "autoSaveInterval")
        s.autoSaveIntervalSec = toInt(value);
    else if (key == "lineNumbers")
        s.lineNumbersVisible = toBool(value);
    else if (key == "wordWrap")
        s.wordWrapEnabled = toBool(value);
    else if (key == "fontSize")
        s.fontSize = toInt(value);
    else if (key == "fontName")
        s.fontName = value;
    else if (key == "workingDirectory")
        s.workingDirectory = value;
    else if (key == "tabSize")
        s.tabSize = toInt(value);
    else if (key == "useSpaces")
        s.useSpaces = toBool(value);
    else if (key == "encoding")
        s.encoding = value;
    else if (key == "eolStyle")
        s.eolStyle = value;
    else if (key == "syntaxColoring")
        s.syntaxColoringEnabled = toBool(value);
    else if (key == "minimap")
        s.minimapEnabled = toBool(value);
    else if (key == "smoothScroll")
        s.smoothScrollEnabled = toBool(value);
    else if (key == "caretAnimation")
        s.caretAnimationEnabled = toBool(value);
    else if (key == "breadcrumbs")
        s.breadcrumbsEnabled = toBool(value);
    else if (key == "aiTemperature")
        s.aiTemperature = toFloat(value);
    else if (key == "aiTopP")
        s.aiTopP = toFloat(value);
    else if (key == "aiTopK")
        s.aiTopK = toInt(value);
    else if (key == "aiMaxTokens")
        s.aiMaxTokens = toInt(value);
    else if (key == "aiContextWindow")
        s.aiContextWindow = toInt(value);
    else if (key == "aiModelPath")
        s.aiModelPath = value;
    else if (key == "aiOllamaUrl")
        s.aiOllamaUrl = value;
    else if (key == "ghostText")
        s.ghostTextEnabled = toBool(value);
    else if (key == "failureDetector")
        s.failureDetectorEnabled = toBool(value);
    else if (key == "failureMaxRetries")
        s.failureMaxRetries = toInt(value);
    else if (key == "amdUnifiedMemory")
        s.amdUnifiedMemoryEnabled = toBool(value);
    else if (key == "modelPrefetchEnabled")
        s.modelPrefetchEnabled = toBool(value);
    else if (key == "modelWorkingSetLockEnabled")
        s.modelWorkingSetLockEnabled = toBool(value);
    else if (key == "silencePrivilegeWarnings")
        s.silencePrivilegeWarnings = toBool(value);
    else if (key == "themeId")
        s.themeId = toInt(value);
    else if (key == "windowAlpha")
        s.windowAlpha = static_cast<BYTE>(toInt(value));
    else if (key == "fileIconTheme")
        s.fileIconTheme = value;
    else if (key == "localServer")
        s.localServerEnabled = toBool(value);
    else if (key == "localServerPort")
        s.localServerPort = toInt(value);
    else if (key == "autoUpdateCheck")
        s.autoUpdateCheckEnabled = toBool(value);
    else if (key == "updateChannel")
        s.updateChannel = value;
    else if (key == "showWelcomeOnStartup")
        s.showWelcomeOnStartup = toBool(value);
}

// ============================================================================
// SETTINGS GUI WINDOW PROCEDURE
// ============================================================================

LRESULT CALLBACK SettingsGUIProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    switch (uMsg)
    {
        case WM_CREATE:
        {
            CREATESTRUCTA* cs = (CREATESTRUCTA*)lParam;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)cs->lpCreateParams);
            return 0;
        }

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
        {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, SGUI_INPUT_BG);
            SetTextColor(hdc, SGUI_INPUT_TEXT);
            static HBRUSH hBrush = CreateSolidBrush(SGUI_INPUT_BG);
            return (LRESULT)hBrush;
        }

        case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            int wmEvent = HIWORD(wParam);

            if (wmId == IDC_SETTINGS_APPLY && pThis)
            {
                pThis->applySettings();
                pThis->saveSettings();
                RAWRXD_LOG_INFO("Settings applied and saved via GUI");
                return 0;
            }
            if (wmId == IDC_SETTINGS_RESET && pThis)
            {
                pThis->applyDefaultSettings();
                // Refresh the GUI
                if (pThis->m_hwndSettingsGUI)
                    SendMessage(pThis->m_hwndSettingsGUI, WM_USER + 1, 0, 0);
                return 0;
            }
            if (wmId == IDC_SETTINGS_CLOSE)
            {
                DestroyWindow(hwnd);
                return 0;
            }

            // Handle search box changes
            if (wmId == IDC_SETTINGS_SEARCH && wmEvent == EN_CHANGE && pThis)
            {
                char buf[256];
                GetWindowTextA(pThis->m_hwndSettingsSearch, buf, 256);
                pThis->filterSettings(buf);
            }

            // Handle dynamic property controls (checkboxes, edits, etc.)
            if (wmId >= IDC_SETTINGS_PROP_BASE && wmId < IDC_SETTINGS_PROP_BASE + 200 && pThis)
            {
                // Calculate which setting this control corresponds to
                int propIndex = wmId - IDC_SETTINGS_PROP_BASE;
                // Settings are stored in schema order; find the key
                int keyIdx = 0;
                for (const auto& cat : pThis->m_settingsSchema)
                {
                    for (const auto& key : cat.keys)
                    {
                        if (keyIdx == propIndex)
                        {
                            std::string type = getSettingType(key);
                            if (type == "bool" && wmEvent == BN_CLICKED)
                            {
                                bool checked = (SendMessage((HWND)lParam, BM_GETCHECK, 0, 0) == BST_CHECKED);
                                Win32IDE_SetSettingValue(pThis->m_settings, key, checked ? "true" : "false");
                            }
                            else if (wmEvent == EN_KILLFOCUS)
                            {
                                char val[512];
                                GetWindowTextA((HWND)lParam, val, 512);
                                Win32IDE_SetSettingValue(pThis->m_settings, key, val);
                            }
                            goto done;
                        }
                        keyIdx++;
                    }
                }
            done:;
            }

            // Handle tab selection
            if (wmId == IDC_SETTINGS_TABS && wmEvent == TCN_SELCHANGE && pThis)
            {
                int sel = TabCtrl_GetCurSel(pThis->m_hwndSettingsTabs);
                pThis->onSettingsCategorySelect(sel);
            }
            break;
        }

        case WM_NOTIFY:
        {
            NMHDR* nmhdr = (NMHDR*)lParam;
            if (nmhdr->idFrom == IDC_SETTINGS_TABS && nmhdr->code == TCN_SELCHANGE && pThis)
            {
                int sel = TabCtrl_GetCurSel(pThis->m_hwndSettingsTabs);
                pThis->onSettingsCategorySelect(sel);
            }
            break;
        }

        case WM_DESTROY:
            if (pThis)
            {
                pThis->m_hwndSettingsGUI = nullptr;
                pThis->m_hwndSettingsSearch = nullptr;
                pThis->m_hwndSettingsTabs = nullptr;
                pThis->m_hwndSettingsPanel = nullptr;
            }
            return 0;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// ============================================================================
// SHOW SETTINGS GUI — Main entry point
// ============================================================================

void Win32IDE::showSettingsGUI()
{
    if (m_hwndSettingsGUI && IsWindow(m_hwndSettingsGUI))
    {
        SetForegroundWindow(m_hwndSettingsGUI);
        return;
    }

    buildSettingsSchema();

    // Register window class for settings GUI
    static bool classRegistered = false;
    if (!classRegistered)
    {
        WNDCLASSEXA wc = {sizeof(WNDCLASSEXA)};
        wc.lpfnWndProc = SettingsGUIProc;
        wc.hInstance = m_hInstance;
        wc.lpszClassName = "RawrXD_SettingsGUI";
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = CreateSolidBrush(SGUI_BG);
        RegisterClassExA(&wc);
        classRegistered = true;
    }

    // Create settings window
    m_hwndSettingsGUI = CreateWindowExA(WS_EX_TOOLWINDOW, "RawrXD_SettingsGUI", "Settings", WS_OVERLAPPEDWINDOW,
                                        CW_USEDEFAULT, CW_USEDEFAULT, 750, 600, m_hwndMain, nullptr, m_hInstance, this);

    if (!m_hwndSettingsGUI)
    {
        RAWRXD_LOG_INFO("Win32IDE_SettingsGUI") << "Failed to create settings GUI window";
        return;
    }

    createSettingsControls(m_hwndSettingsGUI);
    ShowWindow(m_hwndSettingsGUI, SW_SHOW);
    UpdateWindow(m_hwndSettingsGUI);
}

// ============================================================================
// CREATE SETTINGS CONTROLS — Build the tabbed settings UI
// ============================================================================

void Win32IDE::createSettingsControls(HWND hwndParent)
{
    HFONT hFont = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    // Search bar at top
    HWND searchLabel =
        CreateWindowExA(0, "STATIC", "  Search settings:", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE, 10, 10,
                        120, 24, hwndParent, nullptr, m_hInstance, nullptr);
    SendMessage(searchLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    m_hwndSettingsSearch = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 135,
                                           10, 590, 24, hwndParent, (HMENU)IDC_SETTINGS_SEARCH, m_hInstance, nullptr);
    SendMessage(m_hwndSettingsSearch, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Tab control for categories
    m_hwndSettingsTabs = CreateWindowExA(0, WC_TABCONTROLA, "", WS_CHILD | WS_VISIBLE | TCS_TABS, 10, 42, 715, 28,
                                         hwndParent, (HMENU)IDC_SETTINGS_TABS, m_hInstance, nullptr);
    SendMessage(m_hwndSettingsTabs, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Add category tabs
    for (int i = 0; i < (int)m_settingsSchema.size(); i++)
    {
        TCITEMA tie = {TCIF_TEXT};
        tie.pszText = const_cast<char*>(m_settingsSchema[i].name.c_str());
        TabCtrl_InsertItem(m_hwndSettingsTabs, i, &tie);
    }

    // Settings panel (scrollable area for property controls)
    m_hwndSettingsPanel = CreateWindowExA(WS_EX_CLIENTEDGE, "STATIC", "", WS_CHILD | WS_VISIBLE | WS_VSCROLL, 10, 75,
                                          715, 440, hwndParent, (HMENU)IDC_SETTINGS_PANEL, m_hInstance, nullptr);

    // Bottom buttons
    HWND hApply = CreateWindowExA(0, "BUTTON", "Apply && Save", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 440, 525, 100,
                                  28, hwndParent, (HMENU)IDC_SETTINGS_APPLY, m_hInstance, nullptr);
    HWND hReset = CreateWindowExA(0, "BUTTON", "Reset Defaults", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 550, 525, 100,
                                  28, hwndParent, (HMENU)IDC_SETTINGS_RESET, m_hInstance, nullptr);
    HWND hClose = CreateWindowExA(0, "BUTTON", "Close", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 660, 525, 60, 28,
                                  hwndParent, (HMENU)IDC_SETTINGS_CLOSE, m_hInstance, nullptr);

    SendMessage(hApply, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hReset, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hClose, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Show first category
    onSettingsCategorySelect(0);
}

// ============================================================================
// POPULATE SETTINGS FOR SELECTED CATEGORY
// ============================================================================

void Win32IDE::onSettingsCategorySelect(int categoryIndex)
{
    if (categoryIndex < 0 || categoryIndex >= (int)m_settingsSchema.size())
        return;
    if (!m_hwndSettingsPanel)
        return;

    // Destroy existing property controls in the panel
    HWND child = GetWindow(m_hwndSettingsPanel, GW_CHILD);
    while (child)
    {
        HWND next = GetWindow(child, GW_HWNDNEXT);
        DestroyWindow(child);
        child = next;
    }

    const auto& cat = m_settingsSchema[categoryIndex];

    HFONT hFont = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    HFONT hDescFont = CreateFontA(-11, 0, 0, 0, FW_NORMAL, TRUE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                  CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    int yPos = 10;
    int keyGlobalIdx = 0;

    // Calculate global key index offset for this category
    for (int c = 0; c < categoryIndex; c++)
    {
        keyGlobalIdx += (int)m_settingsSchema[c].keys.size();
    }

    for (int k = 0; k < (int)cat.keys.size(); k++)
    {
        const auto& key = cat.keys[k];
        std::string label = getSettingLabel(key);
        std::string desc = getSettingDescription(key);
        std::string type = getSettingType(key);
        std::string value = Win32IDE_GetSettingValue(m_settings, key);

        int controlId = IDC_SETTINGS_PROP_BASE + keyGlobalIdx + k;

        // Label
        HWND hLabel = CreateWindowExA(0, "STATIC", label.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT, 10, yPos, 300, 18,
                                      m_hwndSettingsPanel, nullptr, m_hInstance, nullptr);
        SendMessage(hLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
        yPos += 20;

        // Description (italic, smaller)
        if (!desc.empty())
        {
            HWND hDesc = CreateWindowExA(0, "STATIC", desc.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT, 10, yPos, 680, 16,
                                         m_hwndSettingsPanel, nullptr, m_hInstance, nullptr);
            SendMessage(hDesc, WM_SETFONT, (WPARAM)hDescFont, TRUE);
            yPos += 18;
        }

        // Control based on type
        if (type == "bool")
        {
            HWND hCheck = CreateWindowExA(0, "BUTTON", "", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 320,
                                          yPos - (desc.empty() ? 20 : 38), 24, 20, m_hwndSettingsPanel,
                                          (HMENU)(UINT_PTR)controlId, m_hInstance, nullptr);
            SendMessage(hCheck, BM_SETCHECK, (value == "true") ? BST_CHECKED : BST_UNCHECKED, 0);
        }
        else if (type == "int")
        {
            HWND hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", value.c_str(),
                                         WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_AUTOHSCROLL, 320,
                                         yPos - (desc.empty() ? 20 : 38), 120, 22, m_hwndSettingsPanel,
                                         (HMENU)(UINT_PTR)controlId, m_hInstance, nullptr);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        }
        else if (type == "float")
        {
            HWND hEdit =
                CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", value.c_str(), WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 320,
                                yPos - (desc.empty() ? 20 : 38), 120, 22, m_hwndSettingsPanel,
                                (HMENU)(UINT_PTR)controlId, m_hInstance, nullptr);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        }
        else
        {
            // String
            HWND hEdit =
                CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", value.c_str(), WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 320,
                                yPos - (desc.empty() ? 20 : 38), 360, 22, m_hwndSettingsPanel,
                                (HMENU)(UINT_PTR)controlId, m_hInstance, nullptr);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        }

        yPos += 12;
    }
}

// ============================================================================
// SETTING CHANGED — Handle individual setting change
// ============================================================================

void Win32IDE::onSettingChanged(const std::string& key, const std::string& value)
{
    Win32IDE_SetSettingValue(m_settings, key, value);
    RAWRXD_LOG_INFO("Win32IDE_SettingsGUI") << "Setting changed: " << key << " = " << value;
}

// ============================================================================
// FILTER SETTINGS — Search across all categories/keys
// ============================================================================

void Win32IDE::filterSettings(const std::string& query)
{
    m_settingsSearchQuery = query;

    if (query.empty())
    {
        // Show first tab as-is
        int sel = TabCtrl_GetCurSel(m_hwndSettingsTabs);
        onSettingsCategorySelect(sel >= 0 ? sel : 0);
        return;
    }

    // Rebuild panel showing only matching settings from all categories
    if (!m_hwndSettingsPanel)
        return;

    // Destroy existing controls
    HWND child = GetWindow(m_hwndSettingsPanel, GW_CHILD);
    while (child)
    {
        HWND next = GetWindow(child, GW_HWNDNEXT);
        DestroyWindow(child);
        child = next;
    }

    HFONT hFont = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    std::string lowerQuery;
    lowerQuery.resize(query.size());
    std::transform(query.begin(), query.end(), lowerQuery.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });

    int yPos = 10;
    int globalKeyIdx = 0;

    for (const auto& cat : m_settingsSchema)
    {
        for (const auto& key : cat.keys)
        {
            std::string label = getSettingLabel(key);
            std::string lowerLabel;
            lowerLabel.resize(label.size());
            std::transform(label.begin(), label.end(), lowerLabel.begin(),
                           [](unsigned char c) { return (char)std::tolower(c); });

            std::string lowerKey;
            lowerKey.resize(key.size());
            std::transform(key.begin(), key.end(), lowerKey.begin(),
                           [](unsigned char c) { return (char)std::tolower(c); });

            // Check if query matches label or key
            if (lowerLabel.find(lowerQuery) != std::string::npos || lowerKey.find(lowerQuery) != std::string::npos)
            {

                std::string type = getSettingType(key);
                std::string value = Win32IDE_GetSettingValue(m_settings, key);
                int controlId = IDC_SETTINGS_PROP_BASE + globalKeyIdx;

                // Category header
                std::string headerText = "[" + cat.name + "] " + label;
                HWND hLabel = CreateWindowExA(0, "STATIC", headerText.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT, 10,
                                              yPos, 300, 18, m_hwndSettingsPanel, nullptr, m_hInstance, nullptr);
                SendMessage(hLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
                yPos += 22;

                // Control
                if (type == "bool")
                {
                    HWND hCheck =
                        CreateWindowExA(0, "BUTTON", "", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 320, yPos - 22, 24,
                                        20, m_hwndSettingsPanel, (HMENU)(UINT_PTR)controlId, m_hInstance, nullptr);
                    SendMessage(hCheck, BM_SETCHECK, (value == "true") ? BST_CHECKED : BST_UNCHECKED, 0);
                }
                else
                {
                    HWND hEdit =
                        CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", value.c_str(), WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                        320, yPos - 22, (type == "string") ? 360 : 120, 22, m_hwndSettingsPanel,
                                        (HMENU)(UINT_PTR)controlId, m_hInstance, nullptr);
                    SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
                }

                yPos += 12;
            }
            globalKeyIdx++;
        }
    }

    if (yPos == 10)
    {
        // No matches
        HWND hNoMatch =
            CreateWindowExA(0, "STATIC", "  No settings match your search.", WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 20,
                            400, 20, m_hwndSettingsPanel, nullptr, m_hInstance, nullptr);
        SendMessage(hNoMatch, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
}

// ============================================================================
// POPULATE SETTINGS TREE (Legacy — for tree-view mode if desired)
// ============================================================================

void Win32IDE::populateSettingsTree()
{
    // Currently handled by tab control in createSettingsControls
}

// ============================================================================
// RESOURCE MAP + TUNER SUGGEST (ExecutionPolicy live tools)
// ============================================================================

void Win32IDE::showResourceMapDialog()
{
    using namespace ::Deep2::Exec;
    auto snap = BuildResourceMapFromPolicy();
    std::string text = FormatResourceMap(snap);
    text += "\n\nYes = refresh only\nNo = pin token_embd.weight\nCancel = move L0-3 → GPU0";
    const int choice =
        MessageBoxA(m_hwndMain, text.c_str(), "RawrXD Resource Map", MB_YESNOCANCEL | MB_ICONINFORMATION);
    if (choice == IDNO) {
        auto r = PinFromMap("token_embd.weight");
        MessageBoxA(m_hwndMain, r.ok ? "Pinned token_embd.weight" : r.detail.c_str(),
                    "Resource Map", MB_OK);
    } else if (choice == IDCANCEL) {
        auto r = MoveLayers(LayerRange{0, 3}, DeviceKind::Gpu0);
        MessageBoxA(m_hwndMain, r.ok ? "Moved L0-3 → GPU0 (session)" : r.detail.c_str(),
                    "Resource Map", MB_OK);
    }
}

void Win32IDE::showTunerSuggestDialog()
{
    using namespace ::Deep2::Exec;
    EnsurePolicyLoaded();
    LearnedProfile learned;
    const auto& hw = ActiveHardwareSnapshot();
    const std::string hwFp =
        hw.fingerprint.empty() ? MakeHardwareFingerprint(hw) : hw.fingerprint;
    const std::string mfp = ExecutionPolicyStore::Instance().modelFingerprint();
    if (!hwFp.empty() && !mfp.empty())
        LearnedProfileStore::Instance().load(hwFp, mfp, learned);

    TunerProposal prop = Suggest(ActivePolicy(), learned.valid ? &learned : nullptr);
    if (!prop.hasProposal) {
        MessageBoxA(m_hwndMain, "No tuner suggestion right now.", "Tuner Suggest",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }
    const std::string body = FormatProposal(prop) +
                             "\n\nYes = Apply once\nNo = Ignore\nCancel = Apply + lock";
    const int choice =
        MessageBoxA(m_hwndMain, body.c_str(), "Tuner Suggest", MB_YESNOCANCEL | MB_ICONQUESTION);
    TunerAction act = TunerAction::Ignore;
    if (choice == IDYES) act = TunerAction::ApplyOnce;
    else if (choice == IDCANCEL) act = TunerAction::ApplyAndLock;
    auto r = ApplyProposal(prop, act, &hw, mfp.empty() ? nullptr : &mfp);
    if (act == TunerAction::ApplyAndLock && r.ok && !hwFp.empty() && !mfp.empty()) {
        LearnedProfile lp;
        lp.hardware = hw;
        if (lp.hardware.fingerprint.empty())
            lp.hardware.fingerprint = hwFp;
        lp.modelFingerprint = mfp;
        lp.policy = ActivePolicy();
        lp.policySha = r.policySha;
        lp.valid = true;
        LearnedProfileStore::Instance().save(lp);
        r.detail += "; profile saved";
    }
    if (act != TunerAction::Ignore) {
        std::string msg = r.ok ? ("Applied: " + r.detail) : ("Rejected: " + r.detail);
        MessageBoxA(m_hwndMain, msg.c_str(), "Tuner Suggest", MB_OK);
    }
}

