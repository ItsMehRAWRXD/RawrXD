#include "ide_completion.h"
#include "cpu_inference_engine.h"
#include <thread>
#include <mutex>
#include <queue>
#include <sstream>

namespace IDECompletion {

// Global state
static std::string g_current_model = "codellama:7b";
static std::thread g_completion_thread;
static std::mutex g_state_mutex;
static std::queue<PopupContext> g_pending_requests;
static bool g_engine_ready = false;
static bool g_thread_running = false;
static HWND g_popup_hwnd = NULL;
static std::shared_ptr<RawrXD::CPUInferenceEngine> g_inference_engine = nullptr;
static std::string g_last_suggestion;

//==============================================================================
// COMPLETION POPUP WINDOW
//==============================================================================

LRESULT CALLBACK CompletionPopupProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Draw white background
            HBRUSH hBrush = CreateSolidBrush(RGB(240, 240, 240));
            FillRect(hdc, &ps.rcPaint, hBrush);
            DeleteObject(hBrush);
            
            // Draw border
            HPEN hPen = CreatePen(PS_SOLID, 1, RGB(100, 100, 100));
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            MoveToEx(hdc, ps.rcPaint.left, ps.rcPaint.top, NULL);
            LineTo(hdc, ps.rcPaint.right, ps.rcPaint.top);
            LineTo(hdc, ps.rcPaint.right, ps.rcPaint.bottom);
            LineTo(hdc, ps.rcPaint.left, ps.rcPaint.bottom);
            LineTo(hdc, ps.rcPaint.left, ps.rcPaint.top);
            SelectObject(hdc, hOldPen);
            DeleteObject(hPen);
            
            // Draw suggestion text
            std::string suggestion;
            {
                std::lock_guard<std::mutex> lock(g_state_mutex);
                suggestion = g_last_suggestion;
            }
            
            if (!suggestion.empty()) {
                // Convert to wide string for display
                int wideLen = MultiByteToWideChar(CP_UTF8, 0, suggestion.c_str(), -1, NULL, 0);
                if (wideLen > 0) {
                    std::wstring wideText(wideLen, 0);
                    MultiByteToWideChar(CP_UTF8, 0, suggestion.c_str(), -1, &wideText[0], wideLen);
                    
                    SetTextColor(hdc, RGB(0, 0, 0));
                    SetBkMode(hdc, TRANSPARENT);
                    
                    // Draw with word wrap
                    RECT textRect = {5, 5, ps.rcPaint.right - 5, ps.rcPaint.bottom - 5};
                    DrawTextW(hdc, wideText.c_str(), -1, &textRect, DT_LEFT | DT_TOP | DT_WORDBREAK);
                }
            } else {
                WCHAR szText[] = L"Loading suggestion...";
                SetTextColor(hdc, RGB(100, 100, 100));
                SetBkMode(hdc, TRANSPARENT);
                TextOutW(hdc, 5, 5, szText, wcslen(szText));
            }
            
            EndPaint(hwnd, &ps);
            break;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

//==============================================================================
// BACKGROUND COMPLETION WORKER
//==============================================================================

void CompletionWorkerThread() {
    while (g_thread_running) {
        PopupContext ctx;
        {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            if (g_pending_requests.empty()) {
                // Sleep briefly to avoid busy-waiting
                Sleep(10);
                continue;
            }
            ctx = g_pending_requests.front();
            g_pending_requests.pop();
        }

        // Use RawrXD native inference engine
        if (!g_inference_engine || !g_inference_engine->IsModelLoaded()) {
            continue;  // No model loaded, skip
        }

        // Build completion prompt
        std::string prompt = ctx.current_line;
        if (prompt.empty()) {
            continue;
        }

        // Tokenize the prompt
        auto input_tokens = g_inference_engine->Tokenize(prompt);
        if (input_tokens.empty()) {
            continue;
        }

        // Generate completion using native streaming API
        std::ostringstream completion_stream;
        std::atomic<bool> generation_complete{false};

        g_inference_engine->GenerateStreaming(
            input_tokens,
            64,  // Short suggestions for IDE completion
            [&completion_stream](const std::string& token) {
                completion_stream << token;
            },
            [&generation_complete]() {
                generation_complete = true;
            }
        );

        // Wait for generation to complete (with timeout)
        int timeout_ms = 5000;
        while (!generation_complete && timeout_ms > 0) {
            Sleep(10);
            timeout_ms -= 10;
        }

        std::string suggestion = completion_stream.str();
        if (!suggestion.empty()) {
            // Store suggestion for popup display
            {
                std::lock_guard<std::mutex> lock(g_state_mutex);
                g_last_suggestion = suggestion;
            }
            // Show popup with suggestion
            ShowCompletionPopup(ctx, suggestion);
        }
    }
}

//==============================================================================
// PUBLIC API IMPLEMENTATION
//==============================================================================

void InitializeCompletionEngine(const std::string& default_model) {
    std::lock_guard<std::mutex> lock(g_state_mutex);

    g_current_model = default_model;

    // Get RawrXD native inference engine (shared instance)
    g_inference_engine = RawrXD::CPUInferenceEngine::GetSharedInstance();
    
    // Engine is ready if it exists (model loading is separate)
    g_engine_ready = (g_inference_engine != nullptr);

    if (!g_engine_ready) {
        return;
    }

    // Start background worker thread
    g_thread_running = true;
    g_completion_thread = std::thread(CompletionWorkerThread);
}

// Alternative: Initialize with a specific model path
void InitializeCompletionEngineWithModel(const std::string& model_path) {
    std::lock_guard<std::mutex> lock(g_state_mutex);

    // Get or create the shared inference engine
    g_inference_engine = RawrXD::CPUInferenceEngine::GetSharedInstance();
    
    if (!g_inference_engine) {
        g_engine_ready = false;
        return;
    }

    // Load the model if path provided
    if (!model_path.empty()) {
        if (!g_inference_engine->IsModelLoaded()) {
            g_engine_ready = g_inference_engine->LoadModel(model_path);
        } else {
            g_engine_ready = true;  // Model already loaded
        }
    } else {
        g_engine_ready = g_inference_engine->IsModelLoaded();
    }

    // Start background worker thread if not already running
    if (g_engine_ready && !g_thread_running) {
        g_thread_running = true;
        g_completion_thread = std::thread(CompletionWorkerThread);
    }
}

void RequestCompletion(const PopupContext& ctx) {
    std::lock_guard<std::mutex> lock(g_state_mutex);

    if (!g_engine_ready) {
        return;
    }

    // Add to queue for background processing
    g_pending_requests.push(ctx);
}

void CancelCompletion() {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    
    // Clear pending requests
    while (!g_pending_requests.empty()) {
        g_pending_requests.pop();
    }

    HideCompletionPopup();
}

void ShowCompletionPopup(const PopupContext& ctx, const std::string& suggestion) {
    // Hide existing popup
    if (g_popup_hwnd && IsWindow(g_popup_hwnd)) {
        DestroyWindow(g_popup_hwnd);
    }

    // Register window class
    static WNDCLASSW wc = {0};
    if (!wc.lpszClassName) {
        wc.lpfnWndProc = CompletionPopupProc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.lpszClassName = L"RawrXD_CompletionPopup";
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        RegisterClassW(&wc);
    }

    // Create popup window
    g_popup_hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        L"RawrXD_CompletionPopup",
        L"Completion",
        WS_POPUP | WS_BORDER,
        ctx.x, ctx.y,
        300, 100,  // Width, Height
        ctx.hParentWnd,
        NULL,
        GetModuleHandleW(NULL),
        NULL);

    if (g_popup_hwnd) {
        ShowWindow(g_popup_hwnd, SW_SHOW);
        UpdateWindow(g_popup_hwnd);
    }
}

void HideCompletionPopup() {
    if (g_popup_hwnd && IsWindow(g_popup_hwnd)) {
        DestroyWindow(g_popup_hwnd);
        g_popup_hwnd = NULL;
    }
}

void SetCompletionModel(const std::string& model) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    g_current_model = model;
}

bool IsCompletionEngineReady() {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    return g_engine_ready;
}

} // namespace IDECompletion
