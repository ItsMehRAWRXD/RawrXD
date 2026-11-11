// ============================================================================
// Win32IDE_AnnotationOverlay.cpp — Transparent Annotation Layer Implementation
// ============================================================================

#include "Win32IDE_AnnotationOverlay.h"
#include "Win32IDE.h"
#include <windowsx.h>
#include <gdiplus.h>
#include <algorithm>

#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

namespace RawrXD::IDE {

// ============================================================================
// Constants
// ============================================================================
static const wchar_t* OVERLAY_CLASS_NAME = L"RawrXD_AnnotationOverlay";
static const uint32_t SQUIGGLE_COLOR_WARNING = RGB(255, 204, 0);   // Yellow
static const uint32_t SQUIGGLE_COLOR_ERROR = RGB(255, 0, 0);     // Red
static const uint32_t SQUIGGLE_COLOR_INFO = RGB(0, 128, 255);      // Blue
static const uint32_t GHOST_TEXT_COLOR = RGB(128, 128, 128);      // Gray

// ============================================================================
// Constructor / Destructor
// ============================================================================
AnnotationOverlay::AnnotationOverlay() = default;

AnnotationOverlay::~AnnotationOverlay() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool AnnotationOverlay::Initialize(HWND parentHwnd) {
    if (m_initialized) return true;
    if (!parentHwnd || !IsWindow(parentHwnd)) return false;
    
    m_hwndParent = parentHwnd;
    m_hInstance = GetModuleHandle(nullptr);
    
    // Initialize GDI+
    GdiplusStartupInput gdiplusStartupInput;
    GdiplusStartup(&gdiplusStartupInput, &gdiplusStartupInput, nullptr);
    
    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = OverlayWndProc;
    wc.hInstance = m_hInstance;
    wc.lpszClassName = OVERLAY_CLASS_NAME;
    wc.hbrBackground = (HBRUSH)GetStockObject(NULL_BRUSH);
    
    if (!GetClassInfoExW(m_hInstance, OVERLAY_CLASS_NAME, &wc)) {
        if (!RegisterClassExW(&wc)) {
            OutputDebugStringA("[AnnotationOverlay] Failed to register window class\n");
            return false;
        }
    }
    
    // Create overlay window
    if (!CreateOverlayWindow()) {
        return false;
    }
    
    // Store pointer in window data
    SetWindowLongPtrW(m_hwndOverlay, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    
    m_initialized = true;
    OutputDebugStringA("[AnnotationOverlay] Initialized successfully\n");
    return true;
}

bool AnnotationOverlay::CreateOverlayWindow() {
    // Get parent dimensions
    RECT rcParent;
    GetClientRect(m_hwndParent, &rcParent);
    m_width = rcParent.right - rcParent.left;
    m_height = rcParent.bottom - rcParent.top;
    
    // Create layered, transparent window
    m_hwndOverlay = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE,
        OVERLAY_CLASS_NAME,
        L"Annotation Overlay",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0, 0, m_width, m_height,
        m_hwndParent,
        nullptr,
        m_hInstance,
        nullptr
    );
    
    if (!m_hwndOverlay) {
        OutputDebugStringA("[AnnotationOverlay] Failed to create overlay window\n");
        return false;
    }
    
    // Set transparency (fully transparent background, opaque content)
    SetLayeredWindowAttributes(m_hwndOverlay, RGB(0, 0, 0), 0, LWA_COLORKEY);
    
    // Create memory DC for double buffering
    HDC hdcScreen = GetDC(nullptr);
    m_memDC = CreateCompatibleDC(hdcScreen);
    m_memBitmap = CreateCompatibleBitmap(hdcScreen, m_width, m_height);
    SelectObject(m_memDC, m_memBitmap);
    ReleaseDC(nullptr, hdcScreen);
    
    return true;
}

// ============================================================================
// Shutdown
// ============================================================================
void AnnotationOverlay::Shutdown() {
    if (!m_initialized) return;
    
    // Cleanup GDI resources
    if (m_memBitmap) {
        DeleteObject(m_memBitmap);
        m_memBitmap = nullptr;
    }
    if (m_memDC) {
        DeleteDC(m_memDC);
        m_memDC = nullptr;
    }
    
    // Destroy window
    if (m_hwndOverlay && IsWindow(m_hwndOverlay)) {
        DestroyWindow(m_hwndOverlay);
        m_hwndOverlay = nullptr;
    }
    
    // Cleanup annotations
    ClearAnnotations();
    
    m_initialized = false;
    m_visible = false;
    
    OutputDebugStringA("[AnnotationOverlay] Shutdown complete\n");
}

// ============================================================================
// Visibility
// ============================================================================
void AnnotationOverlay::Show() {
    if (!m_initialized || !m_hwndOverlay) return;
    ShowWindow(m_hwndOverlay, SW_SHOW);
    m_visible = true;
    Render();
}

void AnnotationOverlay::Hide() {
    if (!m_initialized || !m_hwndOverlay) return;
    ShowWindow(m_hwndOverlay, SW_HIDE);
    m_visible = false;
}

// ============================================================================
// Position Sync
// ============================================================================
void AnnotationOverlay::SyncPosition() {
    if (!m_initialized || !m_hwndParent || !m_hwndOverlay) return;
    
    RECT rcParent;
    GetClientRect(m_hwndParent, &rcParent);
    
    int newWidth = rcParent.right - rcParent.left;
    int newHeight = rcParent.bottom - rcParent.top;
    
    // Resize if needed
    if (newWidth != m_width || newHeight != m_height) {
        m_width = newWidth;
        m_height = newHeight;
        
        // Recreate bitmap
        if (m_memBitmap) DeleteObject(m_memBitmap);
        HDC hdcScreen = GetDC(nullptr);
        m_memBitmap = CreateCompatibleBitmap(hdcScreen, m_width, m_height);
        SelectObject(m_memDC, m_memBitmap);
        ReleaseDC(nullptr, hdcScreen);
        
        SetWindowPos(m_hwndOverlay, nullptr, 0, 0, m_width, m_height,
                     SWP_NOZORDER | SWP_NOACTIVATE);
    }
    
    Render();
}

// ============================================================================
// Annotations
// ============================================================================
void AnnotationOverlay::AddAnnotation(const AnnotationItem& item) {
    std::lock_guard<std::mutex> lock(m_annotationsMutex);
    m_annotations.push_back(item);
    if (m_visible) Render();
}

void AnnotationOverlay::ClearAnnotations() {
    std::lock_guard<std::mutex> lock(m_annotationsMutex);
    m_annotations.clear();
    if (m_visible) Render();
}

void AnnotationOverlay::ClearAnnotationsOfType(AnnotationType type) {
    std::lock_guard<std::mutex> lock(m_annotationsMutex);
    m_annotations.erase(
        std::remove_if(m_annotations.begin(), m_annotations.end(),
            [type](const AnnotationItem& item) { return item.type == type; }),
        m_annotations.end()
    );
    if (m_visible) Render();
}

// ============================================================================
// LoRA Result Update
// ============================================================================
void AnnotationOverlay::UpdateFromLoRAResult(uint32_t requestId, 
                                              const std::vector<float>& result) {
    std::lock_guard<std::mutex> lock(m_annotationsMutex);
    
    // Clear previous LoRA activations
    ClearAnnotationsOfType(AnnotationType::LoRA_Activation);
    
    // Convert result to annotations
    // For now, just show top activations as highlights
    if (result.size() >= 768) {
        // Find top 5 activations
        std::vector<std::pair<float, int>> activations;
        for (int i = 0; i < 768; i++) {
            activations.push_back({result[i], i});
        }
        
        // Sort by activation value
        std::partial_sort(activations.begin(), activations.begin() + 5, 
                         activations.end(),
                         std::greater<std::pair<float, int>>());
        
        // Create annotations for top activations
        for (int i = 0; i < 5 && i < activations.size(); i++) {
            AnnotationItem item;
            item.type = AnnotationType::LoRA_Activation;
            item.line = activations[i].second / 80;  // Approximate line
            item.startCol = activations[i].second % 80;
            item.endCol = item.startCol + 10;
            item.confidence = activations[i].first;
            item.color = RGB(0, 255, 128);  // Green highlight
            item.text = L"LoRA: " + std::to_wstring((int)(item.confidence * 100)) + L"%";
            
            m_annotations.push_back(item);
        }
    }
    
    if (m_visible) Render();
}

// ============================================================================
// Static helper to post LoRA result from any thread
// ============================================================================
void AnnotationOverlay::PostLoRAResult(HWND hwndOverlay, uint32_t requestId, 
                                        const std::vector<float>& result) {
    if (!hwndOverlay || !IsWindow(hwndOverlay)) return;
    
    // Copy result data (receiver owns cleanup)
    auto* resultCopy = new std::vector<float>(result);
    
    PostMessage(hwndOverlay, WM_APP + 200, 
                static_cast<WPARAM>(requestId),
                reinterpret_cast<LPARAM>(resultCopy));
}

// ============================================================================
// Rendering
// ============================================================================
void AnnotationOverlay::Render() {
    if (!m_initialized || !m_visible || !m_memDC) return;
    
    // Clear background (transparent)
    RECT rc = {0, 0, m_width, m_height};
    FillRect(m_memDC, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
    
    // Draw all annotations
    {
        std::lock_guard<std::mutex> lock(m_annotationsMutex);
        for (const auto& item : m_annotations) {
            DrawAnnotation(m_memDC, item);
        }
    }
    
    // Update layered window
    HDC hdcScreen = GetDC(nullptr);
    POINT ptSrc = {0, 0};
    SIZE size = {m_width, m_height};
    BLENDFUNCTION blend = {AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};
    
    UpdateLayeredWindow(m_hwndOverlay, hdcScreen, nullptr, &size, m_memDC, &ptSrc, 
                       RGB(0, 0, 0), &blend, ULW_COLORKEY);
    
    ReleaseDC(nullptr, hdcScreen);
}

void AnnotationOverlay::DrawAnnotation(HDC hdc, const AnnotationItem& item) {
    // Calculate position based on line/column
    int lineHeight = 20;  // Approximate line height
    int charWidth = 8;    // Approximate char width
    
    int y = item.line * lineHeight - m_scrollPos;
    int x = item.startCol * charWidth;
    int width = (item.endCol - item.startCol) * charWidth;
    
    if (y < -20 || y > m_height) return;  // Off-screen
    
    switch (item.type) {
        case AnnotationType::Suggestion:
            DrawGhostText(hdc, x, y, item.text);
            break;
        case AnnotationType::Warning:
        case AnnotationType::Error:
        case AnnotationType::Info:
            DrawSquiggle(hdc, x, y + 16, width, item.color);
            break;
        case AnnotationType::Highlight:
        case AnnotationType::LoRA_Activation:
            DrawHighlight(hdc, x, y, width, lineHeight, item.color);
            break;
        default:
            break;
    }
}

void AnnotationOverlay::DrawSquiggle(HDC hdc, int x, int y, int width, uint32_t color) {
    HPEN pen = CreatePen(PS_SOLID, 2, color);
    HPEN oldPen = (HPEN)SelectObject(hdc, pen);
    
    // Draw zigzag pattern
    MoveToEx(hdc, x, y, nullptr);
    for (int i = 0; i < width; i += 4) {
        LineTo(hdc, x + i + 2, y + 2);
        LineTo(hdc, x + i + 4, y);
    }
    
    SelectObject(hdc, oldPen);
    DeleteObject(pen);
}

void AnnotationOverlay::DrawGhostText(HDC hdc, int x, int y, const std::wstring& text) {
    SetTextColor(hdc, GHOST_TEXT_COLOR);
    SetBkMode(hdc, TRANSPARENT);
    
    HFONT font = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Consolas");
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    
    TextOutW(hdc, x, y, text.c_str(), static_cast<int>(text.length()));
    
    SelectObject(hdc, oldFont);
    DeleteObject(font);
}

void AnnotationOverlay::DrawHighlight(HDC hdc, int x, int y, int width, int height, uint32_t color) {
    // Create semi-transparent brush
    HBRUSH brush = CreateSolidBrush(color);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, brush);
    
    RECT rc = {x, y, x + width, y + height};
    FillRect(hdc, &rc, brush);
    
    SelectObject(hdc, oldBrush);
    DeleteObject(brush);
}

// ============================================================================
// Scroll Handling
// ============================================================================
void AnnotationOverlay::OnEditorScroll(int scrollPos) {
    m_scrollPos = scrollPos;
    if (m_visible) Render();
}

// ============================================================================
// Window Procedure
// ============================================================================
LRESULT CALLBACK AnnotationOverlay::OverlayWndProc(HWND hwnd, UINT uMsg, 
                                                     WPARAM wParam, LPARAM lParam) {
    auto* pThis = reinterpret_cast<AnnotationOverlay*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    
    if (pThis) {
        return pThis->HandleMessage(uMsg, wParam, lParam);
    }
    
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

LRESULT AnnotationOverlay::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(m_hwndOverlay, &ps);
            Render();
            EndPaint(m_hwndOverlay, &ps);
            return 0;
        }
        
        case WM_SIZE:
            SyncPosition();
            return 0;
            
        case WM_ERASEBKGND:
            return 1;  // Prevent flicker
            
        case WM_APP + 200: {  // LoRA Kernel Completion
            // wParam = requestId, lParam = pointer to LoRA result data
            uint32_t requestId = static_cast<uint32_t>(wParam);
            auto* resultData = reinterpret_cast<std::vector<float>*>(lParam);
            
            if (resultData) {
                UpdateFromLoRAResult(requestId, *resultData);
                // Cleanup the allocated result data
                delete resultData;
            }
            return 0;
        }
            
        default:
            return DefWindowProcW(m_hwndOverlay, uMsg, wParam, lParam);
    }
}

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

void* AnnotationOverlay_Create(HWND parentHwnd) {
    auto* overlay = new RawrXD::IDE::AnnotationOverlay();
    if (!overlay->Initialize(parentHwnd)) {
        delete overlay;
        return nullptr;
    }
    return overlay;
}

void AnnotationOverlay_Destroy(void* overlay) {
    if (overlay) {
        delete static_cast<RawrXD::IDE::AnnotationOverlay*>(overlay);
    }
}

void AnnotationOverlay_Show(void* overlay) {
    if (overlay) {
        static_cast<RawrXD::IDE::AnnotationOverlay*>(overlay)->Show();
    }
}

void AnnotationOverlay_Hide(void* overlay) {
    if (overlay) {
        static_cast<RawrXD::IDE::AnnotationOverlay*>(overlay)->Hide();
    }
}

void AnnotationOverlay_AddSquiggle(void* overlay, int line, int startCol, 
                                    int endCol, uint32_t color) {
    if (!overlay) return;
    
    RawrXD::IDE::AnnotationItem item;
    item.type = RawrXD::IDE::AnnotationType::Warning;
    item.line = line;
    item.startCol = startCol;
    item.endCol = endCol;
    item.color = color;
    
    static_cast<RawrXD::IDE::AnnotationOverlay*>(overlay)->AddAnnotation(item);
}

void AnnotationOverlay_AddGhostText(void* overlay, int line, int col, 
                                     const wchar_t* text) {
    if (!overlay || !text) return;
    
    RawrXD::IDE::AnnotationItem item;
    item.type = RawrXD::IDE::AnnotationType::Suggestion;
    item.line = line;
    item.startCol = col;
    item.endCol = col + wcslen(text);
    item.text = text;
    
    static_cast<RawrXD::IDE::AnnotationOverlay*>(overlay)->AddAnnotation(item);
}

void AnnotationOverlay_Clear(void* overlay) {
    if (overlay) {
        static_cast<RawrXD::IDE::AnnotationOverlay*>(overlay)->ClearAnnotations();
    }
}

void AnnotationOverlay_UpdateFromLoRA(void* overlay, uint32_t requestId,
                                         const float* resultData, size_t resultSize) {
    if (!overlay || !resultData) return;
    
    std::vector<float> result(resultData, resultData + resultSize);
    static_cast<RawrXD::IDE::AnnotationOverlay*>(overlay)->UpdateFromLoRAResult(requestId, result);
}

void AnnotationOverlay_PostLoRAResult(HWND hwndOverlay, uint32_t requestId,
                                       const float* resultData, size_t resultSize) {
    if (!hwndOverlay || !resultData) return;
    
    std::vector<float> result(resultData, resultData + resultSize);
    RawrXD::IDE::AnnotationOverlay::PostLoRAResult(hwndOverlay, requestId, result);
}

} // extern "C"

} // namespace RawrXD::IDE
