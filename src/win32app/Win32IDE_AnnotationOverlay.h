// ============================================================================
// Win32IDE_AnnotationOverlay.h — Transparent Annotation Layer
// ============================================================================
// Provides visual feedback (squiggles, highlights, inline hints) over the
// Scintilla editor without interfering with text editing
// ============================================================================

#pragma once

#include <windows.h>
#include <vector>
#include <memory>
#include <string>

namespace RawrXD::IDE {

// ============================================================================
// Annotation Types
// ============================================================================
enum class AnnotationType {
    None = 0,
    Suggestion,           // Ghost text / inline completion
    Warning,              // Yellow squiggle
    Error,                // Red squiggle
    Info,                 // Blue underline
    Highlight,            // Background highlight
    LoRA_Activation       // Neural heatmap from LoRA kernel
};

// ============================================================================
// Annotation Item
// ============================================================================
struct AnnotationItem {
    AnnotationType type = AnnotationType::None;
    int line = 0;              // 0-based line number
    int startCol = 0;          // 0-based column
    int endCol = 0;            // End column
    std::wstring text;         // Display text
    uint32_t color = 0;        // RGB color
    float confidence = 0.0f;   // 0.0 - 1.0 (for LoRA activations)
    uint64_t timestamp = 0;    // Creation time
};

// ============================================================================
// Annotation Overlay Window
// ============================================================================
class AnnotationOverlay {
public:
    AnnotationOverlay();
    ~AnnotationOverlay();

    // Initialize the overlay window
    // parentHwnd = handle to editor window to overlay
    bool Initialize(HWND parentHwnd);
    
    // Shutdown and cleanup
    void Shutdown();
    
    // Show/hide the overlay
    void Show();
    void Hide();
    bool IsVisible() const { return m_visible; }
    
    // Update position to match parent editor
    void SyncPosition();
    
    // Add/remove annotations
    void AddAnnotation(const AnnotationItem& item);
    void ClearAnnotations();
    void ClearAnnotationsOfType(AnnotationType type);
    
    // Update from LoRA kernel result
    void UpdateFromLoRAResult(uint32_t requestId, const std::vector<float>& result);
    
    // Static helper to post LoRA result from any thread (thread-safe)
    static void PostLoRAResult(HWND hwndOverlay, uint32_t requestId, 
                                const std::vector<float>& result);
    
    // Render the overlay
    void Render();
    
    // Handle editor scroll (called by parent)
    void OnEditorScroll(int scrollPos);
    
    // Get the overlay window handle
    HWND GetWindowHandle() const { return m_hwndOverlay; }

private:
    // Window procedure (static)
    static LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    
    // Instance window procedure
    LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
    
    // Create the overlay window
    bool CreateOverlayWindow();
    
    // Drawing functions
    void DrawAnnotation(HDC hdc, const AnnotationItem& item);
    void DrawSquiggle(HDC hdc, int x, int y, int width, uint32_t color);
    void DrawGhostText(HDC hdc, int x, int y, const std::wstring& text);
    void DrawHighlight(HDC hdc, int x, int y, int width, int height, uint32_t color);
    
    // Member variables
    HWND m_hwndParent = nullptr;
    HWND m_hwndOverlay = nullptr;
    HINSTANCE m_hInstance = nullptr;
    bool m_visible = false;
    bool m_initialized = false;
    
    // Annotations
    std::vector<AnnotationItem> m_annotations;
    std::mutex m_annotationsMutex;
    
    // Scroll position tracking
    int m_scrollPos = 0;
    
    // GDI resources
    HDC m_memDC = nullptr;
    HBITMAP m_memBitmap = nullptr;
    int m_width = 0;
    int m_height = 0;
};

// ============================================================================
// C API for Integration
// ============================================================================

extern "C" {

// Create annotation overlay for an editor window
__declspec(dllexport) void* AnnotationOverlay_Create(HWND parentHwnd);

// Destroy overlay
__declspec(dllexport) void AnnotationOverlay_Destroy(void* overlay);

// Show/hide overlay
__declspec(dllexport) void AnnotationOverlay_Show(void* overlay);
__declspec(dllexport) void AnnotationOverlay_Hide(void* overlay);

// Add annotation
__declspec(dllexport) void AnnotationOverlay_AddSquiggle(
    void* overlay,
    int line,
    int startCol,
    int endCol,
    uint32_t color
);

// Add ghost text suggestion
__declspec(dllexport) void AnnotationOverlay_AddGhostText(
    void* overlay,
    int line,
    int col,
    const wchar_t* text
);

// Clear all annotations
__declspec(dllexport) void AnnotationOverlay_Clear(void* overlay);

// Update from LoRA result
__declspec(dllexport) void AnnotationOverlay_UpdateFromLoRA(
    void* overlay,
    uint32_t requestId,
    const float* resultData,
    size_t resultSize
);

// Thread-safe post LoRA result (for use from background threads)
__declspec(dllexport) void AnnotationOverlay_PostLoRAResult(
    HWND hwndOverlay,
    uint32_t requestId,
    const float* resultData,
    size_t resultSize
);

} // extern "C"

} // namespace RawrXD::IDE
