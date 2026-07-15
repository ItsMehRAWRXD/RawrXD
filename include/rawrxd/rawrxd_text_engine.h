// rawrxd_text_engine.h — Text engine definitions for line strip editor
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>

namespace rawrxd {
namespace ui {

struct SyntaxColorRun {
    uint32_t start = 0;
    uint32_t length = 0;
    COLORREF color = 0;
    uint32_t byteOffset = 0;
};

struct DocumentLine {
    std::string text;
    uint32_t lineNumber = 0;
    const char* rawBufferStart = nullptr;
    uint32_t lengthBytes = 0;
    uint32_t lineVersion = 0;
};

struct TextLineSpan {
    const char* textStart = nullptr;
    uint32_t length = 0;
};

struct TextLayoutViewport {
    int32_t firstVisibleLine = 0;
    int32_t visibleLineCount = 0;
    int32_t charWidth = 0;
    int32_t lineHeight = 0;
    RECT renderBounds = {};
    int32_t scrollOffsetY = 0;
    int32_t scrollOffsetX = 0;
    int32_t lastVisibleLine = 0;
};

struct RenderBufferWorkspace {
    std::vector<DocumentLine> lines;
    uint32_t poolCount = 0;
    TextLineSpan* visibleLinesPool = nullptr;
};

struct LineStreamWorkspace {
    int cellWidth = 0;
    int cellHeight = 0;
    void initialize() {}
};

struct LineStripCacheWorkspace {
    void* workspacePtr = nullptr;
};

struct SovereignWorkspaceController {
    bool initialize(uint8_t* arena, size_t arenaSize, uint32_t width, uint32_t height) { return true; }
    bool initialize(uint8_t* arena, size_t arenaSize, uint32_t lines, uint32_t cellW, uint32_t cellH, uint32_t charsPerLine) { return true; }
    void shutdown() {}
    void invalidateLineStructure(uint32_t lineIndex, uint32_t version) {}
    static uint32_t calculateRequiredArenaBytes(uint32_t lines, uint32_t cellW, uint32_t cellH, uint32_t charsPerLine) { return 16 * 1024 * 1024; }
    void synchronizeDirtyStrips(LineStreamWorkspace* stream, DocumentLine* lines, uint32_t lineCount, SyntaxColorRun* const* runTable, uint32_t* runCounts, bool fullSync) {}
    LineStripCacheWorkspace workspaceProxy() const { return LineStripCacheWorkspace{}; }
};

struct AgentVirtualCursor {
    int32_t line = 0;
    int32_t column = 0;
};

struct TextEngine {
    void initialize() {}
};

// Line render batch for syntax highlighting
struct LineRenderBatch {
    std::vector<SyntaxColorRun> runs;
    uint32_t lineIndex = 0;
};

// Helper function - inline definition
inline std::uint32_t packColorRef(COLORREF rgb) {
    return (0xFF000000u) | ((std::uint32_t)GetRValue(rgb) << 16) | ((std::uint32_t)GetGValue(rgb) << 8) | (std::uint32_t)GetBValue(rgb);
}

// Stub functions - inline definitions
inline bool softwareBlitRasterEnabled() { return true; }
inline bool lineStripCacheEnabled() { return true; }

struct SoftwareRasterWorkspace;
struct SoftwareSurface;

// Build line stream workspace from software atlas
inline bool buildLineStreamWorkspaceFromSoftwareAtlas(SoftwareRasterWorkspace* atlas, LineStreamWorkspace* workspace) {
    if (!workspace) return false;
    workspace->cellWidth = 8;
    workspace->cellHeight = 16;
    return true;
}

// Render line strip to software surface
inline bool renderLineStripToSoftwareSurface(LineStreamWorkspace* stream, SoftwareSurface* surface, uint32_t lineIndex, const char* text, uint32_t length, SyntaxColorRun* runs, uint32_t runCount) {
    (void)stream;
    (void)surface;
    (void)lineIndex;
    (void)text;
    (void)length;
    (void)runs;
    (void)runCount;
    return true;
}

// Present software surface to window
inline bool presentSoftwareSurfaceToWindow(SoftwareSurface* surface, HWND hwnd) {
    (void)surface;
    (void)hwnd;
    return true;
}

// Create software surface
inline SoftwareSurface* createSoftwareSurface(uint32_t width, uint32_t height) {
    (void)width;
    (void)height;
    return nullptr;
}

// Destroy software surface
inline void destroySoftwareSurface(SoftwareSurface* surface) {
    (void)surface;
}

// Clear software surface
inline void clearSoftwareSurface(SoftwareSurface* surface, COLORREF color) {
    (void)surface;
    (void)color;
}

// Get software surface pointer
inline uint32_t* getSoftwareSurfacePointer(SoftwareSurface* surface) {
    (void)surface;
    return nullptr;
}

// Get software surface pitch
inline uint32_t getSoftwareSurfacePitch(SoftwareSurface* surface) {
    (void)surface;
    return 0;
}

} // namespace ui
} // namespace rawrxd
