#pragma once

// RawrXD Line Strip Cache — Track B line-strip cache presentation layer
// Gated by RAWRXD_SOFTWARE_BLIT_RASTER=1 and RAWRXD_LINE_STRIP_CACHE=1.

#include "rawrxd/rawrxd_software_raster.h"

#include <cstddef>
#include <cstdint>
#include <windows.h>

namespace rawrxd::ui
{

// Line strip cache entry — per-line cached rendering data
struct LineStripCacheEntry
{
    std::uint32_t lineIndex = 0;
    std::uint32_t hash = 0;
    std::uint32_t textLength = 0;
    std::uint32_t runCount = 0;
    bool dirty = true;
    bool hasDiagnostics = false;
    bool hasGhostText = false;
    bool isFolded = false;
};

// Line strip viewport — visible line range
struct LineStripViewport
{
    std::uint32_t firstVisibleLine = 0;
    std::uint32_t visibleLineCount = 0;
    std::int32_t scrollOffsetY = 0;
    std::int32_t scrollOffsetX = 0;
};

// Line strip cache manager
struct LineStripCache
{
    LineStripCacheEntry* entries = nullptr;
    std::uint32_t capacity = 0;
    std::uint32_t count = 0;
    std::uint32_t generation = 0;
};

// Ghost text entry — inline completion preview
struct GhostTextEntry
{
    std::uint32_t lineIndex = 0;
    std::uint32_t startColumn = 0;
    std::uint32_t length = 0;
    const char* text = nullptr;
    bool visible = false;
};

// Diagnostic marker — squiggle/wave underline
struct DiagnosticMarker
{
    std::uint32_t lineIndex = 0;
    std::uint32_t startColumn = 0;
    std::uint32_t endColumn = 0;
    std::uint32_t severity = 0; // 0=error, 1=warning, 2=info, 3=hint
    bool visible = false;
};

// Caret/selection state for line strip
struct LineStripCaretState
{
    std::uint32_t lineIndex = 0;
    std::uint32_t column = 0;
    std::uint32_t selectionStartLine = 0;
    std::uint32_t selectionStartColumn = 0;
    std::uint32_t selectionEndLine = 0;
    std::uint32_t selectionEndColumn = 0;
    bool hasSelection = false;
    bool blinkState = true;
};

// Initialize line strip cache
bool initializeLineStripCache(LineStripCache* cache, std::uint32_t maxLines);

// Shutdown line strip cache
void shutdownLineStripCache(LineStripCache* cache);

// Mark line as dirty (needs re-render)
void markLineDirty(LineStripCache* cache, std::uint32_t lineIndex);

// Mark all lines dirty
void markAllLinesDirty(LineStripCache* cache);

// Update line entry
void updateLineStripEntry(LineStripCache* cache, std::uint32_t lineIndex,
                          const char* text, std::uint32_t textLength,
                          std::uint32_t hash);

// Invalidate cache range
void invalidateLineStripRange(LineStripCache* cache, std::uint32_t startLine, std::uint32_t endLine);

// Get cache entry for line
LineStripCacheEntry* getLineStripEntry(LineStripCache* cache, std::uint32_t lineIndex);

// Calculate line hash (simple FNV-1a)
std::uint32_t calculateLineHash(const char* text, std::uint32_t length);

// Check if line needs re-render
bool lineNeedsRender(const LineStripCacheEntry* entry, std::uint32_t newHash);

// Update viewport
void updateLineStripViewport(LineStripViewport* viewport, std::uint32_t firstLine,
                             std::uint32_t lineCount, std::int32_t offsetY, std::int32_t offsetX);

// Ghost text management
void setGhostText(GhostTextEntry* ghost, std::uint32_t line, std::uint32_t col,
                  const char* text, std::uint32_t len);
void clearGhostText(GhostTextEntry* ghost);

// Diagnostic marker management
void addDiagnosticMarker(DiagnosticMarker* markers, std::size_t maxMarkers, std::size_t* count,
                         std::uint32_t line, std::uint32_t startCol, std::uint32_t endCol, std::uint32_t severity);
void clearDiagnosticMarkers(DiagnosticMarker* markers, std::size_t* count);

// Render cached line strip
void renderLineStripCached(SoftwareRenderSurface* surface, const SoftwareRasterWorkspace* raster,
                           const LineStripCache* cache, const LineStripViewport* viewport,
                           const LineStripCaretState* caret, const GhostTextEntry* ghost,
                           const DiagnosticMarker* diagnostics, std::size_t diagnosticCount);

// Present line strip to editor
void presentLineStrip(HDC targetDc, const SoftwareRenderSurface* surface,
                      const LineStripViewport* viewport);

// Line strip cache enabled check
bool lineStripCacheEnabled();

} // namespace rawrxd::ui
