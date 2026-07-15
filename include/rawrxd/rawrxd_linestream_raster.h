#pragma once

// RawrXD Line Stream Raster — Line-by-line streaming rasterization
// Gated by RAWRXD_SOFTWARE_BLIT_RASTER=1.

#include "rawrxd/rawrxd_software_raster.h"

#include <cstddef>
#include <cstdint>
#include <windows.h>

namespace rawrxd::ui
{

// Line stream raster context
struct LineStreamRasterContext
{
    SoftwareRasterWorkspace* raster = nullptr;
    SoftwareRenderSurface* surface = nullptr;
    std::uint32_t lineHeight = 0;
    std::uint32_t baselineOffset = 0;
    COLORREF defaultTextColor = RGB(220, 220, 220);
    COLORREF defaultBackgroundColor = RGB(30, 30, 30);
};

// Line stream batch — multiple lines to render
struct LineStreamBatch
{
    const char** lineTexts = nullptr;
    const std::uint32_t* lineLengths = nullptr;
    const SyntaxColorRun* const* runsPerLine = nullptr;
    const std::uint32_t* runCounts = nullptr;
    std::uint32_t lineCount = 0;
    std::uint32_t startLineIndex = 0;
};

// Initialize line stream raster
bool initializeLineStreamRaster(LineStreamRasterContext* ctx, HDC referenceDc, HFONT fontHandle,
                                 std::uint32_t surfaceWidth, std::uint32_t surfaceHeight);

// Shutdown line stream raster
void shutdownLineStreamRaster(LineStreamRasterContext* ctx);

// Begin line stream frame
void beginLineStreamFrame(LineStreamRasterContext* ctx);

// Render single line to stream
void renderLineToStream(LineStreamRasterContext* ctx, std::uint32_t lineIndex,
                        const char* text, std::uint32_t length,
                        const SyntaxColorRun* runs, std::uint32_t runCount,
                        std::int32_t offsetX, std::int32_t offsetY);

// Render batch of lines
void renderLineBatch(LineStreamRasterContext* ctx, const LineStreamBatch* batch,
                     std::int32_t offsetX, std::int32_t scrollOffsetY);

// End line stream frame and present
void endLineStreamFrame(LineStreamRasterContext* ctx, HDC targetDc);

// Resize line stream surface
bool resizeLineStreamSurface(LineStreamRasterContext* ctx, std::uint32_t newWidth, std::uint32_t newHeight);

// Clear line stream surface
void clearLineStreamSurface(LineStreamRasterContext* ctx, COLORREF background);

// Line stream raster enabled check
bool lineStreamRasterEnabled();

} // namespace rawrxd::ui
