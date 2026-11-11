#pragma once

// RawrXD Workspace Matrix — Workspace coordinate transformation and layout
// Gated by RAWRXD_SOFTWARE_BLIT_RASTER=1.

#include <cstddef>
#include <cstdint>
#include <windows.h>

namespace rawrxd::ui
{

// Workspace coordinate point
struct WorkspacePoint
{
    float x = 0.0f;
    float y = 0.0f;
};

// Workspace size
struct WorkspaceSize
{
    float width = 0.0f;
    float height = 0.0f;
};

// Workspace rectangle
struct WorkspaceRect
{
    float left = 0.0f;
    float top = 0.0f;
    float right = 0.0f;
    float bottom = 0.0f;

    float width() const { return right - left; }
    float height() const { return bottom - top; }
};

// Viewport transform — maps workspace to screen
struct ViewportTransform
{
    float scaleX = 1.0f;
    float scaleY = 1.0f;
    float offsetX = 0.0f;
    float offsetY = 0.0f;
    float rotation = 0.0f; // radians
};

// Workspace matrix — 2D transformation matrix
struct WorkspaceMatrix
{
    float m[6] = {1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f}; // a, b, c, d, e, f

    // | a  c  e |
    // | b  d  f |
    // | 0  0  1 |

    static WorkspaceMatrix identity();
    static WorkspaceMatrix translation(float x, float y);
    static WorkspaceMatrix scaling(float sx, float sy);
    static WorkspaceMatrix rotation(float radians);
    static WorkspaceMatrix fromViewport(const ViewportTransform& vp);
};

// Workspace matrix operations
WorkspaceMatrix multiply(const WorkspaceMatrix& a, const WorkspaceMatrix& b);
WorkspaceMatrix invert(const WorkspaceMatrix& m);

// Transform point
WorkspacePoint transformPoint(const WorkspaceMatrix& m, const WorkspacePoint& p);

// Transform rect
WorkspaceRect transformRect(const WorkspaceMatrix& m, const WorkspaceRect& r);

// Workspace layout cell
struct WorkspaceCell
{
    std::uint32_t row = 0;
    std::uint32_t col = 0;
    std::uint32_t rowSpan = 1;
    std::uint32_t colSpan = 1;
    WorkspaceRect bounds;
};

// Workspace grid
struct WorkspaceGrid
{
    float* rowHeights = nullptr;
    float* colWidths = nullptr;
    std::uint32_t rowCount = 0;
    std::uint32_t colCount = 0;
    float gapX = 0.0f;
    float gapY = 0.0f;
};

// Initialize workspace grid
bool initializeWorkspaceGrid(WorkspaceGrid* grid, std::uint32_t rows, std::uint32_t cols);

// Shutdown workspace grid
void shutdownWorkspaceGrid(WorkspaceGrid* grid);

// Calculate cell bounds
WorkspaceRect calculateCellBounds(const WorkspaceGrid* grid, std::uint32_t row, std::uint32_t col);

// Convert screen to workspace coordinates
WorkspacePoint screenToWorkspace(const ViewportTransform* vp, int screenX, int screenY);

// Convert workspace to screen coordinates
void workspaceToScreen(const ViewportTransform* vp, const WorkspacePoint& wp, int* outScreenX, int* outScreenY);

// Fit rect to viewport with aspect preservation
ViewportTransform fitRectToViewport(const WorkspaceRect& content, const WorkspaceSize& viewport,
                                       bool preserveAspect = true);

// Workspace matrix enabled check
bool workspaceMatrixEnabled();

} // namespace rawrxd::ui
