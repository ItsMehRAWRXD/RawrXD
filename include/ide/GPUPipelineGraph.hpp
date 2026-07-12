#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

namespace Sovereign {
namespace IDE {

/**
 * @brief GPU dispatch information
 */
struct GPUDispatch {
    uint32_t pipelineID;
    std::string pipelineName;
    uint32_t workgroupsX;
    uint32_t workgroupsY;
    uint32_t workgroupsZ;
    uint64_t durationNs;
    uint64_t timestamp;
};

/**
 * @brief Sovereign GPU Pipeline Graph
 * 
 * Shows Vulkan pipelines as nodes:
 * - Pipelines as nodes
 * - Dispatches as edges
 * - Duration as edge thickness
 * - Workgroup sizes as labels
 * - Beaconism events animate updates
 */
class GPUPipelineGraph {
public:
    bool Create(HWND parent);
    void Destroy();
    
    void Update(const std::vector<GPUDispatch>& dispatches);
    void AddDispatch(const GPUDispatch& dispatch);
    void Clear();
    
    void Render(HDC hdc);
    void OnPaint();
    
    HWND GetHWND() const { return m_hwnd; }
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    HWND m_hwnd = nullptr;
    HFONT m_hFont = nullptr;
    std::vector<GPUDispatch> m_dispatches;
    
    static constexpr int MAX_DISPATCHES = 50;
    static constexpr int NODE_WIDTH = 120;
    static constexpr int NODE_HEIGHT = 40;
    
    void DrawNode(HDC hdc, const GPUDispatch& dispatch, int x, int y);
    void DrawEdge(HDC hdc, int x1, int y1, int x2, int y2, uint64_t duration);
    void DrawLegend(HDC hdc, int x, int y);
    COLORREF GetPipelineColor(uint32_t pipelineID);
    int GetLineThickness(uint64_t durationNs);
};

} // namespace IDE
} // namespace Sovereign
