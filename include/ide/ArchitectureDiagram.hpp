#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>

namespace Sovereign {
namespace IDE {

/**
 * @brief Layer information for architecture diagram
 */
struct LayerInfo {
    uint32_t layerIndex;
    uint32_t hiddenSize;
    uint32_t ffnSize;
    uint32_t attentionHeads;
    uint32_t numExperts;
    uint32_t kvSegmentStart;
    uint32_t kvSegmentCount;
    bool quantized;
};

/**
 * @brief Sovereign Layer-by-Layer Architecture Diagram Renderer
 * 
 * Visualizes model architecture with:
 * - Layer blocks with FFN size as thickness
 * - Attention heads as subdivisions
 * - Expert count as color intensity
 * - KV segment annotations
 * - Quantization shading
 */
class ArchitectureDiagram {
public:
    bool Create(HWND parent);
    void Destroy();
    
    void Load(const std::vector<LayerInfo>& layers);
    void Clear();
    
    void Render(HDC hdc);
    void OnPaint();
    
    HWND GetHWND() const { return m_hwnd; }
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    HWND m_hwnd = nullptr;
    HFONT m_hFont = nullptr;
    std::vector<LayerInfo> m_layers;
    
    static constexpr int LAYER_SPACING = 30;
    static constexpr int MARGIN_LEFT = 10;
    static constexpr int MARGIN_RIGHT = 10;
    static constexpr int MARGIN_TOP = 10;
    
    void DrawLayer(HDC hdc, const LayerInfo& layer, int x, int y, int width);
    void DrawAttentionHeads(HDC hdc, const LayerInfo& layer, int x, int y, int width, int height);
    COLORREF GetLayerColor(const LayerInfo& layer);
    COLORREF GetQuantizationColor(bool quantized);
};

} // namespace IDE
} // namespace Sovereign
