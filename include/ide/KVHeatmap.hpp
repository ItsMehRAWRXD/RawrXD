#pragma once
#include <windows.h>
#include <vector>
#include "sovereign/Beaconism.hpp"

namespace Sovereign {
namespace IDE {

/**
 * @brief Timeline point for KV heatmap
 */
struct KVTimePoint {
    int tier;           // 0=hot, 1=warm, 2=cold
    int pressure;       // 0-255 pressure level
    uint64_t timestamp;
};

/**
 * @brief Sovereign KV Heatmap Timeline (Animated)
 * 
 * Shows KV tier transitions over time:
 * - X axis = time
 * - Y axis = tier (hot/warm/cold)
 * - Color = segment pressure
 * - Beaconism events animate transitions
 */
class KVHeatmap {
public:
    bool Create(HWND parent);
    void Destroy();
    
    void OnBeacon(const Beacon& beacon);
    void Update();
    void Render(HDC hdc);
    void OnPaint();
    
    HWND GetHWND() const { return m_hwnd; }
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    HWND m_hwnd = nullptr;
    std::vector<KVTimePoint> m_timeline;
    
    static constexpr int MAX_POINTS = 500;
    static constexpr int TIER_HEIGHT = 40;
    
    COLORREF GetTierColor(int tier, int pressure);
    void DrawTimeline(HDC hdc, int width, int height);
    void DrawLegend(HDC hdc, int x, int y);
};

} // namespace IDE
} // namespace Sovereign
