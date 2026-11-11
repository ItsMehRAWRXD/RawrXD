#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include "sovereign/Beaconism.hpp"

namespace Sovereign {
namespace IDE {

/**
 * @brief MoE routing event
 */
struct MoEEvent {
    uint8_t expertIndex;
    uint8_t activationLevel;
    uint64_t timestamp;
};

/**
 * @brief Sovereign MoE Routing Timeline (Animated)
 * 
 * Shows expert activation over time:
 * - X axis = time (tokens)
 * - Y axis = expert index
 * - Color = activation intensity
 * - Beaconism events animate routing
 */
class MoETimeline {
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
    std::vector<MoEEvent> m_events;
    
    static constexpr int MAX_EVENTS = 1000;
    static constexpr int EXPERT_COUNT = 64;
    static constexpr int CELL_HEIGHT = 3;
    
    COLORREF GetActivationColor(uint8_t level);
    void DrawGrid(HDC hdc, int width, int height);
    void DrawEvents(HDC hdc, int width, int height);
    void DrawLegend(HDC hdc, int x, int y);
};

} // namespace IDE
} // namespace Sovereign
