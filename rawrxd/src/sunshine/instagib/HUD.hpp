#pragma once

#include "../core/RendererD3D11.hpp"
#include "Player.hpp"
#include "Game.hpp"
#include <cstdint>

namespace Sunshine {

class HUD {
public:
    void drawCrosshair(Renderer* renderer);
    void drawHealthBar(Renderer* renderer, int health, int screenW, int screenH);
    void drawScore(Renderer* renderer, int score, int screenW, int screenH);
    void drawAll(Renderer* renderer, const Player& player, int screenW, int screenH);

private:
    void drawQuad(Renderer* renderer, float x, float y, float w, float h, uint32_t color);
    bool ensureInit(Renderer* renderer);

    bool m_initialized = false;
    Renderer::Shader m_hudShader = {};
    ID3D11Buffer* m_colorCB = nullptr;
};

} // namespace Sunshine
