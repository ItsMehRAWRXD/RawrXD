#pragma once

#include "sunshine/core/RendererD3D11.hpp"
#include "neonsiege_core.hpp"
#include <cstdint>

namespace NeonSiege {

class HUD {
public:
    void drawAll(Renderer* renderer, const GameSession& game, int screenW, int screenH);
    void drawMenu(Renderer* renderer, int screenW, int screenH);
    void drawGameOver(Renderer* renderer, int screenW, int screenH, int score);
    void drawVictory(Renderer* renderer, int screenW, int screenH, int score);
    void drawWaveBanner(Renderer* renderer, int screenW, int screenH, int wave);
    void drawBossBar(Renderer* renderer, int screenW, int screenH, float pct);

private:
    void drawQuad(Renderer* renderer, float x, float y, float w, float h, uint32_t color);
    void drawTextApprox(Renderer* renderer, const char* text, float x, float y, float charW, float charH, uint32_t color);
    bool ensureInit(Renderer* renderer);

    bool m_initialized = false;
    Renderer::Shader m_hudShader = {};
    ID3D11Buffer* m_colorCB = nullptr;
};

} // namespace NeonSiege
