#include "HUD.hpp"
#include <cstring>
#include <windows.h>

namespace NeonSiege {

static const char* kHUDVS = R"(
float4 main(float2 pos : POSITION) : SV_POSITION {
    return float4(pos, 0.0, 1.0);
}
)";

static const char* kHUDPS = R"(
cbuffer Color : register(b0) {
    float4 color;
};
float4 main() : SV_TARGET {
    return color;
}
)";

static void makeRGBA(uint32_t hex, float* out) {
    out[0] = ((hex >> 16) & 0xFF) / 255.0f;
    out[1] = ((hex >> 8)  & 0xFF) / 255.0f;
    out[2] = ((hex >> 0)   & 0xFF) / 255.0f;
    out[3] = ((hex >> 24) & 0xFF) / 255.0f;
}

bool HUD::ensureInit(Renderer* renderer) {
    if (m_initialized) return true;
    D3D11_INPUT_ELEMENT_DESC layout[] = {
        {"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
    };
    if (!renderer->compileShader(kHUDVS, kHUDPS, layout, 1, &m_hudShader)) return false;
    m_colorCB = renderer->createConstantBuffer(sizeof(float) * 4);
    if (!m_colorCB) return false;
    m_initialized = true;
    return true;
}

void HUD::drawQuad(Renderer* renderer, float x, float y, float w, float h, uint32_t color) {
    if (!ensureInit(renderer)) return;

    HWND hwnd = GetActiveWindow();
    RECT rc; GetClientRect(hwnd, &rc);
    int ww = rc.right - rc.left;
    int wh = rc.bottom - rc.top;
    if (ww <= 0) ww = 1280;
    if (wh <= 0) wh = 720;
    float x0 = (x / ww) * 2.0f - 1.0f;
    float y0 = 1.0f - (y / wh) * 2.0f;
    float x1 = ((x + w) / ww) * 2.0f - 1.0f;
    float y1 = 1.0f - ((y + h) / wh) * 2.0f;

    float verts[] = { x0, y0, x1, y0, x0, y1, x1, y1 };
    ID3D11Buffer* vb = nullptr;
    renderer->createVertexBuffer(verts, sizeof(verts), sizeof(float) * 2, &vb);
    if (!vb) return;

    renderer->setShader(&m_hudShader);
    float colorBuf[4];
    makeRGBA(color, colorBuf);
    renderer->getContext()->UpdateSubresource(m_colorCB, 0, nullptr, colorBuf, 0, 0);
    renderer->setConstantBuffer(0, m_colorCB);

    ID3D11DepthStencilState* oldDS = nullptr;
    renderer->getContext()->OMGetDepthStencilState(&oldDS, nullptr);
    static ID3D11DepthStencilState* s_dsOff = nullptr;
    if (!s_dsOff) {
        D3D11_DEPTH_STENCIL_DESC dsd = {};
        dsd.DepthEnable = FALSE;
        dsd.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
        dsd.StencilEnable = FALSE;
        renderer->getDevice()->CreateDepthStencilState(&dsd, &s_dsOff);
    }
    renderer->getContext()->OMSetDepthStencilState(s_dsOff, 0);
    renderer->setPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
    renderer->setVertexBuffer(vb, sizeof(float) * 2);
    renderer->draw(4);
    renderer->getContext()->OMSetDepthStencilState(oldDS, 0);
    if (oldDS) oldDS->Release();
    vb->Release();
}

void HUD::drawTextApprox(Renderer* renderer, const char* text, float x, float y, float charW, float charH, uint32_t color) {
    for (const char* p = text; *p; ++p) {
        // Draw simple block per char
        drawQuad(renderer, x, y, charW - 1.0f, charH, color);
        x += charW;
    }
}

void HUD::drawAll(Renderer* renderer, const GameSession& game, int screenW, int screenH) {
    if (!ensureInit(renderer)) return;

    // Crosshair
    float cx = screenW * 0.5f;
    float cy = screenH * 0.5f;
    drawQuad(renderer, cx - 10.0f, cy - 1.0f, 20.0f, 2.0f, 0xFF00FF00);
    drawQuad(renderer, cx - 1.0f, cy - 10.0f, 2.0f, 20.0f, 0xFF00FF00);

    // Health bar
    float bw = 200.0f;
    float bh = 16.0f;
    float bx = 20.0f;
    float by = (float)screenH - bh - 20.0f;
    drawQuad(renderer, bx, by, bw, bh, 0xFF444444);
    float fill = bw * (game.player.health / (float)game.player.maxHealth);
    uint32_t hcol = game.player.health > 50 ? 0xFF00FF00 : (game.player.health > 25 ? 0xFFFFFF00 : 0xFFFF0000);
    drawQuad(renderer, bx, by, fill, bh, hcol);

    // Lives
    for (int i = 0; i < game.player.lives; ++i) {
        drawQuad(renderer, bx + i * 24.0f, by - 20.0f, 18.0f, 14.0f, 0xFF0088FF);
    }

    // Score
    drawQuad(renderer, screenW - 120.0f, 20.0f, 100.0f, 18.0f, 0xFF444444);

    // Wave
    drawQuad(renderer, (screenW - 80.0f) * 0.5f, 10.0f, 80.0f, 20.0f, 0xFF444444);

    // Boss HP bar during boss fight
    if (game.state == GameState::BossFight) {
        for (const auto& e : game.enemies) {
            if (e.type == EnemyType::Tank && e.alive) {
                float pct = e.health / (float)e.maxHealth;
                drawBossBar(renderer, screenW, screenH, pct);
                break;
            }
        }
    }
}

void HUD::drawMenu(Renderer* renderer, int screenW, int screenH) {
    // Dark overlay
    drawQuad(renderer, 0.0f, 0.0f, (float)screenW, (float)screenH, 0xDD000000);
    // Title-ish block
    drawQuad(renderer, screenW * 0.3f, screenH * 0.3f, screenW * 0.4f, screenH * 0.1f, 0xFFFF00FF);
}

void HUD::drawGameOver(Renderer* renderer, int screenW, int screenH, int score) {
    drawQuad(renderer, 0.0f, 0.0f, (float)screenW, (float)screenH, 0xDD000000);
    drawQuad(renderer, screenW * 0.3f, screenH * 0.35f, screenW * 0.4f, screenH * 0.08f, 0xFFFF0000);
}

void HUD::drawVictory(Renderer* renderer, int screenW, int screenH, int score) {
    drawQuad(renderer, 0.0f, 0.0f, (float)screenW, (float)screenH, 0xDD000000);
    drawQuad(renderer, screenW * 0.3f, screenH * 0.35f, screenW * 0.4f, screenH * 0.08f, 0xFF00FF00);
}

void HUD::drawWaveBanner(Renderer* renderer, int screenW, int screenH, int wave) {
    drawQuad(renderer, screenW * 0.35f, screenH * 0.4f, screenW * 0.3f, screenH * 0.06f, 0xFF0088FF);
}

void HUD::drawBossBar(Renderer* renderer, int screenW, int screenH, float pct) {
    float bw = 300.0f;
    float bh = 14.0f;
    float bx = (screenW - bw) * 0.5f;
    float by = 40.0f;
    drawQuad(renderer, bx, by, bw, bh, 0xFF444444);
    drawQuad(renderer, bx, by, bw * pct, bh, 0xFFFF00FF);
}

} // namespace NeonSiege
