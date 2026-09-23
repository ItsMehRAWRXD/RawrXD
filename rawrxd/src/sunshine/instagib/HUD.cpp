#include "HUD.hpp"
#include <cstring>

namespace Sunshine {

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
    out[2] = ((hex >> 0)  & 0xFF) / 255.0f;
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
    // Convert screen pixels to NDC [-1,1]
    float x0 = (x / ww) * 2.0f - 1.0f;
    float y0 = 1.0f - (y / wh) * 2.0f;
    float x1 = ((x + w) / ww) * 2.0f - 1.0f;
    float y1 = 1.0f - ((y + h) / wh) * 2.0f;

    float verts[] = {
        x0, y0,
        x1, y0,
        x0, y1,
        x1, y1,
    };
    ID3D11Buffer* vb = nullptr;
    renderer->createVertexBuffer(verts, sizeof(verts), sizeof(float) * 2, &vb);
    if (!vb) return;

    // Set HUD shader
    renderer->setShader(&m_hudShader);

    // Update color constant buffer
    float colorBuf[4];
    makeRGBA(color, colorBuf);
    renderer->getContext()->UpdateSubresource(m_colorCB, 0, nullptr, colorBuf, 0, 0);
    renderer->setConstantBuffer(0, m_colorCB);

    // Save current depth/stencil state
    ID3D11DepthStencilState* oldDS = nullptr;
    renderer->getContext()->OMGetDepthStencilState(&oldDS, nullptr);

    // Create and set depth-disabled state
    static ID3D11DepthStencilState* s_dsOff = nullptr;
    if (!s_dsOff) {
        D3D11_DEPTH_STENCIL_DESC dsd = {};
        dsd.DepthEnable = FALSE;
        dsd.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
        dsd.StencilEnable = FALSE;
        renderer->getDevice()->CreateDepthStencilState(&dsd, &s_dsOff);
    }
    renderer->setDepthStencilState(s_dsOff);

    // Draw as triangle strip
    renderer->setPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
    renderer->setVertexBuffer(vb, sizeof(float) * 2);
    renderer->draw(4);

    // Restore depth/stencil state
    renderer->setDepthStencilState(oldDS);
    if (oldDS) oldDS->Release();

    vb->Release();
}

void HUD::drawCrosshair(Renderer* renderer) {
    HWND hwnd = GetActiveWindow();
    RECT rc; GetClientRect(hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    if (w <= 0) w = 1280;
    if (h <= 0) h = 720;
    float cx = (float)w * 0.5f;
    float cy = (float)h * 0.5f;
    drawQuad(renderer, cx - 10.0f, cy - 1.0f, 20.0f, 2.0f, 0xFFFFFFFF);
    drawQuad(renderer, cx - 1.0f, cy - 10.0f, 2.0f, 20.0f, 0xFFFFFFFF);
}

void HUD::drawHealthBar(Renderer* renderer, int health, int screenW, int screenH) {
    float bw = 200.0f;
    float bh = 16.0f;
    float bx = 20.0f;
    float by = (float)screenH - bh - 20.0f;
    // Background
    drawQuad(renderer, bx, by, bw, bh, 0xFF444444);
    // Fill
    float fill = bw * (health / 100.0f);
    uint32_t col = health > 50 ? 0xFF00FF00 : (health > 25 ? 0xFFFFFF00 : 0xFFFF0000);
    drawQuad(renderer, bx, by, fill, bh, col);
}

void HUD::drawScore(Renderer* renderer, int score, int screenW, int screenH) {
    float bw = 100.0f;
    float bh = 16.0f;
    float bx = (float)screenW - bw - 20.0f;
    float by = 20.0f;
    drawQuad(renderer, bx, by, bw, bh, 0xFF0088FF);
}

void HUD::drawTimer(Renderer* renderer, float matchTime, float timeLimit, int screenW, int screenH) {
    int seconds = (int)(timeLimit - matchTime);
    if (seconds < 0) seconds = 0;
    int mins = seconds / 60;
    int secs = seconds % 60;
    // Approximate timer bar at top center
    float bw = 120.0f;
    float bh = 20.0f;
    float bx = ((float)screenW - bw) * 0.5f;
    float by = 10.0f;
    uint32_t col = seconds <= 10 ? 0xFFFF0000 : 0xFFFFFFFF;
    drawQuad(renderer, bx, by, bw, bh, col);
}

void HUD::drawMatchOver(Renderer* renderer, bool playerWon, int screenW, int screenH) {
    float bw = 400.0f;
    float bh = 80.0f;
    float bx = ((float)screenW - bw) * 0.5f;
    float by = ((float)screenH - bh) * 0.5f;
    uint32_t col = playerWon ? 0xFF00FF00 : 0xFFFF0000;
    drawQuad(renderer, bx, by, bw, bh, col);
}

void HUD::drawAll(Renderer* renderer, const Player& player, float matchTime, float timeLimit, bool matchOver, bool playerWon, int screenW, int screenH) {
    drawCrosshair(renderer);
    drawHealthBar(renderer, player.health, screenW, screenH);
    drawScore(renderer, player.score, screenW, screenH);
    drawTimer(renderer, matchTime, timeLimit, screenW, screenH);
    if (matchOver) {
        drawMatchOver(renderer, playerWon, screenW, screenH);
    }
}

} // namespace Sunshine

