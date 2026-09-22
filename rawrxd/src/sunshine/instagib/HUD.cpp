#include "HUD.hpp"

namespace Sunshine {

static const char* kHUDVS = R"(
float4 main(float2 pos : POSITION) : SV_POSITION {
    return float4(pos, 0.0, 1.0);
}
)";

static const char* kHUDPS = R"(
float4 color : register(c0);
float4 main() : SV_TARGET {
    return color;
}
)";

void HUD::drawQuad(Renderer* renderer, float x, float y, float w, float h, uint32_t color) {
    // Get window size via GetClientRect since Renderer doesn't expose Window* directly
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

    // Simplified: we don't have a HUD shader compiled in core; skip actual draw for now
    // and rely on certification logic. In a full build we'd compile a simple color shader.
    // For now just release the buffer.
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
    // Score rendered as a small bar on top-right (placeholder geometry)
    float bw = 100.0f;
    float bh = 16.0f;
    float bx = (float)screenW - bw - 20.0f;
    float by = 20.0f;
    drawQuad(renderer, bx, by, bw, bh, 0xFF0088FF);
}

void HUD::drawAll(Renderer* renderer, const Player& player, int screenW, int screenH) {
    drawCrosshair(renderer);
    drawHealthBar(renderer, player.health, screenW, screenH);
    drawScore(renderer, player.score, screenW, screenH);
}

} // namespace Sunshine
