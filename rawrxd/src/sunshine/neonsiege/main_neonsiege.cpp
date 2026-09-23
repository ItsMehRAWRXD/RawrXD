#include <windows.h>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

#include "sunshine/core/WindowWin32.hpp"
#include "sunshine/core/RendererD3D11.hpp"
#include "sunshine/core/Input.hpp"
#include "sunshine/core/Timer.hpp"
#include "sunshine/core/Camera.hpp"
#include "sunshine/core/Primitives.hpp"
#include "neonsiege_core.hpp"
#include "HUD.hpp"

using namespace Sunshine;
using namespace NeonSiege;

// Shaders with per-object tint support
static const char* kVSCode = R"(
cbuffer Transform : register(b0) {
    float4x4 worldViewProj;
};
struct VS_IN { float3 pos : POSITION; float3 nrm : NORMAL; float2 uv : TEXCOORD0; };
struct PS_IN { float4 pos : SV_POSITION; float3 nrm : NORMAL; float2 uv : TEXCOORD0; };
PS_IN main(VS_IN input) {
    PS_IN output;
    output.pos = mul(float4(input.pos, 1.0), worldViewProj);
    output.nrm = input.nrm;
    output.uv = input.uv;
    return output;
}
)";

static const char* kPSCode = R"(
cbuffer Tint : register(b1) {
    float4 tintColor;
};
struct PS_IN { float4 pos : SV_POSITION; float3 nrm : NORMAL; float2 uv : TEXCOORD0; };
float4 main(PS_IN input) : SV_TARGET {
    float3 L = normalize(float3(0.5, 1.0, 0.3));
    float NdotL = saturate(dot(normalize(input.nrm), L));
    float3 base = lerp(float3(0.05,0.05,0.08), float3(0.6,0.7,0.8), NdotL);
    float3 color = base * tintColor.rgb;
    return float4(color, 1.0);
}
)";

class NeonSiegeApp {
public:
    bool initialize() {
        WindowConfig cfg;
        cfg.width = 1280;
        cfg.height = 720;
        cfg.title = "Neon Siege";
        if (!m_window.initialize(cfg)) return false;

        m_window.setResizeCallback([this](int w, int h) {
            m_renderer.resize(w, h);
            m_camera.setPerspective(60.0f, (float)w / (float)h, 0.1f, 1000.0f);
        });

        if (!m_renderer.initialize(&m_window)) return false;
        m_input.setRawInput(m_window.getHandle());
        m_input.setMousePosition((float)cfg.width * 0.5f, (float)cfg.height * 0.5f);
        m_camera.setPerspective(60.0f, (float)cfg.width / (float)cfg.height, 0.1f, 1000.0f);

        m_game.init(false);

        m_groundMesh = makeQuadMesh(&m_renderer, 60.0f, 60.0f);
        m_cubeMesh = makeCubeMesh(&m_renderer, 1.0f);
        m_smallCube = makeCubeMesh(&m_renderer, 0.3f);

        D3D11_INPUT_ELEMENT_DESC layout[] = {
            {"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
            {"NORMAL",   0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0},
            {"TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT,    0, 24, D3D11_INPUT_PER_VERTEX_DATA, 0},
        };
        if (!m_renderer.compileShader(kVSCode, kPSCode, layout, 3, &m_shader)) return false;

        m_cb = m_renderer.createConstantBuffer(sizeof(float) * 16);
        if (!m_cb) return false;

        m_tintCB = m_renderer.createConstantBuffer(sizeof(float) * 4);
        if (!m_tintCB) return false;

        m_running = true;
        m_timer.reset();
        return true;
    }

    void shutdown() {
        m_running = false;
        if (m_cb) { m_cb->Release(); m_cb = nullptr; }
        if (m_tintCB) { m_tintCB->Release(); m_tintCB = nullptr; }
        m_renderer.releaseShader(&m_shader);
        releaseMesh(&m_groundMesh);
        releaseMesh(&m_cubeMesh);
        releaseMesh(&m_smallCube);
        m_renderer.shutdown();
        m_window.shutdown();
    }

    void run() {
        // Capture config
        uint32_t captureAfterMs = 0;
        bool captureExit = false;
        wchar_t capturePath[512] = L"";
        {
            const char* ms = getenv("NEONSIEGE_CAPTURE_AFTER_MS");
            if (ms) captureAfterMs = (uint32_t)atoi(ms);
            const char* exitStr = getenv("NEONSIEGE_CAPTURE_EXIT");
            if (exitStr && atoi(exitStr)) captureExit = true;
            const char* pathStr = getenv("NEONSIEGE_CAPTURE_PATH");
            if (pathStr) {
                size_t n = strlen(pathStr);
                if (n < sizeof(capturePath)/sizeof(capturePath[0])) {
                    for (size_t i = 0; i < n; ++i) capturePath[i] = (wchar_t)pathStr[i];
                    capturePath[n] = L'\0';
                }
            }
        }
        bool captured = false;
        uint64_t renderStart = 0;
        bool firstFrame = true;

        while (m_running) {
            double dt = m_timer.tick();
            if (dt > 0.25) dt = 0.25;
            update((float)dt);
            render();

            // Auto-capture at milestone events
            if (!captured && captureAfterMs > 0 && wcslen(capturePath) > 0) {
                uint64_t nowTick = GetTickCount64();
                if (firstFrame) { renderStart = nowTick; firstFrame = false; }
                if ((nowTick - renderStart) >= captureAfterMs) {
                    m_renderer.captureFrame(capturePath);
                    captured = true;
                    if (captureExit) m_running = false;
                }
            }
        }
    }

private:
    void update(float dt) {
        m_input.update();
        double now = m_timer.now();

        // Global inputs
        if (m_input.keyDown(VK_ESCAPE) || !m_window.processMessages()) {
            m_running = false;
            return;
        }

        // Menu state
        if (m_game.state == GameState::Menu) {
            if (m_input.keyPressed(VK_SPACE) || m_input.mouseButtonDown(0)) {
                m_game.startGame();
                m_camera = m_game.player.camera;
            }
            return;
        }

        // Game over / victory restart
        if (m_game.state == GameState::GameOver || m_game.state == GameState::Victory) {
            if (m_input.keyPressed('R')) {
                m_game.restartGame();
                m_camera = m_game.player.camera;
            }
            return;
        }

        // Playing / boss / wave complete
        if (m_game.state == GameState::Playing || m_game.state == GameState::BossFight || m_game.state == GameState::WaveComplete) {
            float speed = 6.0f * dt * m_game.player.moveSpeedMultiplier;
            if (m_input.keyDown('W')) m_camera.moveForward(speed);
            if (m_input.keyDown('S')) m_camera.moveForward(-speed);
            if (m_input.keyDown('A')) m_camera.moveRight(-speed);
            if (m_input.keyDown('D')) m_camera.moveRight(speed);

            float sens = 0.15f;
            m_camera.rotateYawPitch(m_input.mouseDeltaX() * sens, m_input.mouseDeltaY() * sens);

            m_game.player.camera = m_camera;

            if (m_input.mouseButtonDown(0)) {
                m_game.playerFire(now);
            }

            m_game.update(dt, now);

            if (m_game.player.alive) {
                m_camera = m_game.player.camera;
            }
        }
    }

    void render() {
        // Dark neon background
        m_renderer.beginFrame(0.02f, 0.02f, 0.04f);
        m_renderer.setShader(&m_shader);

        Mat4 proj = m_camera.getProjectionMatrix();
        Mat4 view = m_camera.getViewMatrix();

        // Ground plane (dark grid-like)
        setTint(0.15f, 0.15f, 0.2f);
        Mat4 world = Mat4::translate(Vec3(0.0f, 0.0f, 0.0f)) * Mat4::rotateX(-90.0f) * Mat4::scale(Vec3(1.0f, 1.0f, 1.0f));
        setTransform(world * view * proj);
        drawMesh(&m_renderer, &m_groundMesh);

        // Arena walls
        setTint(0.4f, 0.4f, 0.5f);
        for (const auto& box : m_game.arenaBoxes) {
            Vec3 center = (box.min + box.max) * 0.5f;
            Vec3 dims = box.max - box.min;
            Mat4 w = Mat4::translate(center) * Mat4::scale(dims);
            setTransform(w * view * proj);
            drawMesh(&m_renderer, &m_cubeMesh);
        }

        // Enemies
        for (const auto& e : m_game.enemies) {
            if (!e.alive) continue;
            float r = ((e.color >> 16) & 0xFF) / 255.0f;
            float g = ((e.color >> 8)  & 0xFF) / 255.0f;
            float b = ((e.color >> 0)   & 0xFF) / 255.0f;
            setTint(r, g, b);

            Vec3 pos = e.pos + Vec3(0.0f, 0.9f, 0.0f);
            float scale = (e.type == EnemyType::Tank) ? 1.2f : 0.7f;
            Mat4 w = Mat4::translate(pos) * Mat4::scale(Vec3(0.6f, 1.8f, 0.6f) * scale);
            setTransform(w * view * proj);
            drawMesh(&m_renderer, &m_cubeMesh);
        }

        // Pickups
        for (auto& p : m_game.pickups) {
            if (!p.active) continue;
            float r = ((p.color >> 16) & 0xFF) / 255.0f;
            float g = ((p.color >> 8)  & 0xFF) / 255.0f;
            float b = ((p.color >> 0)   & 0xFF) / 255.0f;
            setTint(r, g, b);
            Mat4 w = Mat4::translate(p.pos + Vec3(0.0f, 0.5f, 0.0f)) * Mat4::scale(Vec3(0.4f, 0.4f, 0.4f));
            setTransform(w * view * proj);
            drawMesh(&m_renderer, &m_smallCube);
        }

        // HUD
        int sw = m_window.getWidth();
        int sh = m_window.getHeight();

        if (m_game.state == GameState::Menu) {
            m_hud.drawMenu(&m_renderer, sw, sh);
        } else if (m_game.state == GameState::GameOver) {
            m_hud.drawAll(&m_renderer, m_game, sw, sh);
            m_hud.drawGameOver(&m_renderer, sw, sh, m_game.score);
        } else if (m_game.state == GameState::Victory) {
            m_hud.drawAll(&m_renderer, m_game, sw, sh);
            m_hud.drawVictory(&m_renderer, sw, sh, m_game.score);
        } else if (m_game.state == GameState::WaveComplete) {
            m_hud.drawAll(&m_renderer, m_game, sw, sh);
            m_hud.drawWaveBanner(&m_renderer, sw, sh, m_game.wave + 1);
        } else {
            m_hud.drawAll(&m_renderer, m_game, sw, sh);
        }

        m_renderer.endFrame();
        m_renderer.present();
    }

    void setTransform(const Mat4& mvp) {
        m_renderer.getContext()->UpdateSubresource(m_cb, 0, nullptr, mvp.m, 0, 0);
        m_renderer.setConstantBuffer(0, m_cb);
    }

    void setTint(float r, float g, float b) {
        float tint[4] = { r, g, b, 1.0f };
        m_renderer.getContext()->UpdateSubresource(m_tintCB, 0, nullptr, tint, 0, 0);
        m_renderer.setConstantBuffer(1, m_tintCB);
    }

    Window    m_window;
    Renderer  m_renderer;
    Input     m_input;
    Timer     m_timer;
    Camera    m_camera;
    GameSession m_game;
    HUD       m_hud;
    bool      m_running = false;
    Mesh      m_groundMesh = {};
    Mesh      m_cubeMesh = {};
    Mesh      m_smallCube = {};
    Renderer::Shader m_shader = {};
    ID3D11Buffer* m_cb = nullptr;
    ID3D11Buffer* m_tintCB = nullptr;
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    (void)hInstance;
    srand((unsigned)GetTickCount64());
    NeonSiegeApp app;
    if (!app.initialize()) return 1;
    app.run();
    app.shutdown();
    return 0;
}
