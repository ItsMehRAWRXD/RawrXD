#include <windows.h>
#include <cmath>

#include "sunshine/core/WindowWin32.hpp"
#include "sunshine/core/RendererD3D11.hpp"
#include "sunshine/core/Input.hpp"
#include "sunshine/core/Timer.hpp"
#include "sunshine/core/Camera.hpp"
#include "sunshine/core/Primitives.hpp"
#include "sunshine/instagib/Game.hpp"
#include "sunshine/instagib/HUD.hpp"

namespace Sunshine {

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
struct PS_IN { float4 pos : SV_POSITION; float3 nrm : NORMAL; float2 uv : TEXCOORD0; };
float4 main(PS_IN input) : SV_TARGET {
    float3 L = normalize(float3(0.5, 1.0, 0.3));
    float NdotL = saturate(dot(normalize(input.nrm), L));
    float3 color = lerp(float3(0.1,0.1,0.2), float3(0.6,0.7,0.8), NdotL);
    return float4(color, 1.0);
}
)";

static void logMsg(const char* msg) {
    FILE* f = nullptr; fopen_s(&f, "instagib_log.txt", "a");
    if (f) { fprintf(f, "%s\n", msg); fflush(f); fclose(f); }
}

class InstagibGame {
public:
    bool initialize() {
        FILE* log = nullptr;
        fopen_s(&log, "instagib_log.txt", "w");
        auto lg = [&](const char* msg) { if (log) { fprintf(log, "%s\n", msg); fflush(log); } };

        WindowConfig cfg;
        cfg.width = 1280;
        cfg.height = 720;
        cfg.title = "Sunshine Instagib";
        if (!m_window.initialize(cfg)) { lg("window.init failed"); if (log) fclose(log); return false; }
        lg("window.init ok");

        m_window.setResizeCallback([this](int w, int h) {
            m_renderer.resize(w, h);
            m_camera.setPerspective(60.0f, (float)w / (float)h, 0.1f, 1000.0f);
        });

        if (!m_renderer.initialize(&m_window)) { lg("renderer.init failed"); if (log) fclose(log); return false; }
        lg("renderer.init ok");

        m_input.setRawInput(m_window.getHandle());
        m_input.setMousePosition((float)cfg.width * 0.5f, (float)cfg.height * 0.5f);

        m_camera.setPerspective(60.0f, (float)cfg.width / (float)cfg.height, 0.1f, 1000.0f);

        m_game.init();
        lg("game.init ok");
        // Use player's spawned camera
        m_camera = m_game.player.camera;

        m_groundMesh = makeQuadMesh(&m_renderer, 40.0f, 40.0f);
        m_cubeMesh = makeCubeMesh(&m_renderer, 1.0f);
        lg("meshes ok");

        D3D11_INPUT_ELEMENT_DESC layout[] = {
            {"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
            {"NORMAL",   0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0},
            {"TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT,    0, 24, D3D11_INPUT_PER_VERTEX_DATA, 0},
        };
        if (!m_renderer.compileShader(kVSCode, kPSCode, layout, 3, &m_shader)) { lg("shader compile failed"); if (log) fclose(log); return false; }
        lg("shader compile ok");

        m_cb = m_renderer.createConstantBuffer(sizeof(float) * 16);
        if (!m_cb) { lg("cb create failed"); if (log) fclose(log); return false; }
        lg("cb ok");

        m_running = true;
        m_timer.reset();
        lg("init complete");
        if (log) fclose(log);
        return true;
    }

    void shutdown() {
        m_running = false;
        if (m_cb) { m_cb->Release(); m_cb = nullptr; }
        m_renderer.releaseShader(&m_shader);
        releaseMesh(&m_groundMesh);
        releaseMesh(&m_cubeMesh);
        m_renderer.shutdown();
        m_window.shutdown();
    }

    void run() {
        while (m_running) {
            double dt = m_timer.tick();
            if (dt > 0.25) dt = 0.25;
            update((float)dt);
            render();
        }
    }

private:
    void update(float dt) {
        m_input.update();
        double now = m_timer.now();

        float speed = 5.0f * dt;
        if (m_input.keyDown('W')) m_camera.moveForward(speed);
        if (m_input.keyDown('S')) m_camera.moveForward(-speed);
        if (m_input.keyDown('A')) m_camera.moveRight(-speed);
        if (m_input.keyDown('D')) m_camera.moveRight(speed);

        float sens = 0.15f;
        m_camera.rotateYawPitch(m_input.mouseDeltaX() * sens, m_input.mouseDeltaY() * sens);

        // Keep player camera in sync
        m_game.player.camera = m_camera;

        // Fire on left click
        if (m_input.mouseButtonDown(0)) {
            m_game.playerFire(now);
        }

        // Update game logic (bots, respawns, match time)
        m_game.update(dt, now);

        // If player respawned, sync camera back
        if (!m_game.player.alive) {
            // During death, freeze camera / spectator could go here
        } else {
            m_camera = m_game.player.camera;
        }

        if (m_input.keyDown(VK_ESCAPE) || !m_window.processMessages()) {
            m_running = false;
        }
    }

    void render() {
        m_renderer.beginFrame(0.1f, 0.12f, 0.15f);
        m_renderer.setShader(&m_shader);

        Mat4 proj = m_camera.getProjectionMatrix();
        Mat4 view = m_camera.getViewMatrix();

        // Ground plane
        Mat4 world = Mat4::translate(Vec3(0.0f, 0.0f, 0.0f)) * Mat4::scale(Vec3(1.0f, 1.0f, 1.0f));
        Mat4 mvp = world * view * proj;
        m_renderer.getContext()->UpdateSubresource(m_cb, 0, nullptr, mvp.m, 0, 0);
        m_renderer.setConstantBuffer(0, m_cb);
        drawMesh(&m_renderer, &m_groundMesh);

        // Arena walls (rendered as scaled cubes)
        for (size_t i = 0; i < m_game.arena.boxes.size(); ++i) {
            const AABB& box = m_game.arena.boxes[i];
            Vec3 center = (box.min + box.max) * 0.5f;
            Vec3 dims = box.max - box.min;
            world = Mat4::translate(center) * Mat4::scale(dims);
            mvp = world * view * proj;
            m_renderer.getContext()->UpdateSubresource(m_cb, 0, nullptr, mvp.m, 0, 0);
            m_renderer.setConstantBuffer(0, m_cb);
            drawMesh(&m_renderer, &m_cubeMesh);
        }

        // Bots (rendered as cubes)
        for (auto& bot : m_game.bots) {
            if (!bot.alive) continue;
            Vec3 botPos = bot.pos + Vec3(0.0f, 0.9f, 0.0f);
            world = Mat4::translate(botPos) * Mat4::scale(Vec3(0.6f, 1.8f, 0.6f));
            mvp = world * view * proj;
            m_renderer.getContext()->UpdateSubresource(m_cb, 0, nullptr, mvp.m, 0, 0);
            m_renderer.setConstantBuffer(0, m_cb);
            drawMesh(&m_renderer, &m_cubeMesh);
        }

        // HUD (screen-space overlay)
        int sw = m_window.getWidth();
        int sh = m_window.getHeight();
        m_hud.drawAll(&m_renderer, m_game.player, sw, sh);

        m_renderer.endFrame();
        m_renderer.present();
    }

    Window    m_window;
    Renderer  m_renderer;
    Input     m_input;
    Timer     m_timer;
    Camera    m_camera;
    GameRules m_game;
    HUD       m_hud;
    bool      m_running = false;

    Mesh m_groundMesh = {};
    Mesh m_cubeMesh = {};
    Renderer::Shader m_shader = {};
    ID3D11Buffer* m_cb = nullptr;
};

} // namespace Sunshine

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    Sunshine::InstagibGame game;
    if (!game.initialize()) return 1;
    game.run();
    game.shutdown();
    return 0;
}
