#include <windows.h>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <vector>
#include <string>

#include "sunshine/core/WindowWin32.hpp"
#include "sunshine/core/RendererD3D11.hpp"
#include "sunshine/core/Input.hpp"
#include "sunshine/core/Timer.hpp"
#include "sunshine/core/Camera.hpp"
#include "sunshine/core/Primitives.hpp"
#include "sunshine/core/Sky.hpp"
#include "neonsiege_core.hpp"
#include "HUD.hpp"

using namespace Sunshine;
using namespace NeonSiege;

// Shaders with per-object tint support.
//
// RAWRXD_SUNSHINE_GROUND_001
// The transform constant buffer carries TWO matrices, not one. Previously it held
// only worldViewProj, which forced the vertex shader to emit the OBJECT-space
// normal (`output.nrm = input.nrm`). The ground is rotated rotateX(-90 deg), so
// its world normal is +Y while the shader still saw +Z, and lighting was evaluated
// against the wrong axis. Measured effect on the ground:
//     NdotL = dot((0,0,1), normalize(0.5,1,0.3)) = 0.2571   (correct value: 0.8571)
//     base*tint = (0.0287,0.0326,0.0530) ~= RGB(7,8,13)
// against a clear colour of RGB(5,5,10) -- drawn, but indistinguishable, which
// is what read as a fully black scene. The normal is now transformed by world.
//
// The ground flag rides in tintColor.a so that adding a material channel does not
// require a second constant buffer.
static const char* kVSCode = R"(
cbuffer Transform : register(b0) {
    // RAWRXD_SUNSHINE_MATRIX_LAYOUT_001
    // Mat4::m is float[4][4] filled ROW-major, but HLSL's float4x4 defaults to
    // COLUMN-major, so mul() consumed a transposed matrix. Symptom: every object
    // rendered as a diagonal wedge instead of an axis-aligned box or plane --
    // the scene was visibly sheared rather than merely mis-scaled. row_major
    // makes the shader read the bytes in the order they are written.
    row_major float4x4 world;
    row_major float4x4 worldViewProj;
};
struct VS_IN { float3 pos : POSITION; float3 nrm : NORMAL; float2 uv : TEXCOORD0; };
struct PS_IN { float4 pos : SV_POSITION; float3 nrm : NORMAL; float2 uv : TEXCOORD0; };
PS_IN main(VS_IN input) {
    PS_IN output;
    output.pos = mul(float4(input.pos, 1.0), worldViewProj);
    // World-space normal. (float3x3)world is the correct transform for the
    // rigid+uniform-scale transforms used here; a full inverse-transpose is
    // unnecessary and would cost a per-frame inverse.
    output.nrm = normalize(mul((float3x3)world, input.nrm));
    output.uv = input.uv;
    return output;
}
)";

static const char* kPSCode = R"(
cbuffer Tint : register(b1) {
    float4 tintColor;   // rgb = albedo tint, a = ground-grid flag
};
struct PS_IN { float4 pos : SV_POSITION; float3 nrm : NORMAL; float2 uv : TEXCOORD0; };
float4 main(PS_IN input) : SV_TARGET {
    float3 L = normalize(float3(0.45, 0.85, 0.30));
    float3 N = normalize(input.nrm);
    float NdotL = saturate(dot(N, L));

    // Soft two-term wrap so surfaces facing away from the key light are still
    // readable instead of collapsing to the ambient floor.
    float wrap = saturate((dot(N, L) + 0.35) / 1.35);
    float3 ambient = float3(0.13, 0.15, 0.22);
    float3 key     = float3(0.78, 0.84, 0.95);
    float3 base    = ambient + key * wrap;
    float3 color   = base * tintColor.rgb;

    // Procedural ground grid: a 24x24 lattice with an anti-aliased line width,
    // plus a radial fade so the plane dissolves into the horizon rather than
    // ending on a hard visible edge.
    //
    // SM4 CONSTRAINTS, both learned the hard way (D3DCompile against ps_4_0):
    //   * `line` is a RESERVED HLSL word (geometry-shader primitive type), so
    //     the obvious variable name `float line = ...` is a hard X3000.
    //   * `mix()` does not exist in Shader Model 4; it is `lerp()`.
    if (tintColor.a > 0.5) {
        float2 gv = abs(frac(input.uv * 24.0) - 0.5);
        float gridLine = 1.0 - smoothstep(0.0, 0.055, min(gv.x, gv.y));
        float r = length(input.uv - 0.5) * 2.0;
        float fade = 1.0 - smoothstep(0.35, 1.0, r);
        color += float3(0.16, 0.62, 0.95) * gridLine * fade * 0.85;
        color *= lerp(1.0, 0.55, smoothstep(0.55, 1.0, r));
    }
    return float4(color, 1.0);
}
)";

// RAWRXD_SUNSHINE_INIT_TRACE_001
//
// This is a GUI-subsystem app (WinMain), so it has no console attached: stdout
// and stderr go nowhere. Every initialize() failure was therefore silent, and a
// headless launch just exited with code 1 and no evidence whatsoever -- an
// observation that looks identical to "the app works but renders black".
// The trace writes to a file so a failing launch is diagnosable.
//
// Path comes from NEONSIEGE_TRACE_PATH; otherwise it sits beside the capture.
static void nsTrace(const char* fmt, ...) {
    char path[512] = {};
    if (const char* p = getenv("NEONSIEGE_TRACE_PATH")) {
        strncpy_s(path, p, _TRUNCATE);
    } else {
        const char* cp = getenv("NEONSIEGE_CAPTURE_PATH");
        if (cp) {
            strncpy_s(path, cp, _TRUNCATE);
            char* dot = strrchr(path, '.');
            if (dot) *dot = '\0';
            strncat_s(path, ".initlog", _TRUNCATE);
        } else {
            strncpy_s(path, "neonsiege_init.log", _TRUNCATE);
        }
    }
    FILE* f = nullptr;
    if (fopen_s(&f, path, "a") != 0 || !f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

class NeonSiegeApp {
public:
    bool initialize() {
        WindowConfig cfg;
        cfg.width = 1280;
        cfg.height = 720;
        cfg.title = "Neon Siege";
        nsTrace("STEP window_initialize");
        if (!m_window.initialize(cfg)) { nsTrace("FAIL window_initialize"); return false; }
        nsTrace("OK window_initialize");

        m_window.setResizeCallback([this](int w, int h) {
            m_renderer.resize(w, h);
            m_camera.setPerspective(60.0f, (float)w / (float)h, 0.1f, 1000.0f);
        });

        nsTrace("STEP renderer_initialize");
        if (!m_renderer.initialize(&m_window)) { nsTrace("FAIL renderer_initialize"); return false; }
        nsTrace("OK renderer_initialize");
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
        nsTrace("STEP compile_shader");
        if (!m_renderer.compileShader(kVSCode, kPSCode, layout, 3, &m_shader)) { nsTrace("FAIL compile_shader"); return false; }
        nsTrace("OK compile_shader");

        if (!m_sky.initialize(&m_renderer, SkyParams{})) { nsTrace("FAIL sky_initialize"); return false; }

        m_cb = m_renderer.createConstantBuffer(sizeof(float) * 32);  // world + worldViewProj
        if (!m_cb) { nsTrace("FAIL createConstantBuffer transform"); return false; }

        m_tintCB = m_renderer.createConstantBuffer(sizeof(float) * 4);
        if (!m_tintCB) { nsTrace("FAIL createConstantBuffer tint"); return false; }

        nsTrace("OK initialize_complete");
        m_running = true;
        m_timer.reset();
        return true;
    }

    void shutdown() {
        m_running = false;
        m_sky.shutdown();
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

        // RAWRXD_SUNSHINE_CAPTURE_AUTOSTART_001
        // The app boots into GameState::Menu, whose HUD draws a fullscreen
        // 0xDD (87% opaque) black overlay on top of the whole scene. A capture
        // taken in that state shows a black field and a magenta title block, not
        // the arena -- which reads as "the renderer is broken" when in fact the
        // renderer is fine and the menu is simply covering it.
        // When a capture is configured, skip the menu so the evidence frame is
        // the actual 3D scene.
        if (captureAfterMs > 0 && wcslen(capturePath) > 0 && m_game.state == GameState::Menu) {
            m_game.startGame();
            m_camera = m_game.player.camera;
            nsTrace("CAPTURE_AUTOSTART state -> %d", (int)m_game.state);
        }

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
                    const bool capOk = m_renderer.captureFrame(capturePath);
                    nsTrace("CAPTURE ok=%d", capOk ? 1 : 0);
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
        m_renderer.beginFrame(0.05f, 0.07f, 0.13f);   // dark blue sky, not near-black
        // RAWRXD_SUNSHINE_SKY_002: fullscreen procedural background first, with
        // depth testing disabled so it is not rejected at the far plane.
        m_sky.draw(&m_renderer, m_timer.now(), -1);
        m_renderer.setShader(&m_shader);

        Mat4 proj = m_camera.getProjectionMatrix();
        Mat4 view = m_camera.getViewMatrix();

        // RAWRXD_SUNSHINE_GROUND_001: one-shot scene dump. The HUD draws while
        // no mesh geometry appears at all, so the pipeline is proven good and
        // the question is where the mesh transform puts the ground. Printing the
        // camera basis and the composed MVP answers that without a guess.
        static bool dumped = false;
        if (!dumped) {
            dumped = true;
            const Vec3 fwd = m_camera.getForward();
            const Vec3 eye = m_camera.getPosition();
            nsTrace("SCENE state=%d eye=(%.3f,%.3f,%.3f) fwd=(%.3f,%.3f,%.3f)",
                    (int)m_game.state, eye.x, eye.y, eye.z, fwd.x, fwd.y, fwd.z);
            nsTrace("MESHES ground_vb=%p ground_verts=%zu cube_vb=%p arena_boxes=%zu",
                    (void*)m_groundMesh.vertexBuffer, m_groundMesh.vertexCount,
                    (void*)m_cubeMesh.vertexBuffer, m_game.arenaBoxes.size());
            const Mat4 gw = Mat4::translate(Vec3(0,0,0)) * Mat4::rotateX(-90.0f) * Mat4::scale(Vec3(1,1,1));
            const Mat4 gvp = gw * view * proj;
            nsTrace("GROUND_WVP row0=(%.4f,%.4f,%.4f,%.4f) row3=(%.4f,%.4f,%.4f,%.4f)",
                    gvp.m[0], gvp.m[1], gvp.m[2], gvp.m[3],
                    gvp.m[12], gvp.m[13], gvp.m[14], gvp.m[15]);
        }

        // Ground plane: brighter albedo than the sky so the plane reads,
        // with the procedural grid enabled via setTint's ground flag.
        setTint(0.34f, 0.36f, 0.42f, 1.0f);
        Mat4 world = Mat4::translate(Vec3(0.0f, 0.0f, 0.0f)) * Mat4::rotateX(-90.0f) * Mat4::scale(Vec3(1.0f, 1.0f, 1.0f));
        setTransform(world * view * proj, world);
        drawMesh(&m_renderer, &m_groundMesh);

        // Arena walls
        setTint(0.4f, 0.4f, 0.5f);
        for (const auto& box : m_game.arenaBoxes) {
            Vec3 center = (box.min + box.max) * 0.5f;
            Vec3 dims = box.max - box.min;
            Mat4 w = Mat4::translate(center) * Mat4::scale(dims);
            setTransform(w * view * proj, w);
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
            setTransform(w * view * proj, w);
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
            setTransform(w * view * proj, w);
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

    void setTransform(const Mat4& mvp, const Mat4& world) {
        // Two matrices in one buffer, matching cbuffer Transform: float4x4 world;
        // float4x4 worldViewProj. The world matrix is what makes the pixel
        // shader able to light a rotated object correctly.
        float data[32];
        std::memcpy(data, world.m, sizeof(float) * 16);
        std::memcpy(data + 16, mvp.m, sizeof(float) * 16);
        m_renderer.getContext()->UpdateSubresource(m_cb, 0, nullptr, data, 0, 0);
        m_renderer.setConstantBuffer(0, m_cb);
    }

    void setTint(float r, float g, float b, float ground = 0.0f) {
        // .a carries the ground-grid flag for the pixel shader.
        float tint[4] = { r, g, b, ground };
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
    Sky            m_sky{};
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
    nsTrace("ENTRY WinMain");
    if (!app.initialize()) { nsTrace("FATAL initialize returned false"); return 1; }
    app.run();
    app.shutdown();
    return 0;
}
