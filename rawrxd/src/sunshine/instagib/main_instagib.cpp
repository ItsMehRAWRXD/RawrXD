#include <windows.h>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "sunshine/core/WindowWin32.hpp"
#include "sunshine/core/RendererD3D11.hpp"
#include "sunshine/core/Input.hpp"
#include "sunshine/core/Timer.hpp"
#include "sunshine/core/Camera.hpp"
#include "sunshine/core/Primitives.hpp"
#include "sunshine/core/Sky.hpp"
#include "sunshine/instagib/Game.hpp"
#include "sunshine/instagib/HUD.hpp"

namespace Sunshine {

// RAWRXD_INSTAGIB_Q3_UT99_CS_SHADER_001
//
// Target look: late-90s/early-2000s arena shooter (Quake III, UT99, CS 1.6).
// Four things carry that era, and all four are computed here rather than
// faked with a flat colour ramp:
//
//   1. HEMISPHERIC AMBIENT -- cool sky from above, warm dark bounce from
//      below. Q3's single dominant cue; a single flat ambient cannot do it.
//   2. WRAPPED KEY LIGHT -- soft terminator instead of a hard N.L edge.
//   3. TIGHT BLINN-PHONG SPECULAR -- small hot highlight, low intensity.
//   4. LINEAR DISTANCE FOG toward a horizon tint -- the single strongest
//      "this is 1999" signal, and what gives the arena its sense of scale.
//
// SM4 constraints learned the hard way in this file already: `line` is a
// reserved HLSL word, and `mix()` does not exist in ps_4_0 (it is `lerp()`).
static const char* kVSCode = R"(
cbuffer Transform : register(b0) {
    // row_major is mandatory: Mat4::m is float[4][4] filled row-major, while
    // HLSL float4x4 defaults to column-major. Without it every transform is
    // transposed and the whole arena renders as a diagonal shear.
    row_major float4x4 world;
    row_major float4x4 worldViewProj;
};
struct VS_IN  { float3 pos : POSITION; float3 nrm : NORMAL; float2 uv : TEXCOORD0; };
struct PS_IN  { float4 pos : SV_POSITION; float3 nrm : NORMAL; float2 uv : TEXCOORD0;
                float fogDist : TEXCOORD1; };
PS_IN main(VS_IN input) {
    PS_IN output;
    output.pos = mul(float4(input.pos, 1.0), worldViewProj);
    // World-space normal. The arena ground is rotated -90 deg about X, so its
    // true normal is +Y; passing the object-space normal lit it on the wrong
    // axis (N.L = 0.257 instead of 0.857).
    output.nrm = normalize(mul((float3x3)world, input.nrm));
    output.uv = input.uv;
    // Clip-space w equals view-space distance under a standard perspective
    // projection, which is exactly the fog parameter we want.
    output.fogDist = output.pos.w;
    return output;
}
)";

static const char* kPSCode = R"(
cbuffer Tint : register(b1) {
    float4 tintColor;    // rgb = albedo, a = material id (0 generic, 1 ground plate)
};
struct PS_IN { float4 pos : SV_POSITION; float3 nrm : NORMAL; float2 uv : TEXCOORD0;
               float fogDist : TEXCOORD1; };

// Cheap value noise for per-panel albedo variation.
float hash21(float2 p) {
    return frac(sin(dot(p, float2(12.9898, 78.233))) * 43758.5453);
}

float4 main(PS_IN input) : SV_TARGET {
    float3 N = normalize(input.nrm);
    float3 L = normalize(float3(0.42, 0.80, 0.43));   // key light, high and slightly right

    // ---- 1. hemispheric ambient -------------------------------------------
    float hemi = N.y * 0.5 + 0.5;
    float3 skyAmb    = float3(0.31, 0.37, 0.47);
    float3 groundAmb = float3(0.14, 0.125, 0.11);
    float3 ambient   = lerp(groundAmb, skyAmb, hemi);

    // ---- 2. wrapped key light --------------------------------------------
    float ndl  = dot(N, L);
    float wrap = saturate((ndl + 0.28) / 1.28);
    float3 key = float3(1.00, 0.955, 0.875) * wrap;

    // ---- 3. tight specular -------------------------------------------------
    float3 H    = normalize(L + float3(0.0, 0.0, 1.0));
    float  spec = pow(saturate(dot(N, H)), 30.0) * 0.30;

    // ---- albedo, with procedural detail on the ground plate ----------------
    float3 albedo = tintColor.rgb;
    if (tintColor.a > 0.5) {
        // CS-style panelled floor: 16 plates, darker seams, per-plate value
        // jitter so the surface does not read as a flat sheet.
        float2 g  = input.uv * 16.0;
        float2 fr = abs(frac(g) - 0.5);
        float seam = 1.0 - smoothstep(0.40, 0.485, max(fr.x, fr.y));
        float panel = hash21(floor(g));
        albedo *= (0.84 + 0.28 * panel);
        albedo  = lerp(albedo, albedo * 0.48, seam * 0.85);
    }

    float3 color = albedo * (ambient + key) + spec;

    // ---- 4. linear distance fog -------------------------------------------
    float fog = saturate((input.fogDist - 7.0) / 45.0);
    color = lerp(color, float3(0.105, 0.125, 0.165), fog * 0.92);

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

        // world + worldViewProj. The world matrix is required so the pixel shader
        // can light a rotated object; without it the normal stays object-space.
        if (!m_sky.initialize(&m_renderer, SkyParams{})) { lg("sky init failed"); if (log) fclose(log); return false; }

        m_cb = m_renderer.createConstantBuffer(sizeof(float) * 32);
        if (!m_cb) { lg("cb create failed"); if (log) fclose(log); return false; }
        m_tintCB = m_renderer.createConstantBuffer(sizeof(float) * 4);
        if (!m_tintCB) { lg("tint cb create failed"); if (log) fclose(log); return false; }
        lg("cb ok");

        m_running = true;
        m_timer.reset();
        lg("init complete");
        if (log) fclose(log);
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
        m_renderer.shutdown();
        m_window.shutdown();
    }

    void run() {
        // Capture config from environment
        uint32_t captureAfterMs = 0;
        bool captureExit = false;
        wchar_t capturePath[512] = L"";
        uint32_t captureFrame = 0;
        bool deterministic = false;
        float fixedDt = 0.0f;
        {
            const char* ms = getenv("SUNSHINE_CAPTURE_AFTER_MS");
            if (ms) captureAfterMs = (uint32_t)atoi(ms);
            const char* exitStr = getenv("SUNSHINE_CAPTURE_EXIT");
            if (exitStr && atoi(exitStr)) captureExit = true;
            const char* pathStr = getenv("SUNSHINE_CAPTURE_PATH");
            if (pathStr) {
                size_t n = strlen(pathStr);
                if (n < sizeof(capturePath) / sizeof(capturePath[0])) {
                    for (size_t i = 0; i < n; ++i) capturePath[i] = (wchar_t)pathStr[i];
                    capturePath[n] = L'\0';
                }
            } else if (captureAfterMs > 0 || captureFrame > 0) {
                wcscpy_s(capturePath, L"sunshine_capture.bmp");
            }
            const char* frameStr = getenv("SUNSHINE_CAPTURE_FRAME");
            if (frameStr) captureFrame = (uint32_t)atoi(frameStr);
            const char* detStr = getenv("SUNSHINE_DETERMINISTIC");
            if (detStr && atoi(detStr)) {
                deterministic = true;
                fixedDt = 1.0f / 60.0f;
                const char* fixedMs = getenv("SUNSHINE_FIXED_TIMESTEP_MS");
                if (fixedMs) fixedDt = (float)atof(fixedMs) / 1000.0f;
                if (fixedDt <= 0.0f) fixedDt = 1.0f / 60.0f;
            }
        }

        bool firstFrame = true;
        uint64_t renderStart = 0;
        bool captured = false;
        uint32_t frameCount = 0;

        m_game.deterministic = deterministic;

        while (m_running) {
            double dt = deterministic ? (double)fixedDt : m_timer.tick();
            if (!deterministic && dt > 0.25) dt = 0.25;
            update((float)dt, deterministic);
            render();
            ++frameCount;

            if (!captured) {
                bool shouldCapture = false;
                if (captureFrame > 0 && frameCount >= captureFrame) {
                    shouldCapture = true;
                } else if (captureAfterMs > 0) {
                    uint64_t nowTick = GetTickCount64();
                    if (firstFrame) {
                        renderStart = nowTick;
                        firstFrame = false;
                    }
                    if ((nowTick - renderStart) >= captureAfterMs) {
                        shouldCapture = true;
                    }
                }
                if (shouldCapture && wcslen(capturePath) > 0) {
                    if (m_renderer.captureFrame(capturePath)) {
                        FILE* lf = nullptr;
                        fopen_s(&lf, "instagib_log.txt", "a");
                        if (lf) {
                            char buf[512];
                            if (captureFrame > 0)
                                sprintf_s(buf, "CAPTURE_OK path=%S frame=%u", capturePath, frameCount);
                            else
                                sprintf_s(buf, "CAPTURE_OK path=%S ms=%u", capturePath, captureAfterMs);
                            fprintf(lf, "%s\n", buf);
                            fclose(lf);
                        }
                    }
                    captured = true;
                    if (captureExit) m_running = false;
                }
            }
        }
    }

private:
    void update(float dt, bool deterministic) {
        if (!deterministic) {
            m_input.update();
            float speed = 5.0f * dt;
            if (m_input.keyDown('W')) m_camera.moveForward(speed);
            if (m_input.keyDown('S')) m_camera.moveForward(-speed);
            if (m_input.keyDown('A')) m_camera.moveRight(-speed);
            if (m_input.keyDown('D')) m_camera.moveRight(speed);

            float sens = 0.15f;
            m_camera.rotateYawPitch(m_input.mouseDeltaX() * sens, m_input.mouseDeltaY() * sens);
        }

        double now = m_timer.now();

        // Keep player camera in sync
        m_game.player.camera = m_camera;

        // Fire on left click (auto-fire for verification)
        if (!deterministic) {
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

        if (!deterministic && (m_input.keyDown(VK_ESCAPE) || !m_window.processMessages())) {
            m_running = false;
        } else if (deterministic) {
            if (!m_window.processMessages()) m_running = false;
        }
    }

    void render() {
        m_renderer.beginFrame(0.105f, 0.125f, 0.165f);   // horizon-matched fog colour
        // RAWRXD_SUNSHINE_SKY_002: fullscreen procedural background first, with
        // depth testing disabled so it is not rejected at the far plane.
        m_sky.draw(&m_renderer, m_timer.now(), -1);
        m_renderer.setShader(&m_shader);

        Mat4 proj = m_camera.getProjectionMatrix();
        Mat4 view = m_camera.getViewMatrix();

        // Ground plane (rotate XY quad to XZ plane so it faces +Y / up)
        Mat4 world = Mat4::translate(Vec3(0.0f, 0.0f, 0.0f)) * Mat4::rotateX(-90.0f) * Mat4::scale(Vec3(1.0f, 1.0f, 1.0f));
        Mat4 mvp = world * view * proj;
        setTint(0.44f, 0.42f, 0.38f, 1.0f);   // dusty plate floor, material 1 = panelled
        setTransform(mvp, world);
        drawMesh(&m_renderer, &m_groundMesh);

        // Arena walls (rendered as scaled cubes)
        for (size_t i = 0; i < m_game.arena.boxes.size(); ++i) {
            const AABB& box = m_game.arena.boxes[i];
            Vec3 center = (box.min + box.max) * 0.5f;
            Vec3 dims = box.max - box.min;
            world = Mat4::translate(center) * Mat4::scale(dims);
            mvp = world * view * proj;
            setTint(0.52f, 0.50f, 0.47f);          // concrete grey walls
            setTransform(mvp, world);
            drawMesh(&m_renderer, &m_cubeMesh);
        }

        // Bots (rendered as cubes)
        for (size_t bi = 0; bi < m_game.bots.size(); ++bi) {
            Bot& bot = m_game.bots[bi];
            if (!bot.alive) continue;
            Vec3 botPos = bot.pos + Vec3(0.0f, 0.9f, 0.0f);
            world = Mat4::translate(botPos) * Mat4::scale(Vec3(0.6f, 1.8f, 0.6f));
            mvp = world * view * proj;
            // Two-team colour split by roster index. Bot and Player carry no
            // team/index field, so the parity split is the honest way to get
            // readable team colours without inventing state that does not exist.
            if (bi % 2 == 0) setTint(0.68f, 0.22f, 0.19f);   // rust red
            else           setTint(0.24f, 0.38f, 0.66f);   // steel blue
            setTransform(mvp, world);
            drawMesh(&m_renderer, &m_cubeMesh);
        }

        // HUD (screen-space overlay)
        int sw = m_window.getWidth();
        int sh = m_window.getHeight();
        bool playerWon = m_game.matchOver && m_game.player.score >= m_game.scoreLimit;
        m_hud.drawAll(&m_renderer, m_game.player, m_game.matchTime, m_game.timeLimit, m_game.matchOver, playerWon, sw, sh);

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
    bool      m_running = false;    bool m_deterministic = false;
    Mesh m_groundMesh = {};
    Mesh m_cubeMesh = {};
    Renderer::Shader m_shader = {};
    Sky            m_sky{};
    ID3D11Buffer* m_cb = nullptr;
    ID3D11Buffer* m_tintCB = nullptr;

    void setTransform(const Mat4& mvp, const Mat4& world) {
        float data[32];
        std::memcpy(data, world.m, sizeof(float) * 16);
        std::memcpy(data + 16, mvp.m, sizeof(float) * 16);
        m_renderer.getContext()->UpdateSubresource(m_cb, 0, nullptr, data, 0, 0);
        m_renderer.setConstantBuffer(0, m_cb);
    }
    void setTint(float r, float g, float b, float material = 0.0f) {
        float tint[4] = { r, g, b, material };
        m_renderer.getContext()->UpdateSubresource(m_tintCB, 0, nullptr, tint, 0, 0);
        m_renderer.setConstantBuffer(1, m_tintCB);
    }
};

} // namespace Sunshine

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    Sunshine::InstagibGame game;
    if (!game.initialize()) return 1;
    game.run();
    game.shutdown();
    return 0;
}
