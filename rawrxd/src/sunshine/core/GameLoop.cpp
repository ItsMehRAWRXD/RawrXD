#include "GameLoop.hpp"
#include <cstring>

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

bool GameLoop::initialize() {
    WindowConfig cfg;
    cfg.width = 1280;
    cfg.height = 720;
    cfg.title = "Sunshine Core";
    if (!m_window.initialize(cfg)) return false;

    m_window.setResizeCallback([this](int w, int h) {
        m_renderer.resize(w, h);
        m_camera.setPerspective(60.0f, (float)w / (float)h, 0.1f, 1000.0f);
    });

    if (!m_renderer.initialize(&m_window)) return false;

    m_input.setRawInput(m_window.getHandle());

    m_camera.setPerspective(60.0f, 1280.0f / 720.0f, 0.1f, 1000.0f);
    m_camera.setPosition(Vec3(0.0f, 1.6f, 4.0f));
    m_camera.setLookAt(Vec3(0.0f, 1.0f, 0.0f));
    m_camera.setUp(Vec3(0.0f, 1.0f, 0.0f));

    if (!m_audio.initialize()) return false;

    m_cubeMesh = makeCubeMesh(&m_renderer, 1.0f);
    m_quadMesh = makeQuadMesh(&m_renderer, 20.0f, 20.0f);

    D3D11_INPUT_ELEMENT_DESC layout[] = {
        {"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
        {"NORMAL",   0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0},
        {"TEXCOORD0",0, DXGI_FORMAT_R32G32_FLOAT,    0, 24, D3D11_INPUT_PER_VERTEX_DATA, 0},
    };
    if (!m_renderer.compileShader(kVSCode, kPSCode, layout, 3, &m_shader)) return false;

    m_cb = m_renderer.createConstantBuffer(sizeof(float) * 16);
    if (!m_cb) return false;

    m_running = true;
    m_timer.reset();
    return true;
}

void GameLoop::shutdown() {
    m_running = false;
    if (m_cb) { m_cb->Release(); m_cb = nullptr; }
    m_renderer.releaseShader(&m_shader);
    releaseMesh(&m_cubeMesh);
    releaseMesh(&m_quadMesh);
    m_audio.shutdown();
    m_renderer.shutdown();
    m_window.shutdown();
}

void GameLoop::update(double dt) {
    m_input.update();
    m_elapsedTime = m_timer.elapsed();

    float speed = 3.0f * (float)dt;
    if (m_input.keyDown('W')) m_camera.moveForward(speed);
    if (m_input.keyDown('S')) m_camera.moveForward(-speed);
    if (m_input.keyDown('A')) m_camera.moveRight(-speed);
    if (m_input.keyDown('D')) m_camera.moveRight(speed);

    float sens = 0.1f;
    m_camera.rotateYawPitch(m_input.mouseDeltaX() * sens, m_input.mouseDeltaY() * sens);

    if (m_input.keyPressed(VK_SPACE)) {
        m_audio.playTone(440.0f, 0.2f);
    }

    if (m_input.keyDown(VK_ESCAPE) || !m_window.processMessages()) {
        m_running = false;
    }
}

void GameLoop::render() {
    m_renderer.beginFrame(0.1f, 0.12f, 0.15f);
    m_renderer.setShader(&m_shader);

    Mat4 proj = m_camera.getProjectionMatrix();
    Mat4 view = m_camera.getViewMatrix();

    // Ground plane
    Mat4 world = Mat4::translate(Vec3(0.0f, 0.0f, 0.0f)) * Mat4::scale(Vec3(1.0f, 1.0f, 1.0f));
    Mat4 mvp = world * view * proj;
    m_renderer.getContext()->UpdateSubresource(m_cb, 0, nullptr, mvp.m, 0, 0);
    m_renderer.setConstantBuffer(0, m_cb);
    drawMesh(&m_renderer, &m_quadMesh);

    // Spinning cube
    float angle = (float)(m_elapsedTime * 45.0);
    world = Mat4::translate(Vec3(0.0f, 1.0f, 0.0f)) * Mat4::rotateY(angle);
    mvp = world * view * proj;
    m_renderer.getContext()->UpdateSubresource(m_cb, 0, nullptr, mvp.m, 0, 0);
    m_renderer.setConstantBuffer(0, m_cb);
    drawMesh(&m_renderer, &m_cubeMesh);

    m_renderer.endFrame();
    m_renderer.present();
}

void GameLoop::run() {
    while (m_running) {
        double dt = m_timer.tick();
        if (dt > 0.25) dt = 0.25; // clamp
        m_frameTime = dt;
        update(dt);
        render();
    }
}

} // namespace Sunshine
