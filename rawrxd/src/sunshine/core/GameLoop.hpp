#pragma once

#include "WindowWin32.hpp"
#include "RendererD3D11.hpp"
#include "Input.hpp"
#include "Timer.hpp"
#include "Camera.hpp"
#include "Audio.hpp"
#include "Primitives.hpp"

namespace Sunshine {

class GameLoop {
public:
    bool initialize();
    void shutdown();
    void run();
    bool isRunning() const { return m_running; }

    Window* getWindow() { return &m_window; }
    Renderer* getRenderer() { return &m_renderer; }
    Input* getInput() { return &m_input; }
    Camera* getCamera() { return &m_camera; }
    Audio* getAudio() { return &m_audio; }
    Timer* getTimer() { return &m_timer; }

    double frameTime() const { return m_frameTime; }
    double elapsedTime() const { return m_elapsedTime; }

private:
    void update(double dt);
    void render();

    Window m_window;
    Renderer m_renderer;
    Input m_input;
    Timer m_timer;
    Camera m_camera;
    Audio m_audio;
    bool m_running = false;
    double m_frameTime = 0.0;
    double m_elapsedTime = 0.0;

    Mesh m_cubeMesh = {};
    Mesh m_quadMesh = {};
    Renderer::Shader m_shader = {};
    ID3D11Buffer* m_cb = nullptr;
};

} // namespace Sunshine
