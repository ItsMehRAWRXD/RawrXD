#include "Engine.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <windows.h>

Engine::Engine() {
    m_timing = {};
}

Engine::~Engine() {
    Shutdown();
}

bool Engine::Initialize(const EngineConfig& config) {
    m_config = config;
    m_running = true;
    m_timing.frameNumber = 0;
    m_timing.totalTime = 0.0;

    std::cout << "========================================\n";
    std::cout << "  RawrXD Engine v1.0.0\n";
    std::cout << "  " << config.windowTitle << "\n";
    std::cout << "  Resolution: " << config.windowWidth << "x" << config.windowHeight << "\n";
    std::cout << "  Target FPS: " << config.targetFps << "\n";
    std::cout << "  AI Runtime: " << (config.enableAI ? "enabled" : "disabled") << "\n";
    std::cout << "========================================\n";

    m_lastFrameTime = 0.0;
    return true;
}

void Engine::Shutdown() {
    m_running = false;
    std::cout << "[Engine] Shutdown complete\n";
}

bool Engine::IsRunning() const {
    return m_running;
}

int Engine::Run() {
    if (!m_running) {
        std::cerr << "[Engine] Not initialized\n";
        return 1;
    }

    std::cout << "[Engine] Main loop started\n";

    while (m_running) {
        FrameTick();

        // Cap frame rate
        double frameTime = m_timing.deltaTime;
        double targetFrameTime = 1.0 / m_config.targetFps;
        if (frameTime < targetFrameTime) {
            double sleepMs = (targetFrameTime - frameTime) * 1000.0;
            std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(sleepMs)));
        }
    }

    std::cout << "[Engine] Main loop exited\n";
    return 0;
}

void Engine::Stop() {
    m_running = false;
}

void Engine::FrameTick() {
    CalculateFrameTiming();

    // Update
    if (m_updateCallback) {
        m_updateCallback(m_timing);
    }

    // Render
    if (m_renderCallback) {
        m_renderCallback(m_timing);
    }

    m_timing.frameNumber++;
}

void Engine::CalculateFrameTiming() {
    LARGE_INTEGER freq, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);

    double currentTime = static_cast<double>(now.QuadPart) / freq.QuadPart;

    if (m_lastFrameTime == 0.0) {
        m_lastFrameTime = currentTime;
        m_timing.deltaTime = 1.0 / 60.0;
        return;
    }

    m_timing.deltaTime = currentTime - m_lastFrameTime;
    m_lastFrameTime = currentTime;
    m_timing.totalTime += m_timing.deltaTime;

    // FPS calculation
    m_fpsAccumulator += m_timing.deltaTime;
    m_fpsFrameCount++;
    if (m_fpsAccumulator >= 1.0) {
        m_timing.fps = m_fpsFrameCount / m_fpsAccumulator;
        m_fpsAccumulator = 0.0;
        m_fpsFrameCount = 0;
    }
}

void Engine::SetUpdateCallback(UpdateCallback cb) {
    m_updateCallback = std::move(cb);
}

void Engine::SetRenderCallback(RenderCallback cb) {
    m_renderCallback = std::move(cb);
}
