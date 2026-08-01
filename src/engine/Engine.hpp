#pragma once
#include <string>
#include <cstdint>
#include <memory>
#include <functional>

// ============================================================================
// Engine Core — main loop, subsystem lifecycle, and frame timing
// ============================================================================

// ---------------------------------------------------------------------------
// Frame timing
// ---------------------------------------------------------------------------
struct FrameTiming {
    double deltaTime;       // seconds since last frame
    double totalTime;       // seconds since engine start
    uint64_t frameNumber;
    double fps;
    double cpuLoadPercent;
    double gpuLoadPercent;
};

// ---------------------------------------------------------------------------
// Engine configuration
// ---------------------------------------------------------------------------
struct EngineConfig {
    std::string windowTitle = "RawrXD Engine";
    uint32_t    windowWidth = 1280;
    uint32_t    windowHeight = 720;
    bool        vsync = true;
    double      targetFps = 60.0;
    bool        enableTelemetry = true;
    bool        enableAI = true;
    std::string modelPath = "";
};

// ---------------------------------------------------------------------------
// Engine class
// ---------------------------------------------------------------------------
class Engine {
public:
    Engine();
    ~Engine();

    // Lifecycle
    bool Initialize(const EngineConfig& config);
    void Shutdown();
    bool IsRunning() const;

    // Main loop
    int Run();
    void Stop();

    // Frame callbacks
    using UpdateCallback = std::function<void(const FrameTiming&)>;
    using RenderCallback = std::function<void(const FrameTiming&)>;

    void SetUpdateCallback(UpdateCallback cb);
    void SetRenderCallback(RenderCallback cb);

    // Manual frame tick (for external loop control)
    void FrameTick();

    // Accessors
    const FrameTiming& GetFrameTiming() const { return m_timing; }
    EngineConfig& GetConfig() { return m_config; }

private:
    void CalculateFrameTiming();

    EngineConfig m_config;
    FrameTiming m_timing;
    bool m_running = false;

    // Timing
    double m_frameStartTime = 0;
    double m_lastFrameTime = 0;
    double m_fpsAccumulator = 0;
    uint64_t m_fpsFrameCount = 0;

    // Callbacks
    UpdateCallback m_updateCallback;
    RenderCallback m_renderCallback;
};
