#pragma once

#include <vulkan/vulkan.h>
#include <chrono>
#include <vector>
#include <memory>
#include <array>
#include <cmath>
#include <string>
#include <fstream>

#include "win32_window.hpp"
#include "vulkan_renderer.hpp"

struct KartState {
    float x = 0.0f, y = 0.0f, z = 0.0f;
    float yaw = 0.0f, pitch = 0.0f, roll = 0.0f;
    float speed = 0.0f;
    float throttle = 0.0f;
    float steer = 0.0f;
    float vertical = 0.0f;
    bool firing = false;
    bool jump = false;
    bool airborne = false;
};

struct CameraState {
    float eyeX = 0.0f, eyeY = 3.0f, eyeZ = -8.0f;
    float targetX = 0.0f, targetY = 0.0f, targetZ = 0.0f;
    float upX = 0.0f, upY = 1.0f, upZ = 0.0f;
};

struct SceneSaveData {
    uint64_t seed = 20261025;
    std::string biome = "tropical";
    uint64_t tick = 0;
    float kartX = 0.0f, kartY = 0.0f, kartZ = 0.0f;
    float kartYaw = 0.0f;
    float kartThrottle = 0.0f, kartSteer = 0.0f;
};

class GameLoop {
public:
    GameLoop(Win32Window& window, VulkanRenderer& renderer, class WorldForgeBridge& worldforge, uint64_t seed, const std::string& biome);
    ~GameLoop();
    
    GameLoop(const GameLoop&) = delete;
    GameLoop& operator=(const GameLoop&) = delete;
    
    void run();
    void update(float deltaTime);
    void render();
    
    // Accessors for renderer
    VkBuffer getVertexBuffer() const { return vertexBuffer_; }
    VkBuffer getIndexBuffer() const { return indexBuffer_; }
    uint32_t getIndexCount() const { return indexCount_; }
    VulkanRenderer::UniformBuffer& getUniformBuffer() { return uniformBuffer_; }
    
    const KartState& getKartState() const { return kartState_; }
    const CameraState& getCameraState() const { return cameraState_; }
    
    // Persistence
    void saveScene(const std::string& path);
    void loadScene(const std::string& path);
    uint64_t getTick() const { return tick_; }
    
private:
    Win32Window& window_;
    VulkanRenderer& renderer_;
    class WorldForgeBridge& worldforge_;
    
    uint64_t seed_;
    std::string biome_;
    
    KartState kartState_;
    CameraState cameraState_;
    
    // Rendering resources
    VkBuffer vertexBuffer_ = VK_NULL_HANDLE;
    VkBuffer indexBuffer_ = VK_NULL_HANDLE;
    VkDeviceMemory vertexBufferMemory_ = VK_NULL_HANDLE;
    VkDeviceMemory indexBufferMemory_ = VK_NULL_HANDLE;
    uint32_t indexCount_ = 0;
    
    // Uniform buffer
    VulkanRenderer::UniformBuffer uniformBuffer_;
    
    // Timing
    std::chrono::steady_clock::time_point lastTime_;
    float accumulatedTime_ = 0.0f;
    const float FIXED_TIMESTEP = 1.0f / 60.0f;
    
    bool running_ = true;
    uint64_t tick_ = 0;
    
    // WorldForge mesh data
    std::vector<Vertex> terrainVertices_;
    std::vector<uint32_t> terrainIndices_;
    int gpuStreamSerial_ = -1;
    int productMeshStep_ = -1;
    int editorMeshRev_ = -1;
    
    // Input state
    std::array<bool, 256> keyStates_ = { false };
    bool debugTriangleMode_ = true; // Enable by default for debugging grey screen
    
    // Deterministic replay
    struct InputRecord {
        uint64_t tick;
        int virtualKey;
        bool pressed;
    };
    std::vector<InputRecord> inputRecords_;
    bool recording_ = false;
    bool replaying_ = false;
    size_t replayIndex_ = 0;
    
    void loadWorldForgeMesh();
    void createRenderBuffers();
    void cleanupRenderBuffers();
    
    // Input handling
    void onKeyPressed(int virtualKey);
    void onKeyReleased(int virtualKey);
    
    // Terrain height lookup (nearest vertex from heightmap)
    float getTerrainHeight(float x, float z) const;
    
    // Chase camera update
    void updateCamera();
    
    // Build model matrix for kart
    void buildKartModelMatrix(float model[16]) const;
    
    // Persistence helpers
    void recordInput(int virtualKey, bool pressed);
    void replayInput();
};
