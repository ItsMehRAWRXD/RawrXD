#include "game_loop.hpp"
#include "player_step.hpp"
#include "product_scene.hpp"
#include "editor_api.hpp"
#include "worldforge_bridge.hpp"
#include <iostream>
#include <cmath>
#include <thread>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>

GameLoop::GameLoop(Win32Window& window, VulkanRenderer& renderer, WorldForgeBridge& worldforge, uint64_t seed, const std::string& biome)
    : window_(window), renderer_(renderer), worldforge_(worldforge),
      seed_(seed), biome_(biome) {
    
    lastTime_ = std::chrono::steady_clock::now();
    
    kartState_.x = 0.0f;
    kartState_.y = 1.0f;
    kartState_.z = 0.0f;
    kartState_.yaw = 0.0f;
    
    loadWorldForgeMesh();
    createRenderBuffers();
    if (worldforge_.productActive()) {
        productMeshStep_ = worldforge_.productStep();
        std::vector<float> xyz;
        fillInstances(worldforge_, xyz);
        if (!xyz.empty()) renderer_.uploadInstances(xyz.data(), static_cast<int>(xyz.size() / 3));
    }
    if (worldforge_.editorActive()) editorMeshRev_ = editorRevision();
    gpuStreamSerial_ = worldforge_.streamSerial();
    
    // Create uniform buffer
    uniformBuffer_ = renderer_.createUniformBuffer(sizeof(UniformBufferObject));
    
    // Wire up keyboard input
    window_.setKeyCallback([this](int vk, bool pressed) {
        if (vk < 256) keyStates_[vk] = pressed;
        recordInput(vk, pressed);
        
        // Save/Load hotkeys
        if (pressed && worldforge_.editorActive()) editorNoteKey(vk);
        if (pressed) {
            if (vk == VK_F5) {
                saveScene("kartgib_save.json");
                std::cout << "[G09] Scene saved to kartgib_save.json" << std::endl;
            } else if (vk == VK_F9) {
                loadScene("kartgib_save.json");
                std::cout << "[G09] Scene loaded from kartgib_save.json" << std::endl;
            } else if (vk == VK_F6) {
                recording_ = !recording_;
                inputRecords_.clear();
                replaying_ = false;
                replayIndex_ = 0;
                std::cout << "[G10] Input recording " << (recording_ ? "STARTED" : "STOPPED") << std::endl;
            } else if (vk == VK_F7) {
                replaying_ = !replaying_;
                replayIndex_ = 0;
                recording_ = false;
                std::cout << "[G10] Input replay " << (replaying_ ? "STARTED" : "STOPPED") << std::endl;
            } else if (vk == VK_F10) {
                renderer_.armForensics();
                std::cout << "[F10] Render visibility forensics armed" << std::endl;
            } else if (vk == VK_F8) {
                debugTriangleMode_ = !debugTriangleMode_;
                renderer_.enableDebugTriangleMode(debugTriangleMode_);
                std::cout << "[DEBUG] Triangle mode " << (debugTriangleMode_ ? "ENABLED" : "DISABLED") << std::endl;
            }
        }
    });
    
    std::cout << "Game loop initialized\n";
}

GameLoop::~GameLoop() {
    if (renderer_.getDevice() == VK_NULL_HANDLE) return;
    cleanupRenderBuffers();
    renderer_.destroyUniformBuffer(uniformBuffer_);
}

void GameLoop::run() {
    const float autoExitSeconds = 5.0f; // Short test duration
    std::cout << "Starting game loop... (will run for " << autoExitSeconds << " seconds)" << std::endl;
    std::cout << "Controls: W/A/S/D = drive, F5 = save, F9 = load, F6 = record input, F7 = replay input" << std::endl;
    
    auto loopStart = std::chrono::steady_clock::now();
    
    int frameCount = 0;
    while (!window_.shouldClose() && running_) {
        auto currentTime = std::chrono::steady_clock::now();
        float deltaTime = std::chrono::duration<float>(currentTime - lastTime_).count();
        lastTime_ = currentTime;
        
        // Auto-exit after timeout for testing
        float elapsed = std::chrono::duration<float>(currentTime - loopStart).count();
        if (elapsed > autoExitSeconds && !renderer_.forensicsBusy() && !renderer_.shadowCertBusy()
            && !renderer_.chunkTourBusy() && !renderer_.oceanTourBusy() && !renderer_.productTourBusy()
            && !worldforge_.editorActive()) {
            running_ = false;
            break;
        }
        
        // Cap delta time to prevent spiral of death
        if (deltaTime > 0.25f) deltaTime = 0.25f;
        
        auto frameStart = std::chrono::steady_clock::now();
        window_.pollEvents();
        update(deltaTime);
        if (worldforge_.editorActive() && editorSessionDone()) running_ = false;
        render();
        if (worldforge_.productActive()) {
            float frameMs = std::chrono::duration<float, std::milli>(
                std::chrono::steady_clock::now() - frameStart).count();
            renderer_.noteCpuMs(frameMs);
        }
        frameCount++;
        
        if (frameCount % 60 == 0) {
            std::cout << "[G04] Frame " << frameCount << " elapsed=" << elapsed << "s" << std::endl;
        }
        
        // Small sleep to prevent 100% CPU when not needed
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    std::cout << "Game loop ended after " << autoExitSeconds << "s, frames=" << frameCount << "\n" << std::endl;
}

void GameLoop::update(float deltaTime) {
        if (worldforge_.editorActive()) {
        studioNoteMesh(static_cast<int>(worldforge_.getWorld().terrain.vertices.size()));
        if (studioOwnsUndo()) {
            if (studioShowOnly()) studioScript(window_, renderer_);
            else if (studioEditor2()) editor2Script(window_, renderer_);
            else inspectorScript(window_, renderer_);
            inspectorRefresh();
        }
        else editorScript(window_, renderer_, 0);
        if (editorRevision() != editorMeshRev_) {
            if (editorMeshRev_ >= 0) {
                renderer_.waitIdle();
                cleanupRenderBuffers();
            }
            loadWorldForgeMesh();
            if (editorMeshRev_ >= 0) createRenderBuffers();
            editorMeshRev_ = editorRevision();
        }
        float shift = studioCameraShift();
        cameraState_.eyeX = -40.0f + shift; cameraState_.eyeY = 24.0f; cameraState_.eyeZ = -55.0f;
        cameraState_.targetX = 20.0f + shift; cameraState_.targetY = 12.0f; cameraState_.targetZ = 35.0f;
        cameraState_.upX = 0.0f; cameraState_.upY = 1.0f; cameraState_.upZ = 0.0f;
        static int pathNoted = 0;
        if (!pathNoted && !studioOwnsUndo() && editorShotCount() >= 1) {
            pathNoted = 1;
            renderer_.noteRenderPath("editor", editorCount(), editorCount(), 0, 1,
                static_cast<int>(worldforge_.getWorld().instances.size()), worldforge_.oceanActive() ? 1 : 0);
        }
        return;
    }
    if (worldforge_.productActive()) {
        int step = renderer_.productStep();
        if (step != productMeshStep_) {
            worldforge_.setProduct(true, step);
            if (productMeshStep_ >= 0) {
                renderer_.waitIdle();
                cleanupRenderBuffers();
            }
            loadWorldForgeMesh();
            if (productMeshStep_ >= 0) createRenderBuffers();
            productMeshStep_ = step;
        }
        float yaw = 0.0f, pitch = 0.0f;
        if (step == 1 || step == 3) applyLook(yaw, pitch, 225, -30);
        float ox = 60.0f, oy = -12.0f, oz = 90.0f;
        float c = std::cos(yaw), s = std::sin(yaw);
        cameraState_.eyeX = -40.0f; cameraState_.eyeY = 24.0f; cameraState_.eyeZ = -55.0f;
        cameraState_.targetX = cameraState_.eyeX + c * ox - s * oz;
        cameraState_.targetY = cameraState_.eyeY + oy + pitch * 18.0f;
        cameraState_.targetZ = cameraState_.eyeZ + s * ox + c * oz;
        cameraState_.upX = 0.0f; cameraState_.upY = 1.0f; cameraState_.upZ = 0.0f;
        return;
    }
    if (worldforge_.oceanActive()) {
        float simTime = renderer_.oceanSimTime();
        if (std::fabs(simTime - worldforge_.oceanTime()) > 0.001f) {
            worldforge_.setOcean(true, simTime);
            renderer_.waitIdle();
            cleanupRenderBuffers();
            loadWorldForgeMesh();
            createRenderBuffers();
        }
        kartState_.x = 0.0f; kartState_.z = 20.0f;
        kartState_.y = static_cast<float>(worldforge_.sampleHeightAt(0.0f, 20.0f)) + 0.5f;
        cameraState_.eyeX = -30.0f; cameraState_.eyeY = 36.0f; cameraState_.eyeZ = -80.0f;
        cameraState_.targetX = 50.0f; cameraState_.targetY = 8.0f; cameraState_.targetZ = 40.0f;
        cameraState_.upX = 0.0f; cameraState_.upY = 1.0f; cameraState_.upZ = 0.0f;
        return;
    }
    if (worldforge_.chunkGridActive()) {
        kartState_.throttle = 0.0f;
        kartState_.speed = 0.0f;
        kartState_.x = renderer_.chunkFocusX();
        kartState_.z = 0.0f;
        kartState_.y = static_cast<float>(worldforge_.sampleHeightAt(kartState_.x, kartState_.z)) + 0.5f;
        cameraState_.eyeX = kartState_.x - 40.0f;
        cameraState_.eyeY = kartState_.y + 55.0f;
        cameraState_.eyeZ = kartState_.z - 40.0f;
        cameraState_.targetX = kartState_.x + 90.0f;
        cameraState_.targetY = kartState_.y + 2.0f;
        cameraState_.targetZ = kartState_.z + 10.0f;
        cameraState_.upX = 0.0f;
        cameraState_.upY = 1.0f;
        cameraState_.upZ = 0.0f;
        worldforge_.streamAround(kartState_.x, kartState_.z);
        if (worldforge_.streamSerial() != gpuStreamSerial_) {
            renderer_.waitIdle();
            cleanupRenderBuffers();
            loadWorldForgeMesh();
            createRenderBuffers();
            gpuStreamSerial_ = worldforge_.streamSerial();
        }
        return;
    }
    // Handle input replay
    if (replaying_) {
        replayInput();
    }
    
    // Read keyboard input into kart controls (unless replaying)
    if (!replaying_) {
        kartState_.throttle = 0.0f;
        kartState_.steer = 0.0f;
        
        if (window_.isKeyPressed('W') || window_.isKeyPressed(VK_UP)) {
            kartState_.throttle = 1.0f;
        }
        if (window_.isKeyPressed('S') || window_.isKeyPressed(VK_DOWN)) {
            kartState_.throttle = -0.5f;
        }
        if (window_.isKeyPressed('A') || window_.isKeyPressed(VK_LEFT)) {
            kartState_.steer = -1.0f;
        }
        if (window_.isKeyPressed('D') || window_.isKeyPressed(VK_RIGHT)) {
            kartState_.steer = 1.0f;
        }
        if (window_.isKeyPressed(VK_SPACE)) kartState_.jump = true;
    }
    
    // Fixed timestep update for physics
    accumulatedTime_ += deltaTime;
    
    while (accumulatedTime_ >= FIXED_TIMESTEP) {
        tick_++;
        stepKartBody(kartState_, FIXED_TIMESTEP, [this](float x, float z) { return getTerrainHeight(x, z); });
        accumulatedTime_ -= FIXED_TIMESTEP;
    }
    
    // Update chase camera
    updateCamera();
}

void GameLoop::render() {
    if (window_.isMinimized()) {
        return;
    }
    
    // Handle swapchain resize
    if (window_.isResized()) {
        window_.clearResized();
        renderer_.recreateSwapchain();
        std::cout << "[G05] Swapchain resized to " << window_.getWidth() << "x" << window_.getHeight() << std::endl;
    }
    
    UniformBufferObject uboData = {};
    
    // Build view matrix (chase camera looking at kart)
    float ex = cameraState_.eyeX, ey = cameraState_.eyeY, ez = cameraState_.eyeZ;
    float tx = cameraState_.targetX, ty = cameraState_.targetY, tz = cameraState_.targetZ;
    float ux = cameraState_.upX, uy = cameraState_.upY, uz = cameraState_.upZ;
    
    // Forward vector
    float fx = tx - ex, fy = ty - ey, fz = tz - ez;
    float flen = std::sqrt(fx*fx + fy*fy + fz*fz);
    if (flen > 0.0001f) { fx /= flen; fy /= flen; fz /= flen; }
    
    // Right vector = forward x up
    float rx = fy*uz - fz*uy;
    float ry = fz*ux - fx*uz;
    float rz = fx*uy - fy*ux;
    float rlen = std::sqrt(rx*rx + ry*ry + rz*rz);
    if (rlen > 0.0001f) { rx /= rlen; ry /= rlen; rz /= rlen; }
    
    // Recompute up = right x forward
    float uxx = ry*fz - rz*fy;
    float uyy = rz*fx - rx*fz;
    float uzz = rx*fy - ry*fx;
    
    uboData.view[0] = rx;  uboData.view[1] = uxx; uboData.view[2] = -fx; uboData.view[3] = 0.0f;
    uboData.view[4] = ry;  uboData.view[5] = uyy; uboData.view[6] = -fy; uboData.view[7] = 0.0f;
    uboData.view[8] = rz;  uboData.view[9] = uzz; uboData.view[10] = -fz; uboData.view[11] = 0.0f;
    uboData.view[12] = -(rx * ex + ry * ey + rz * ez);
    uboData.view[13] = -(uxx * ex + uyy * ey + uzz * ez);
    uboData.view[14] = (fx * ex + fy * ey + fz * ez);
    uboData.view[15] = 1.0f;

    float fov = 1.04719755f;
    float aspect = static_cast<float>(window_.getWidth()) / std::max(1, window_.getHeight());
    float zNear = 0.5f;
    float zFar = 4000.0f;
    float f = 1.0f / std::tan(fov * 0.5f);
    uboData.proj[0] = f / aspect;
    uboData.proj[5] = -f;
    uboData.proj[10] = zFar / (zNear - zFar);
    uboData.proj[11] = -1.0f;
    uboData.proj[14] = (zFar * zNear) / (zNear - zFar);
    
    // Kart model matrix (identity for terrain - terrain is at world origin)
    float terrainModel[16] = {
        1.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 1.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 1.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 1.0f
    };
    memcpy(uboData.model, terrainModel, sizeof(terrainModel));
    
    uboData.lightDir[0] = -1.5f; uboData.lightDir[1] = -0.09f; uboData.lightDir[2] = -0.20f; uboData.lightDir[3] = 0.0f;
    uboData.padding[1] = worldforge_.chunkGridActive() ? 1.0f : 0.0f;
    uboData.cameraPos[0] = ex; uboData.cameraPos[1] = ey; uboData.cameraPos[2] = ez; uboData.cameraPos[3] = 1.0f;
    uboData.time = static_cast<float>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count()) / 1000.0f;
    
    // Update uniform buffer
    renderer_.updateUniformBuffer(uniformBuffer_, &uboData, sizeof(uboData));
    
    renderer_.drawFrame(vertexBuffer_, indexBuffer_, indexCount_, uboData);
}

void GameLoop::loadWorldForgeMesh() {
    // Load terrain mesh from WorldForge bridge
    auto meshData = worldforge_.generateTerrainMesh();
    terrainVertices_ = std::move(meshData.vertices);
    terrainIndices_ = std::move(meshData.indices);
    
    std::cout << "Loaded WorldForge terrain: " << terrainVertices_.size() << " vertices, "
              << terrainIndices_.size() << " indices\n";
}

void GameLoop::createRenderBuffers() {
    // Create vertex buffer
    VkDeviceSize vertexBufferSize = sizeof(terrainVertices_[0]) * terrainVertices_.size();
    
    VkBuffer stagingBuffer;
    VkDeviceMemory stagingBufferMemory;
    renderer_.createBuffer(vertexBufferSize, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
        stagingBuffer, stagingBufferMemory);
    
    void* data;
    vkMapMemory(renderer_.getDevice(), stagingBufferMemory, 0, vertexBufferSize, 0, &data);
    memcpy(data, terrainVertices_.data(), vertexBufferSize);
    vkUnmapMemory(renderer_.getDevice(), stagingBufferMemory);
    
    renderer_.createBuffer(vertexBufferSize, VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_VERTEX_BUFFER_BIT,
        VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
        vertexBuffer_, vertexBufferMemory_);
    
    renderer_.copyBuffer(stagingBuffer, vertexBuffer_, vertexBufferSize);
    
    vkDestroyBuffer(renderer_.getDevice(), stagingBuffer, nullptr);
    vkFreeMemory(renderer_.getDevice(), stagingBufferMemory, nullptr);
    
    // Create index buffer
    VkDeviceSize indexBufferSize = sizeof(terrainIndices_[0]) * terrainIndices_.size();
    indexCount_ = static_cast<uint32_t>(terrainIndices_.size());
    
    renderer_.createBuffer(indexBufferSize, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
        stagingBuffer, stagingBufferMemory);
    
    vkMapMemory(renderer_.getDevice(), stagingBufferMemory, 0, indexBufferSize, 0, &data);
    memcpy(data, terrainIndices_.data(), indexBufferSize);
    vkUnmapMemory(renderer_.getDevice(), stagingBufferMemory);
    
    renderer_.createBuffer(indexBufferSize, VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_INDEX_BUFFER_BIT,
        VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
        indexBuffer_, indexBufferMemory_);
    
    renderer_.copyBuffer(stagingBuffer, indexBuffer_, indexBufferSize);
    
    vkDestroyBuffer(renderer_.getDevice(), stagingBuffer, nullptr);
    vkFreeMemory(renderer_.getDevice(), stagingBufferMemory, nullptr);
    
    std::cout << "Render buffers created: " << indexCount_ << " indices\n";
}

void GameLoop::cleanupRenderBuffers() {
    if (vertexBuffer_ != VK_NULL_HANDLE) {
        vkDestroyBuffer(renderer_.getDevice(), vertexBuffer_, nullptr);
        vkFreeMemory(renderer_.getDevice(), vertexBufferMemory_, nullptr);
        vertexBuffer_ = VK_NULL_HANDLE;
        vertexBufferMemory_ = VK_NULL_HANDLE;
    }
    if (indexBuffer_ != VK_NULL_HANDLE) {
        vkDestroyBuffer(renderer_.getDevice(), indexBuffer_, nullptr);
        vkFreeMemory(renderer_.getDevice(), indexBufferMemory_, nullptr);
        indexBuffer_ = VK_NULL_HANDLE;
        indexBufferMemory_ = VK_NULL_HANDLE;
    }
}

float GameLoop::getTerrainHeight(float x, float z) const {
    // Simple nearest-vertex height lookup from terrain mesh
    const int resolution = 129;
    const float worldSize = 2048.0f;
    float gx = std::clamp((x + worldSize * 0.5f) / worldSize, 0.0f, 1.0f) * static_cast<float>(resolution - 1);
    float gz = std::clamp((z + worldSize * 0.5f) / worldSize, 0.0f, 1.0f) * static_cast<float>(resolution - 1);
    
    int ix0 = static_cast<int>(std::floor(gx));
    int iz0 = static_cast<int>(std::floor(gz));
    int ix1 = std::min(ix0 + 1, resolution - 1);
    int iz1 = std::min(iz0 + 1, resolution - 1);
    
    float fx = gx - ix0;
    float fz = gz - iz0;
    
    // Bilinear interpolation of vertex heights
    int v00 = iz0 * resolution + ix0;
    int v10 = iz0 * resolution + ix1;
    int v01 = iz1 * resolution + ix0;
    int v11 = iz1 * resolution + ix1;
    
    if (v00 >= static_cast<int>(terrainVertices_.size()) || 
        v10 >= static_cast<int>(terrainVertices_.size()) ||
        v01 >= static_cast<int>(terrainVertices_.size()) || 
        v11 >= static_cast<int>(terrainVertices_.size())) {
        return 0.0f;
    }
    
    float h00 = terrainVertices_[v00].pos[1];
    float h10 = terrainVertices_[v10].pos[1];
    float h01 = terrainVertices_[v01].pos[1];
    float h11 = terrainVertices_[v11].pos[1];
    
    float h0 = h00 * (1.0f - fx) + h10 * fx;
    float h1 = h01 * (1.0f - fx) + h11 * fx;
    
    return h0 * (1.0f - fz) + h1 * fz;
}

void GameLoop::updateCamera() {
    if (worldforge_.chunkGridActive()) {
        cameraState_.eyeX = kartState_.x - 40.0f;
        cameraState_.eyeY = kartState_.y + 55.0f;
        cameraState_.eyeZ = kartState_.z - 40.0f;
        cameraState_.targetX = kartState_.x + 90.0f;
        cameraState_.targetY = kartState_.y + 2.0f;
        cameraState_.targetZ = kartState_.z + 10.0f;
        cameraState_.upX = 0.0f;
        cameraState_.upY = 1.0f;
        cameraState_.upZ = 0.0f;
        return;
    }
    // Chase camera - positioned behind and above the kart
    float camDist = 80.0f;
    float camHeight = 6.0f;
    
    cameraState_.targetX = kartState_.x;
    cameraState_.targetY = kartState_.y + 1.0f;
    cameraState_.targetZ = kartState_.z + 40.0f;
    
    cameraState_.eyeX = kartState_.x;
    cameraState_.eyeY = kartState_.y + camHeight;
    cameraState_.eyeZ = kartState_.z - camDist;
    float eyeGround = getTerrainHeight(cameraState_.eyeX, cameraState_.eyeZ);
    if (cameraState_.eyeY < eyeGround + 8.0f) {
        cameraState_.eyeY = eyeGround + camHeight;
    }
    
    cameraState_.upX = 0.0f;
    cameraState_.upY = 1.0f;
    cameraState_.upZ = 0.0f;
}

void GameLoop::buildKartModelMatrix(float model[16]) const {
    // Simple rotation + translation matrix for the kart
    float cy = std::cos(kartState_.yaw);
    float sy = std::sin(kartState_.yaw);
    
    model[0]  = cy;  model[1]  = 0.0f; model[2]  = sy;  model[3]  = 0.0f;
    model[4]  = 0.0f; model[5]  = 1.0f; model[6]  = 0.0f; model[7]  = 0.0f;
    model[8]  = -sy; model[9]  = 0.0f; model[10] = cy;  model[11] = 0.0f;
    model[12] = kartState_.x; model[13] = kartState_.y; model[14] = kartState_.z; model[15] = 1.0f;
}

void GameLoop::saveScene(const std::string& path) {
    SceneSaveData save;
    save.seed = seed_;
    save.biome = biome_;
    save.tick = tick_;
    save.kartX = kartState_.x;
    save.kartY = kartState_.y;
    save.kartZ = kartState_.z;
    save.kartYaw = kartState_.yaw;
    save.kartThrottle = kartState_.throttle;
    save.kartSteer = kartState_.steer;
    
    std::ofstream file(path);
    if (!file.is_open()) {
        std::cerr << "[G09] Failed to open save file: " << path << std::endl;
        return;
    }
    
    file << std::fixed << std::setprecision(6);
    file << "seed=" << save.seed << "\n";
    file << "biome=" << save.biome << "\n";
    file << "tick=" << save.tick << "\n";
    file << "kartX=" << save.kartX << "\n";
    file << "kartY=" << save.kartY << "\n";
    file << "kartZ=" << save.kartZ << "\n";
    file << "kartYaw=" << save.kartYaw << "\n";
    file << "kartThrottle=" << save.kartThrottle << "\n";
    file << "kartSteer=" << save.kartSteer << "\n";
    
    file.close();
    std::cout << "[G09] Scene saved: tick=" << save.tick 
              << " kart=(" << save.kartX << "," << save.kartY << "," << save.kartZ << ")" << std::endl;
}

void GameLoop::loadScene(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[G09] Failed to open save file: " << path << std::endl;
        return;
    }
    
    SceneSaveData save;
    std::string line;
    while (std::getline(file, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        
        if (key == "seed") save.seed = std::stoull(val);
        else if (key == "biome") save.biome = val;
        else if (key == "tick") save.tick = std::stoull(val);
        else if (key == "kartX") save.kartX = std::stof(val);
        else if (key == "kartY") save.kartY = std::stof(val);
        else if (key == "kartZ") save.kartZ = std::stof(val);
        else if (key == "kartYaw") save.kartYaw = std::stof(val);
        else if (key == "kartThrottle") save.kartThrottle = std::stof(val);
        else if (key == "kartSteer") save.kartSteer = std::stof(val);
    }
    
    file.close();
    
    // Restore kart state
    kartState_.x = save.kartX;
    kartState_.y = save.kartY;
    kartState_.z = save.kartZ;
    kartState_.yaw = save.kartYaw;
    kartState_.throttle = save.kartThrottle;
    kartState_.steer = save.kartSteer;
    tick_ = save.tick;
    
    std::cout << "[G09] Scene loaded: tick=" << save.tick 
              << " kart=(" << save.kartX << "," << save.kartY << "," << save.kartZ << ")" << std::endl;
}

void GameLoop::recordInput(int virtualKey, bool pressed) {
    if (!recording_) return;
    
    InputRecord record;
    record.tick = tick_;
    record.virtualKey = virtualKey;
    record.pressed = pressed;
    inputRecords_.push_back(record);
}

void GameLoop::replayInput() {
    if (inputRecords_.empty() || replayIndex_ >= inputRecords_.size()) {
        replaying_ = false;
        replayIndex_ = 0;
        std::cout << "[G10] Replay complete" << std::endl;
        return;
    }
    
    const InputRecord& rec = inputRecords_[replayIndex_];
    
    // Only apply input if we've reached the tick
    if (tick_ >= rec.tick) {
        keyStates_[rec.virtualKey] = rec.pressed;
        replayIndex_++;
    }
}
