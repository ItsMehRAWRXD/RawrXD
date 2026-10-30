#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "vulkan_renderer.hpp"
#include "worldforge.hpp"

struct HeightEdit { float x = 0, z = 0; double y = 0; };
void appendChunkMesh(std::vector<Vertex>& verts, std::vector<uint32_t>& indices,
    int cx, int cz, const std::vector<double>& h, const kg::Settings& settings, int step, int edgeMask);

class WorldForgeBridge {
public:
    WorldForgeBridge();
    ~WorldForgeBridge();
    
    WorldForgeBridge(const WorldForgeBridge&) = delete;
    WorldForgeBridge& operator=(const WorldForgeBridge&) = delete;
    
    void initialize(uint64_t seed, const std::string& biome);
    
    // Generate terrain mesh from WorldForge procedural generation
    struct MeshResult {
        std::vector<Vertex> vertices;
        std::vector<uint32_t> indices;
    };
    
    MeshResult generateTerrainMesh();
    void useChunkGrid(bool enable);
    bool chunkGridActive() const { return chunkGrid_; }
    double sampleHeightAt(float x, float z) const;
    void editHeight(float x, float z, double y);
    void clearEdits();
    bool saveEdits(const std::string& path) const;
    bool loadEdits(const std::string& path);
    void streamAround(float x, float z);
    void setOcean(bool enabled, float time) { ocean_ = enabled; oceanTime_ = time; }
    void setProduct(bool enabled, int step) { product_ = enabled; productStep_ = step; }
    bool productActive() const { return product_; }
    void setEditor(bool enabled) { editor_ = enabled; }
    bool editorActive() const { return editor_; }
    int productStep() const { return productStep_; }
    bool oceanActive() const { return ocean_; }
    float oceanTime() const { return oceanTime_; }
    int streamSerial() const { return streamSerial_; }
    int residentCount() const { return slotN_; }
    bool residentHas(int cx, int cz) const;
    size_t chunkVertexCount() const { return chunkVertices_.size(); }
    bool chunkSeamsExact() const { return seamsExact_; }
    bool chunkOrderIndependent() const { return orderIndependent_; }
    uint64_t chunkGridHash() const { return gridHash_; }
    double chunkBuildMs() const { return buildMs_; }
    
    // Access to WorldForge systems
    kg::World& getWorld() { return world_; }
    
    // Scene management
    void saveScene(const std::string& path);
    void loadScene(const std::string& path);
    
    // Vehicle control
    struct VehicleCommand {
        float throttle = 0.0f;
        float steer = 0.0f;
        bool fire = false;
    };
    
    void setVehicleCommand(const VehicleCommand& cmd);
    
private:
    uint64_t seed_;
    std::string biome_;
    kg::World world_;
    bool initialized_ = false;
    bool chunkGrid_ = false;
    bool seamsExact_ = false;
    bool orderIndependent_ = false;
    uint64_t gridHash_ = 0;
    double buildMs_ = 0;
    int slotCx_[25]{};
    int slotCz_[25]{};
    int slotN_ = 0;
    int streamSerial_ = 0;
    int centerCx_ = 99;
    int centerCz_ = 99;
    bool ocean_ = false;
    float oceanTime_ = 0.0f;
    bool product_ = false;
    bool editor_ = false;
    int productStep_ = 0;
    std::vector<HeightEdit> edits_;
    std::vector<Vertex> chunkVertices_;
    std::vector<uint32_t> chunkIndices_;
    void markChunkOrigin();
};
