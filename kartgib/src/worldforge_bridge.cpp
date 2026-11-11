#include "worldforge_bridge.hpp"
#include "ocean_field.hpp"
#include "product_scene.hpp"
#include "editor_api.hpp"
#include <iostream>
#include <cmath>
#include <algorithm>

WorldForgeBridge::WorldForgeBridge() : seed_(0), initialized_(false) {}

WorldForgeBridge::~WorldForgeBridge() {}

void WorldForgeBridge::initialize(uint64_t seed, const std::string& biome) {
    seed_ = seed;
    biome_ = biome;
    
    kg::Settings settings;
    settings.seed = seed;
    
    if (biome == "tropical") settings.biome = kg::Biome::Tropical;
    else if (biome == "gothic") settings.biome = kg::Biome::Gothic;
    else if (biome == "voxel") settings.biome = kg::Biome::Voxel;
    else if (biome == "floating") settings.biome = kg::Biome::Floating;
    else settings.biome = kg::Biome::Tropical;
    
    settings.terrainResolution = 129;
    settings.trackSamples = 256;
    settings.worldSize = 2048;
    settings.propCount = 800;
    
    world_ = kg::generate(settings);
    
    initialized_ = true;
    std::cout << "WorldForge initialized: seed=" << seed << ", biome=" << biome << std::endl;
    std::cout << "Terrain: " << world_.terrain.vertices.size() << " vertices, "
              << world_.terrain.indices.size() << " indices" << std::endl;
    std::cout << "Road: " << world_.road.vertices.size() << " vertices, "
              << world_.road.indices.size() << " indices" << std::endl;
    std::cout << "Props: " << world_.instances.size() << " instances" << std::endl;
}

WorldForgeBridge::MeshResult WorldForgeBridge::generateTerrainMesh() {
    MeshResult result;
    if (chunkGrid_) {
        result.vertices = chunkVertices_;
        result.indices = chunkIndices_;
        return result;
    }
    
    const auto& mesh = world_.terrain;
    
    // Convert kg::Mesh vertices to VulkanRenderer::Vertex
    result.vertices.reserve(mesh.vertices.size());
    for (const auto& v : mesh.vertices) {
        Vertex bv;
        bv.pos[0] = static_cast<float>(v.p.x);
        bv.pos[1] = static_cast<float>(v.p.y);
        bv.pos[2] = static_cast<float>(v.p.z);
        bv.normal[0] = static_cast<float>(v.n.x);
        bv.normal[1] = static_cast<float>(v.n.y);
        bv.normal[2] = static_cast<float>(v.n.z);
        bv.uv[0] = v.u;
        bv.uv[1] = v.v;
        result.vertices.push_back(bv);
    }
    
    // Copy indices
    result.indices = mesh.indices;
    studioApplyStamps(result.vertices);
    if (ocean_) {
        OceanField field;
        OceanParams params;
        buildOcean(params, oceanTime_, field);
        appendOceanMesh(result.vertices, result.indices, field);
    }
    if (product_) appendProductScene(result.vertices, result.indices, *this);
    if (editor_) editorAppend(result.vertices, result.indices);
    return result;
}

void WorldForgeBridge::saveScene(const std::string& path) {
    kg::exportManifest(world_, path);
    std::cout << "Scene saved to: " << path << "\n";
}

void WorldForgeBridge::loadScene(const std::string& path) {
    std::cout << "Scene load not yet implemented: " << path << "\n";
}

void WorldForgeBridge::setVehicleCommand(const VehicleCommand& cmd) {
    // Vehicle commands will be passed to the game loop
    // This is a placeholder for future integration with WorldForge vehicle physics
}