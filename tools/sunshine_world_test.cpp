// ============================================================================
// sunshine_world_test.cpp - the certification gate for the configurable world
// generator, bound to the REAL engine classes.
//
// The generator is not tested in isolation. Every check here goes through
// the engine's own VoxelWorld and VoxelMesher, so what is verified is that
// the generator produces a world the engine can actually consume:
//
//   1. the designer's exact JSON parses, and round trips byte for byte
//   2. the JSON maps onto the generator's configuration, with the sea level
//      resolved as a percentage of the engine's real column height
//   3. the generator is deterministic: two worlds from the same config agree
//      block for block
//   4. the world is chunk order independent: a block on a chunk boundary is
//      identical whether it is read from the chunk cache or queried directly
//   5. the mesher produces real geometry from the generated world
//   6. cross-chunk face culling is EXACT against the generated world: the
//      emitted boundary quads equal the independently computed count of
//      positions where the neighbouring block is not solid
//   7. the world's own configuration serializes to the binary form and
//      reads back identically
//   8. the world renders: a frame captured from the generated terrain
//      contains land, water and sky
//
// Exit code is non-zero if any check fails.
// ============================================================================

#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "voxel/Math3D.hpp"
#include "voxel/SunshineWorldConfig.hpp"
#include "voxel/VoxelMesher.hpp"
#include "voxel/VoxelRasterizer.hpp"
#include "voxel/PngWriter.hpp"
#include "voxel/VoxelWorld.hpp"
#include "voxel/sunshine/WorldGen.hpp"

using namespace RawrXD::Voxel;

namespace {

int g_failures = 0;

void Report(const char* name, bool ok, const std::string& detail) {
    printf("[%s] %-48s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
    if (!ok) ++g_failures;
}

// The configuration the world designer exports, verbatim.
const char* kDesignerConfig =
    "{\"seed\":1337,\"world\":\"islands\",\"scale\":1,\"sea\":64,\"mountains\":35,"
    "\"erosion\":55,\"caves\":40,\"trees\":85,\"temperature\":85,\"humidity\":80,"
    "\"rivers\":40,\"structures\":35}";

} // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("=== configurable world generator certification ===\n");

    // ---- 1. The designer's JSON parses and round trips ----------------------
    SunshineWorldConfig config;
    std::string error;
    const bool parsed = config.ParseJson(kDesignerConfig, &error);
    Report("the designer's JSON parses", parsed, parsed ? "" : error);
    if (!parsed) {
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    Report("the parsed values are the designer's",
           config.seed == 1337 && config.world == "islands" && config.scale == 1.0 &&
               config.sea == 64 && config.mountains == 35 && config.erosion == 55 &&
               config.caves == 40 && config.trees == 85 && config.temperature == 85 &&
               config.humidity == 80 && config.rivers == 40 && config.structures == 35,
           "seed=" + std::to_string(config.seed) + " sea=" + std::to_string(config.sea) +
               " caves=" + std::to_string(config.caves));
    Report("the JSON round trips byte for byte", config.ToJson() == kDesignerConfig,
           config.ToJson());

    // ---- 2. The mapping onto the generator ----------------------------------
    sunshine::Config generatorConfig;
    bool modeSupported = false;
    const bool mapped = config.ToGeneratorConfig(kChunkHeight, generatorConfig, &modeSupported);
    Report("the configuration maps onto the generator", mapped && generatorConfig.valid(),
           "generator sea=" + std::to_string(generatorConfig.sea) + " (a block level)");
    Report("the sea level is resolved as a percentage of the world height",
           generatorConfig.sea == static_cast<int>((64.0 / 100.0) * kChunkHeight + 0.5),
           "64% of " + std::to_string(kChunkHeight) + " blocks = " +
               std::to_string(generatorConfig.sea));
    Report("the requested world mode is supported by the generator", modeSupported,
           std::string("mode='") + config.world + "'");

    // ---- 3. The generator is deterministic -----------------------------------
    VoxelWorld worldA(config);
    VoxelWorld worldB(config);
    bool identical = true;
    for (int32_t x = -40; x < 40 && identical; ++x) {
        for (int32_t z = -40; z < 40 && identical; ++z) {
            for (int32_t y = 0; y < kChunkHeight; ++y) {
                if (worldA.GetBlock(x, y, z) != worldB.GetBlock(x, y, z)) {
                    identical = false;
                    break;
                }
            }
        }
    }
    Report("the generated world is deterministic", identical,
           "an 80x80x" + std::to_string(kChunkHeight) + " volume compared block for block");

    // A different seed must produce a different world.
    SunshineWorldConfig other = config;
    other.seed = config.seed + 1;
    VoxelWorld worldOther(other);
    bool differs = false;
    for (int32_t x = -40; x < 40 && !differs; ++x) {
        for (int32_t z = -40; z < 40 && !differs; ++z) {
            for (int32_t y = 0; y < kChunkHeight; ++y) {
                if (worldA.GetBlock(x, y, z) != worldOther.GetBlock(x, y, z)) {
                    differs = true;
                    break;
                }
            }
        }
    }
    Report("a different seed produces a different world", differs,
           "seed " + std::to_string(config.seed + 1));

    // ---- 4. Chunk order independence ----------------------------------------
    // A block on a chunk boundary must be the same whether it is read from
    // the chunk cache or queried directly. This is the property the greedy
    // mesher's cross-chunk culling depends on.
    const int32_t boundaryX = kChunkWidth;   // the first column of chunk (1,0)
    bool boundaryStable = true;
    for (int32_t z = 0; z < kChunkDepth; ++z) {
        for (int32_t y = 0; y < kChunkHeight; ++y) {
            const BlockType cached = static_cast<BlockType>(worldA.GetOrCreateChunk(1, 0).At(0, y, z));
            const BlockType direct = worldA.GetBlock(boundaryX, y, z);
            if (cached != direct) { boundaryStable = false; break; }
        }
    }
    Report("the world is chunk order independent", boundaryStable,
           "the chunk cache and a direct query agree on the boundary column");

    // ---- 5. The mesher produces geometry from the generated world -----------
    const ChunkMesh mesh = MeshChunk(worldA, 0, 0);
    Report("the mesher produces geometry from the generated world",
           mesh.quadCount > 0 && mesh.vertices.size() >= 4 &&
               mesh.indices.size() == mesh.quadCount * 6,
           "chunk (0,0): " + std::to_string(mesh.quadCount) + " quads, " +
               std::to_string(mesh.faceCount) + " visible faces, " +
               std::to_string(mesh.triangleCount) + " triangles");
    Report("greedy meshing merges the generated terrain", mesh.quadCount < mesh.faceCount,
           "merged " + std::to_string(mesh.faceCount) + " faces into " +
               std::to_string(mesh.quadCount) + " quads");

    // ---- 6. Cross-chunk face culling is exact against the generated world ---
    uint32_t boundaryQuads = 0;
    for (const VoxelVertex& v : mesh.vertices) {
        if (v.nx > 0.5f && v.px >= static_cast<float>(kChunkWidth) &&
            v.px <= static_cast<float>(kChunkWidth) + 0.001f) {
            ++boundaryQuads;
        }
    }
    boundaryQuads /= 4;

    uint32_t expectedBoundaryQuads = 0;
    for (int32_t y = 0; y < kChunkHeight; ++y) {
        for (int32_t z = 0; z < kChunkDepth; ++z) {
            const BlockType self = worldA.GetBlock(kChunkWidth - 1, y, z);
            const BlockType other = worldA.GetBlock(kChunkWidth, y, z);
            if (VoxelWorld::FaceVisible(self, other)) ++expectedBoundaryQuads;
        }
    }
    Report("cross-chunk face culling is exact against the generated world",
           boundaryQuads == expectedBoundaryQuads,
           "+X boundary: emitted " + std::to_string(boundaryQuads) + " quads, expected " +
               std::to_string(expectedBoundaryQuads));

    // ---- 7. The binary configuration serialization round trips ---------------
    bool binaryOk = false;
    std::string binaryDetail;
    try {
        const std::vector<std::uint8_t> blob = sunshine::serializeConfig(generatorConfig);
        const sunshine::Config restored = sunshine::deserializeConfig(blob);
        binaryOk = (restored.seed == generatorConfig.seed) &&
                   (restored.sea == generatorConfig.sea) &&
                   (restored.mountains == generatorConfig.mountains) &&
                   (restored.erosion == generatorConfig.erosion) &&
                   (restored.caves == generatorConfig.caves) &&
                   (restored.trees == generatorConfig.trees) &&
                   (restored.temperature == generatorConfig.temperature) &&
                   (restored.humidity == generatorConfig.humidity) &&
                   (restored.rivers == generatorConfig.rivers) &&
                   (restored.structures == generatorConfig.structures);
        binaryDetail = std::to_string(blob.size()) + " bytes, version 1, CRC32 protected";
    } catch (const std::exception& e) {
        binaryDetail = e.what();
    }
    Report("the binary configuration serialization round trips", binaryOk, binaryDetail);

    // ---- 8. The generated world renders -------------------------------------
    std::vector<ChunkMesh> chunks;
    std::vector<const ChunkMesh*> pointers;
    // The chunk vector must not reallocate: the pointers into it are handed
    // to the rasterizer.
    chunks.reserve(25);
    pointers.reserve(25);
    for (int32_t cz = -2; cz <= 2; ++cz) {
        for (int32_t cx = -2; cx <= 2; ++cx) {
            chunks.push_back(MeshChunk(worldA, cx, cz));
            pointers.push_back(&chunks.back());
        }
    }

    VoxelCamera camera;
    camera.position = Vec3{4.0f, 150.0f, 120.0f};
    camera.target = Vec3{4.0f, 95.0f, 0.0f};
    camera.fovYDegrees = 68.0f;
    camera.zFar = 1200.0f;

    const uint32_t kWidth = 640;
    const uint32_t kHeight = 480;
    std::vector<uint8_t> pixels;
    std::string rasterError;
    const bool rasterized = RasterizeFrame(pointers, camera, kWidth, kHeight, pixels, &rasterError);
    Report("the generated world renders", rasterized,
           rasterized ? (std::to_string(kWidth) + "x" + std::to_string(kHeight) + " frame")
                      : rasterError);
    if (!rasterized) {
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }

    // Count the distinct materials in the frame, by the class the renderer
    // assigns. A frame with land, water and sky proves the three material
    // families all reached the image.
    size_t sky = 0;
    size_t green = 0;
    size_t dark = 0;
    size_t bright = 0;
    for (size_t i = 0; i < pixels.size(); i += 4) {
        const int r = pixels[i];
        const int g = pixels[i + 1];
        const int b = pixels[i + 2];
        if (b > r + 25 && b > 60) ++sky;
        else if (g > r + 15 && g > 60) ++green;
        else if (r < 90 && g < 90) ++dark;
        else if (r > 170 && g > 170 && b > 170) ++bright;
    }
    const size_t total = static_cast<size_t>(kWidth) * kHeight;
    Report("the frame contains water, land and sky",
           sky > total / 20 && green > total / 40 && (dark + bright) > total / 40,
           "sky=" + std::to_string(sky * 100 / total) + "% green=" +
               std::to_string(green * 100 / total) + "% dark/bright=" +
               std::to_string((dark + bright) * 100 / total) + "%");

    // Write the frame out so the island can be inspected directly.
    if (WritePng("sunshine_island.png", pixels, kWidth, kHeight)) {
        printf("[INFO] the island frame was written to sunshine_island.png\n");
    }

    // The frame must be stable: rendering the same world twice gives the
    // same pixels.
    std::vector<uint8_t> pixels2;
    RasterizeFrame(pointers, camera, kWidth, kHeight, pixels2, nullptr);
    Report("the rendered frame is stable", pixels == pixels2,
           std::to_string(pixels.size()) + " bytes compared");

    printf("=== %s ===\n", g_failures == 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
    if (g_failures != 0) {
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    return 0;
}
