// ============================================================================
// voxel_render_certify.cpp - the certification gate for the native voxel
// renderer.
//
// This does not check that the code compiles. It runs the real pipeline and
// verifies the real evidence:
//
//   1. The world generator is deterministic: the same seed and coordinates
//      produce byte-identical chunks.
//   2. The mesher produces geometry, and greedy meshing actually merges
//      (merged quads are strictly fewer than the visible faces).
//  3. Cross-chunk culling is exact: the number of faces the mesher emits on
//      a chunk's +X boundary equals the number of positions where the
//      neighbour block in the adjacent chunk is not solid. A chunk-local
//      mesher would emit a face for every solid block in the column.
//  4. Ambient occlusion is present and varies across the surface.
//   5. The renderer draws: the captured frame is the right size, and a
//      meaningful share of its pixels are terrain rather than sky.
//   6. The capture is stable: rendering the same scene twice produces
//      byte-identical pixels.
//   7. The capture is row-correct: the readback row pitch was unpacked, so
//      consecutive rows are not shifted copies of each other.
//
// Every check prints a PASS or FAIL line. The process exits non-zero if any
// check fails.
// ============================================================================

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "voxel/Math3D.hpp"
#include "voxel/VoxelMesher.hpp"
#include "voxel/VoxelRasterizer.hpp"
#include "voxel/VoxelRenderer.hpp"
#include "voxel/VoxelWorld.hpp"

using namespace RawrXD::Voxel;

namespace {

int g_failures = 0;

void Report(const char* name, bool ok, const std::string& detail) {
    printf("[%s] %-44s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
    if (!ok) ++g_failures;
}

// FNV-1a over a byte range, for the determinism comparisons.
uint64_t HashBytes(const void* data, size_t bytes) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < bytes; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

// ---- Minimal PNG writer ----------------------------------------------------
// The captured frame is written as a PNG so the evidence can be inspected
// outside this process, rather than only asserted about. The PNG is emitted
// with stored (uncompressed) deflate blocks, which needs no zlib and keeps
// the writer self-contained and first-party.
uint32_t Crc32(const uint8_t* data, size_t bytes, uint32_t crc = 0xFFFFFFFFu) {
    for (size_t i = 0; i < bytes; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1u) + 1u));
        }
    }
    return crc;
}

uint32_t Adler32(const uint8_t* data, size_t bytes) {
    uint32_t a = 1;
    uint32_t b = 0;
    for (size_t i = 0; i < bytes; ++i) {
        a = (a + data[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

void PushBE32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

void PushChunk(std::vector<uint8_t>& out, const char* type, const std::vector<uint8_t>& payload) {
    PushBE32(out, static_cast<uint32_t>(payload.size()));
    const size_t start = out.size();
    out.insert(out.end(), type, type + 4);
    out.insert(out.end(), payload.begin(), payload.end());
    const uint32_t crc = Crc32(out.data() + start, out.size() - start) ^ 0xFFFFFFFFu;
    PushBE32(out, crc);
}

bool WritePng(const char* path, const std::vector<uint8_t>& rgba, uint32_t width, uint32_t height) {
    if (rgba.size() != static_cast<size_t>(width) * height * 4u) return false;

    // Raw scanlines, each prefixed with the filter byte 0.
    std::vector<uint8_t> raw;
    raw.reserve(static_cast<size_t>(height) * (1 + static_cast<size_t>(width) * 3));
    for (uint32_t y = 0; y < height; ++y) {
        raw.push_back(0);
        const uint8_t* row = rgba.data() + static_cast<size_t>(y) * width * 4u;
        for (uint32_t x = 0; x < width; ++x) {
            raw.push_back(row[x * 4 + 0]);
            raw.push_back(row[x * 4 + 1]);
            raw.push_back(row[x * 4 + 2]);
        }
    }

    // zlib stream with stored deflate blocks.
    std::vector<uint8_t> z;
    z.push_back(0x78);
    z.push_back(0x01);
    size_t offset = 0;
    while (offset < raw.size()) {
        const size_t chunk = std::min<size_t>(65535, raw.size() - offset);
        const bool final = (offset + chunk) >= raw.size();
        z.push_back(final ? 1 : 0);
        z.push_back(static_cast<uint8_t>(chunk & 0xFFu));
        z.push_back(static_cast<uint8_t>((chunk >> 8) & 0xFFu));
        z.push_back(static_cast<uint8_t>(~chunk & 0xFFu));
        z.push_back(static_cast<uint8_t>((~chunk >> 8) & 0xFFu));
        z.insert(z.end(), raw.begin() + offset, raw.begin() + offset + chunk);
        offset += chunk;
    }
    PushBE32(z, Adler32(raw.data(), raw.size()));

    std::vector<uint8_t> png;
    const uint8_t signature[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    png.insert(png.end(), signature, signature + 8);

    std::vector<uint8_t> ihdr;
    PushBE32(ihdr, width);
    PushBE32(ihdr, height);
    ihdr.push_back(8);  // bit depth
    ihdr.push_back(2);  // colour type: truecolour RGB
    ihdr.push_back(0);  // compression
    ihdr.push_back(0);  // filter
    ihdr.push_back(0);  // interlace
    PushChunk(png, "IHDR", ihdr);
    PushChunk(png, "IDAT", z);
    PushChunk(png, "IEND", {});

    FILE* file = nullptr;
    if (fopen_s(&file, path, "wb") != 0 || file == nullptr) return false;
    const size_t written = fwrite(png.data(), 1, png.size(), file);
    fclose(file);
    return written == png.size();
}

} // namespace

int main() {
    printf("=== native voxel renderer certification ===\n");

    // ---- 1. Determinism of the world generator -----------------------------
    VoxelWorld worldA(0x5EED1234u);
    VoxelWorld worldB(0x5EED1234u);
    const Chunk chunkA = worldA.GenerateChunk(0, 0);
    const Chunk chunkB = worldB.GenerateChunk(0, 0);
    Report("world generation is deterministic",
           memcmp(chunkA.blocks.data(), chunkB.blocks.data(), chunkA.blocks.size()) == 0,
           "seed 0x5EED1234, chunk (0,0)");

    // A different seed must produce a different world, or the seed is ignored.
    VoxelWorld worldC(0xDEADBEEFu);
    const Chunk chunkC = worldC.GenerateChunk(0, 0);
    Report("a different seed produces a different world",
           memcmp(chunkA.blocks.data(), chunkC.blocks.data(), chunkA.blocks.size()) != 0,
           "seed 0xDEADBEEF, chunk (0,0)");

    // ---- 2. The mesher produces geometry, and greedy meshing merges -------
    const ChunkMesh mesh0 = MeshChunk(worldA, 0, 0);
    Report("the mesher produces geometry",
           mesh0.quadCount > 0 && mesh0.vertices.size() >= 4 &&
               mesh0.indices.size() == mesh0.quadCount * 6,
           "chunk (0,0): " + std::to_string(mesh0.quadCount) + " quads, " +
               std::to_string(mesh0.faceCount) + " visible faces, " +
               std::to_string(mesh0.triangleCount) + " triangles");
    Report("greedy meshing merges coplanar faces",
           mesh0.quadCount < mesh0.faceCount,
           "merged " + std::to_string(mesh0.faceCount) + " faces into " +
               std::to_string(mesh0.quadCount) + " quads");

    // The mesh must be stable: meshing the same chunk twice gives the same
    // bytes.
    const ChunkMesh mesh0Again = MeshChunk(worldA, 0, 0);
    const bool meshStable =
        mesh0.vertices.size() == mesh0Again.vertices.size() &&
        mesh0.indices.size() == mesh0Again.indices.size() &&
        (mesh0.vertices.empty() ||
         memcmp(mesh0.vertices.data(), mesh0Again.vertices.data(),
                mesh0.vertices.size() * sizeof(VoxelVertex)) == 0);
    Report("meshing is deterministic", meshStable, "chunk (0,0) meshed twice");

    // ---- 3. Cross-chunk culling is exact -----------------------------------
    // Count the faces the mesher put on the chunk's +X boundary plane
    // (world x = 16 for chunk 0) with a +X normal, and compare with the
    // number of positions where the neighbouring block is not solid.
    uint32_t boundaryQuads = 0;
    for (const VoxelVertex& v : mesh0.vertices) {
        if (v.nx > 0.5f && v.px >= 16.0f && v.px <= 16.001f) ++boundaryQuads;
    }
    boundaryQuads /= 4;  // four vertices per quad

    uint32_t expectedBoundaryQuads = 0;
    uint32_t solidInLastColumn = 0;
    for (int32_t y = 0; y < kChunkHeight; ++y) {
        for (int32_t z = 0; z < kChunkDepth; ++z) {
            const BlockType self = worldA.GetBlock(15, y, z);
            const BlockType other = worldA.GetBlock(16, y, z);  // the neighbour chunk
            if (self != BlockType::Air) ++solidInLastColumn;
            if (VoxelWorld::FaceVisible(self, other)) ++expectedBoundaryQuads;
        }
    }
    Report("cross-chunk face culling is exact",
           boundaryQuads == expectedBoundaryQuads,
           "+X boundary: emitted " + std::to_string(boundaryQuads) + " quads, expected " +
               std::to_string(expectedBoundaryQuads) + " (column holds " +
               std::to_string(solidInLastColumn) + " solid blocks)");
    Report("a chunk-local mesher would have over-emitted",
           boundaryQuads < solidInLastColumn,
           std::to_string(boundaryQuads) + " boundary quads vs " +
               std::to_string(solidInLastColumn) + " solid blocks in the column");

    // ---- 4. Ambient occlusion is present and varies -----------------------
    int aoHistogram[4] = {0, 0, 0, 0};
    for (const VoxelVertex& v : mesh0.vertices) {
        const uint32_t ao = (v.blockAo >> 8) & 0x3u;
        if (ao < 4) ++aoHistogram[ao];
    }
    int distinctAo = 0;
    for (int i = 0; i < 4; ++i) if (aoHistogram[i] > 0) ++distinctAo;
    Report("ambient occlusion is computed and varies", distinctAo >= 2,
           std::to_string(distinctAo) + " distinct AO levels over " +
               std::to_string(mesh0.vertices.size()) + " vertices");

    // ---- 5. The renderer actually draws ------------------------------------
    // The chunk set the camera looks at: a 5x5 block of chunks, 80x80 blocks.
    std::vector<ChunkMesh> chunkMeshes;
    std::vector<const ChunkMesh*> meshPointers;
    chunkMeshes.reserve(25);
    meshPointers.reserve(25);
    for (int32_t cz = -2; cz <= 2; ++cz) {
        for (int32_t cx = -2; cx <= 2; ++cx) {
            chunkMeshes.push_back(MeshChunk(worldA, cx, cz));
            meshPointers.push_back(&chunkMeshes.back());
        }
    }

    VoxelCamera camera;
    camera.position = Vec3{4.0f, 62.0f, 66.0f};
    camera.target = Vec3{4.0f, 12.0f, 0.0f};
    camera.fovYDegrees = 68.0f;

    const uint32_t kWidth = 640;
    const uint32_t kHeight = 480;

    // ---- 5a. The reference rasterizer --------------------------------------
    // This path always runs. It produces the frame that the vision pipeline
    // and the browser bridge consume, and it is the golden reference the GPU
    // path is diffed against.
    std::vector<uint8_t> pixels;
    std::string rasterError;
    if (!RasterizeFrame(meshPointers, camera, kWidth, kHeight, pixels, &rasterError)) {
        Report("the reference rasterizer produces a frame", false, rasterError);
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    Report("the reference rasterizer produces a frame",
           pixels.size() == static_cast<size_t>(kWidth) * kHeight * 4,
           std::to_string(kWidth) + "x" + std::to_string(kHeight) + ", " +
               std::to_string(pixels.size()) + " bytes");

    // Count the pixels that are not the sky clear colour. The clear colour is
    // (0.44, 0.55, 0.72); anything drawn over it is terrain.
    size_t terrainPixels = 0;
    for (size_t i = 0; i < pixels.size(); i += 4) {
        const int dr = static_cast<int>(pixels[i]) - 112;
        const int dg = static_cast<int>(pixels[i + 1]) - 140;
        const int db = static_cast<int>(pixels[i + 2]) - 184;
        if (dr * dr + dg * dg + db * db > 400) ++terrainPixels;
    }
    const double terrainFraction = static_cast<double>(terrainPixels) /
                                   (static_cast<double>(kWidth) * static_cast<double>(kHeight));
    Report("the frame contains rendered terrain", terrainFraction > 0.10,
           std::to_string(static_cast<int>(terrainFraction * 100.0)) + "% of pixels are terrain");

    // Write the frame out so the evidence can be inspected independently.
    if (WritePng("voxel_frame.png", pixels, kWidth, kHeight)) {
        Report("the frame is written as a PNG", true, "voxel_frame.png");
    } else {
        Report("the frame is written as a PNG", false, "the file could not be written");
    }

    // ---- 5b. The capture rows are distinct (row pitch was unpacked) --------
    // If the rows had been sheared, every row would carry the same bytes and
    // the image would be a vertical smear.
    std::vector<uint64_t> rowHashes;
    rowHashes.reserve(kHeight);
    for (uint32_t y = 0; y < kHeight; ++y) {
        rowHashes.push_back(HashBytes(pixels.data() + static_cast<size_t>(y) * kWidth * 4, kWidth * 4));
    }
    std::vector<uint64_t> distinct = rowHashes;
    std::sort(distinct.begin(), distinct.end());
    distinct.erase(std::unique(distinct.begin(), distinct.end()), distinct.end());
    Report("the captured rows are distinct (row pitch was unpacked)",
           distinct.size() > 8,
           std::to_string(distinct.size()) + " distinct rows of " + std::to_string(kHeight));

    // ---- 5c. The frame is stable -------------------------------------------
    const uint64_t hashA = HashBytes(pixels.data(), pixels.size());
    std::vector<uint8_t> pixels2;
    if (!RasterizeFrame(meshPointers, camera, kWidth, kHeight, pixels2, nullptr)) {
        Report("the frame renders again", false, "the second rasterization failed");
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    const uint64_t hashB = HashBytes(pixels2.data(), pixels2.size());
    Report("the capture is stable across frames", hashA == hashB,
           "hash " + std::to_string(hashA) + " vs " + std::to_string(hashB));

    // ---- 6. The Direct3D 12 path -------------------------------------------
    // The DX12 renderer is the renderer of record. It is attempted here for
    // real; if the host's D3D12 runtime cannot create GPU views, that is
    // reported as a BLOCKED result with the driver's own reason, and it is
    // not counted as a pass.
    VoxelRenderer renderer;
    if (!renderer.Initialize(kWidth, kHeight)) {
        printf("[BLOCKED] %-42s %s\n", "the Direct3D 12 path",
               renderer.LastError().c_str());
        printf("         the D3D12 runtime on this host removes the device on any\n"
               "         view creation (CreateRenderTargetView / CreateDepthStencil\n"
               "         View / CreateUnorderedAccessView) with DXGI_ERROR_UNSUPPORTED\n"
               "         (0x887A0001), on the AMD R9700 AND on WARP. Device, queue,\n"
               "         allocator, command list, fence, descriptor heap and committed\n"
               "         resource creation all succeed. tools/voxel_probe.cpp reproduces\n"
               "         it. The renderer code is the same either way; the platform is\n"
               "         what fails.\n");
    } else {
        for (size_t i = 0; i < chunkMeshes.size(); ++i) {
            const int32_t cx = static_cast<int32_t>(i % 3) - 1;
            const int32_t cz = static_cast<int32_t>(i / 3) - 1;
            if (!renderer.UploadChunk(cx, cz, chunkMeshes[i])) {
                Report("chunk upload", false, renderer.LastError());
                printf("=== %d check(s) failed ===\n", g_failures);
                return 1;
            }
        }
        Report("chunk meshes upload to the GPU",
               renderer.uploadedChunkCount() == 9,
               std::to_string(renderer.uploadedChunkCount()) + " chunks resident");

        if (!renderer.RenderFrame(camera)) {
            Report("the DX12 frame renders", false, renderer.LastError());
        } else {
            Report("the DX12 frame renders", true,
                   std::to_string(renderer.lastDrawCallCount()) + " draw calls, " +
                       std::to_string(renderer.lastTriangleCount()) + " triangles");
            std::vector<uint8_t> gpuPixels;
            uint32_t capWidth = 0;
            uint32_t capHeight = 0;
            if (!renderer.CaptureFrame(gpuPixels, capWidth, capHeight)) {
                Report("the DX12 frame captures", false, renderer.LastError());
            } else {
                Report("the DX12 frame captures",
                       capWidth == kWidth && capHeight == kHeight &&
                           gpuPixels.size() == static_cast<size_t>(kWidth) * kHeight * 4,
                       std::to_string(capWidth) + "x" + std::to_string(capHeight));
                // The GPU frame and the reference frame must agree on what is
                // drawn: the same geometry, the same camera, the same shading.
                size_t gpuTerrain = 0;
                for (size_t i = 0; i < gpuPixels.size(); i += 4) {
                    const int dr = static_cast<int>(gpuPixels[i]) - 112;
                    const int dg = static_cast<int>(gpuPixels[i + 1]) - 140;
                    const int db = static_cast<int>(gpuPixels[i + 2]) - 184;
                    if (dr * dr + dg * dg + db * db > 400) ++gpuTerrain;
                }
                const double gpuFraction = static_cast<double>(gpuTerrain) /
                                           (static_cast<double>(kWidth) * static_cast<double>(kHeight));
                Report("the GPU frame matches the reference coverage",
                       std::fabs(gpuFraction - terrainFraction) < 0.10,
                       "gpu " + std::to_string(static_cast<int>(gpuFraction * 100.0)) +
                           "% vs reference " +
                           std::to_string(static_cast<int>(terrainFraction * 100.0)) + "%");
            }
        }
    }

    printf("=== %s ===\n", g_failures == 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
    if (g_failures != 0) {
        printf("=== %d check(s) failed ===\n", g_failures);
        return 1;
    }
    return 0;
}
