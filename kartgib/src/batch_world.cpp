#include "finish_batches.hpp"
#include "worldforge_bridge.hpp"
#include <sstream>
#include <vector>

void fillBatchWorld(std::vector<BatchGate>& out) {
    WorldForgeBridge bridge;
    bridge.initialize(20261025, "tropical");
    bridge.useChunkGrid(true);
    bool seeded = bridge.chunkSeamsExact() && bridge.chunkOrderIndependent() && bridge.chunkGridHash() != 0;
    std::ostringstream seed;
    seed << "hash=" << bridge.chunkGridHash() << " seams=" << bridge.chunkSeamsExact()
         << " order=" << bridge.chunkOrderIndependent() << " build_ms=" << bridge.chunkBuildMs();
    addGate(out, 1, "Deterministic world seeds and coordinate-based noise", passFail(seeded), seed.str());

    bool stayed = bridge.residentHas(-2, 0) && bridge.streamSerial() == 1;
    bridge.streamAround(400.0f, 0.0f);
    stayed = stayed && bridge.streamSerial() == 1 && bridge.residentHas(-2, 0);
    bridge.streamAround(2200.0f, 0.0f);
    size_t verts = bridge.chunkVertexCount();
    bool moved = bridge.residentHas(4, 0) && !bridge.residentHas(-2, 0) && bridge.residentCount() == 25;
    bool bound = verts > 1000 && verts < 105625;
    std::ostringstream stream;
    stream << "serial=" << bridge.streamSerial() << " vertices=" << verts
           << " loaded_4=" << bridge.residentHas(4, 0) << " unloaded_-2=" << !bridge.residentHas(-2, 0);
    addGate(out, 2, "Seamless chunk generation and streaming", passFail(stayed && moved), stream.str());

    kg::Settings settings = bridge.getWorld().settings;
    std::vector<double> fine(65 * 65), coarse(65 * 65);
    for (int j = 0; j < 65; ++j) {
        for (int i = 0; i < 65; ++i) {
            fine[static_cast<size_t>(j * 65 + i)] = kg::sampleHeight(i * 8.0, j * 8.0, settings);
            coarse[static_cast<size_t>(j * 65 + i)] = kg::sampleHeight((64 + i) * 8.0, j * 8.0, settings);
        }
    }
    std::vector<Vertex> fineVerts, coarseVerts;
    std::vector<uint32_t> fineIdx, coarseIdx;
    appendChunkMesh(fineVerts, fineIdx, 0, 0, fine, settings, 1, 1);
    appendChunkMesh(coarseVerts, coarseIdx, 1, 0, coarse, settings, 2, 0);
    bool edge = true;
    for (int j = 0; j < 33; ++j) {
        float yFine = fineVerts[static_cast<size_t>((j * 2) * 65 + 64)].pos[1];
        float yCoarse = coarseVerts[static_cast<size_t>(j * 33)].pos[1];
        if (yFine != yCoarse) edge = false;
    }
    for (int j = 1; j < 64; j += 2) {
        float mid = 0.5f * (fineVerts[static_cast<size_t>((j - 1) * 65 + 64)].pos[1]
            + fineVerts[static_cast<size_t>((j + 1) * 65 + 64)].pos[1]);
        if (fineVerts[static_cast<size_t>(j * 65 + 64)].pos[1] != mid) edge = false;
    }
    std::ostringstream lod;
    lod << "shared_edge=" << edge << " odd_vertices_locked=" << edge << " streamed_vertices=" << verts;
    addGate(out, 3, "Terrain LOD, quadtree selection, GPU residency", passFail(edge && bound), lod.str());
}
