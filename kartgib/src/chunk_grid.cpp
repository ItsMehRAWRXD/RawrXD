#include "worldforge_bridge.hpp"
#include <chrono>
#include <cmath>
#include <cstring>
#include <iostream>
#include <unordered_map>

static constexpr int kCells = 64;
static constexpr int kN = kCells + 1;
static constexpr double kCell = 8.0;

static double worldX(int cx, int i) { return (cx * kCells + i) * kCell; }
static double worldZ(int cz, int j) { return (cz * kCells + j) * kCell; }

static uint64_t hashHeights(const std::vector<double>& h) {
    uint64_t hash = 14695981039346656037ull;
    for (double y : h) {
        uint64_t bits = 0;
        static_assert(sizeof(double) == sizeof(uint64_t));
        std::memcpy(&bits, &y, sizeof(bits));
        hash ^= bits;
        hash *= 1099511628211ull;
    }
    return hash;
}

static std::vector<double> fillChunk(int cx, int cz, const kg::Settings& settings, uint64_t& hash) {
    std::vector<double> h(static_cast<size_t>(kN * kN));
    for (int j = 0; j < kN; ++j) {
        for (int i = 0; i < kN; ++i) {
            h[static_cast<size_t>(j * kN + i)] = kg::sampleHeight(worldX(cx, i), worldZ(cz, j), settings);
        }
    }
    hash = hashHeights(h);
    return h;
}

void WorldForgeBridge::useChunkGrid(bool enable) {
    chunkGrid_ = enable;
    if (!enable) return;
    auto start = std::chrono::steady_clock::now();
    std::unordered_map<int, uint64_t> forward;
    std::unordered_map<int, std::vector<double>> heights;
    auto key = [](int cx, int cz) { return (cx + 8) * 16 + (cz + 8); };
    for (int cz = -2; cz <= 2; ++cz) {
        for (int cx = -2; cx <= 2; ++cx) {
            uint64_t hash = 0;
            heights[key(cx, cz)] = fillChunk(cx, cz, world_.settings, hash);
            forward[key(cx, cz)] = hash;
            gridHash_ ^= hash;
        }
    }
    orderIndependent_ = true;
    for (int cz = 2; cz >= -2; --cz) {
        for (int cx = 2; cx >= -2; --cx) {
            uint64_t hash = 0;
            fillChunk(cx, cz, world_.settings, hash);
            if (hash != forward[key(cx, cz)]) orderIndependent_ = false;
        }
    }
    seamsExact_ = true;
    for (int cz = -2; cz <= 2; ++cz) {
        for (int cx = -2; cx <= 1; ++cx) {
            const auto& a = heights[key(cx, cz)];
            const auto& b = heights[key(cx + 1, cz)];
            for (int j = 0; j < kN; ++j) {
                if (a[static_cast<size_t>(j * kN + kCells)] != b[static_cast<size_t>(j * kN)]) seamsExact_ = false;
            }
        }
    }
    for (int cx = -2; cx <= 2; ++cx) {
        for (int cz = -2; cz <= 1; ++cz) {
            const auto& a = heights[key(cx, cz)];
            const auto& b = heights[key(cx, cz + 1)];
            for (int i = 0; i < kN; ++i) {
                if (a[static_cast<size_t>(kCells * kN + i)] != b[static_cast<size_t>(i)]) seamsExact_ = false;
            }
        }
    }
    chunkVertices_.clear();
    chunkIndices_.clear();
    for (int cz = -2; cz <= 2; ++cz) {
        for (int cx = -2; cx <= 2; ++cx) {
            appendChunkMesh(chunkVertices_, chunkIndices_, cx, cz, heights[key(cx, cz)], world_.settings, 1, 0);
        }
    }
    markChunkOrigin();
    buildMs_ = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    std::cout << "[CHUNK] seams=" << (seamsExact_ ? "PASS" : "FAIL")
              << " order=" << (orderIndependent_ ? "PASS" : "FAIL")
              << " hash=" << gridHash_ << " vertices=" << chunkVertices_.size()
              << " build_ms=" << buildMs_ << std::endl;
}
