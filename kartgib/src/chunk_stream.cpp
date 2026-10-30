#include "worldforge_bridge.hpp"
#include <cmath>
#include <iostream>
#include <vector>

static std::vector<double> fillChunkHeights(int cx, int cz, const kg::Settings& settings) {
    constexpr int n = 65;
    std::vector<double> h(static_cast<size_t>(n * n));
    for (int j = 0; j < n; ++j) {
        for (int i = 0; i < n; ++i) {
            h[static_cast<size_t>(j * n + i)] = kg::sampleHeight((cx * 64 + i) * 8.0, (cz * 64 + j) * 8.0, settings);
        }
    }
    return h;
}

void WorldForgeBridge::markChunkOrigin() {
    centerCx_ = 0;
    centerCz_ = 0;
    slotN_ = 0;
    streamSerial_ = 1;
    for (int cz = -2; cz <= 2; ++cz) {
        for (int cx = -2; cx <= 2; ++cx) {
            slotCx_[slotN_] = cx;
            slotCz_[slotN_] = cz;
            ++slotN_;
        }
    }
}

void WorldForgeBridge::streamAround(float x, float z) {
    int ccx = static_cast<int>(std::floor(x / 512.0f));
    int ccz = static_cast<int>(std::floor(z / 512.0f));
    if (ccx == centerCx_ && ccz == centerCz_ && slotN_ == 25) return;
    centerCx_ = ccx;
    centerCz_ = ccz;
    chunkVertices_.clear();
    chunkIndices_.clear();
    slotN_ = 0;
    auto coarse = [&](int nx, int nz) { return std::abs(nx - ccx) > 1 || std::abs(nz - ccz) > 1; };
    for (int cz = ccz - 2; cz <= ccz + 2; ++cz) {
        for (int cx = ccx - 2; cx <= ccx + 2; ++cx) {
            int step = coarse(cx, cz) ? 2 : 1;
            int mask = 0;
            if (step == 1) {
                if (coarse(cx + 1, cz)) mask |= 1;
                if (coarse(cx - 1, cz)) mask |= 2;
                if (coarse(cx, cz + 1)) mask |= 4;
                if (coarse(cx, cz - 1)) mask |= 8;
            }
            appendChunkMesh(chunkVertices_, chunkIndices_, cx, cz, fillChunkHeights(cx, cz, world_.settings), world_.settings, step, mask);
            slotCx_[slotN_] = cx;
            slotCz_[slotN_] = cz;
            ++slotN_;
        }
    }
    ++streamSerial_;
    std::cout << "[STREAM] center=" << ccx << "," << ccz << " resident=" << slotN_
              << " vertices=" << chunkVertices_.size() << " serial=" << streamSerial_ << std::endl;
}

bool WorldForgeBridge::residentHas(int cx, int cz) const {
    for (int i = 0; i < slotN_; ++i) {
        if (slotCx_[i] == cx && slotCz_[i] == cz) return true;
    }
    return false;
}
