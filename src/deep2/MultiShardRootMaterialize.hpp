#pragma once
/* B02: fread root/layer tensor bytes from owning shard. <=99. */
#include "Deep2Engine.h"
#include "K2GlobalTensorIndex.hpp"
#include <cstdio>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace multishard_bind {

inline int Materialize(WeightTensor& wt, const GlobalTensorIndex& idx,
                       int quiet = 0) {
    if (!wt.hasFileBacking || wt.sizeBytes == 0 || wt.name.empty()) return 0;
    if (wt.data) return 1;
    const auto& path = idx.ShardPath(wt.shardId);
    FILE* f = nullptr;
    if (fopen_s(&f, path.string().c_str(), "rb") != 0 || !f) {
        std::fprintf(stderr,
                     "B03_MAT_FAIL name=%s shard=%u why=OPEN path=%s\n",
                     wt.name.c_str(), wt.shardId, path.string().c_str());
        return 0;
    }
    if (_fseeki64(f, (long long)wt.fileOffset, SEEK_SET) != 0) {
        std::fprintf(stderr, "B03_MAT_FAIL name=%s shard=%u why=SEEK off=%llu\n",
                     wt.name.c_str(), wt.shardId,
                     (unsigned long long)wt.fileOffset);
        fclose(f);
        return 0;
    }
#ifdef _WIN32
    void* p = VirtualAlloc(nullptr, wt.sizeBytes, MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE);
#else
    void* p = nullptr;
#endif
    if (!p) {
        fclose(f);
        std::fprintf(stderr, "B03_MAT_FAIL name=%s shard=%u why=ALLOC bytes=%zu\n",
                     wt.name.c_str(), wt.shardId, wt.sizeBytes);
        return 0;
    }
    const size_t got = fread(p, 1, wt.sizeBytes, f);
    fclose(f);
    if (got != wt.sizeBytes) {
#ifdef _WIN32
        VirtualFree(p, 0, MEM_RELEASE);
#endif
        std::fprintf(stderr,
                     "B03_MAT_FAIL name=%s shard=%u why=READ got=%zu need=%zu\n",
                     wt.name.c_str(), wt.shardId, got, wt.sizeBytes);
        return 0;
    }
    wt.data = p;
    wt.mapped = true;
    if (!quiet) {
        const unsigned char* b = static_cast<const unsigned char*>(p);
        std::fprintf(stderr,
                     "B02_ROOT_MATERIALIZE=1 name=%s shard=%u off=%llu bytes=%zu "
                     "rows=%zu cols=%zu type=%d head4=%02x%02x%02x%02x\n",
                     wt.name.c_str(), wt.shardId,
                     (unsigned long long)wt.fileOffset, wt.sizeBytes, wt.rows,
                     wt.cols, wt.type, b[0], b[1], b[2], b[3]);
    }
    return 1;
}

} // namespace multishard_bind
} // namespace Deep2
