// NVMeReverseBunnyHop.hpp — unlaidout reverse-chunk dual-slot bunnyhop
// Forced when NVMe mmap stream falls back (empty path / open fail).
#pragma once
#include <cstdint>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

struct NVMeBunnyHopConfig {
    std::string path;                 // file or shard dir (first .gguf)
    size_t chunkBytes = 4ull << 20;   // 4 MiB reverse chunks (sector-aligned)
    size_t maxResidentBytes = 512ull << 20;
    bool unlaidout = true;            // raw on-disk bytes, no layout repair
    bool hotpatchRelive = true;       // undeadHop / hotpatch(relive)
};

// Dual-slot reverse IO: read EOF→0, hop slots after each chunk.
class NVMeReverseBunnyHop {
public:
    NVMeReverseBunnyHop() = default;
    ~NVMeReverseBunnyHop() { shutdown(); }

    bool initialize(const NVMeBunnyHopConfig& cfg);
    void shutdown();
    bool active() const { return active_; }
    bool unlaidout() const { return cfg_.unlaidout; }
    bool hotpatchRelive() const { return cfg_.hotpatchRelive; }

    // Bunnyhop: prime next reverse chunk into IO slot; swap to compute.
    bool hopReverseChunk();
    const uint8_t* computePtr() const { return slots_[compute_].buf; }
    size_t computeBytes() const { return slots_[compute_].ready; }
    uint64_t fileBytes() const { return fileBytes_; }
    uint64_t nextOffset() const { return nextOff_; }
    uint64_t bytesStreamed() const { return streamed_; }
    const char* modeName() const { return "UNLAIDOUT_REVERSE_CHUNK_HOTPATCH_BUNNYHOP"; }

private:
    struct Slot {
        uint8_t* buf = nullptr;
        size_t cap = 0;
        size_t ready = 0;
    };
    NVMeBunnyHopConfig cfg_{};
    bool active_ = false;
    Slot slots_[2]{};
    uint32_t compute_ = 0;
    uint32_t io_ = 1;
    uint64_t fileBytes_ = 0;
    uint64_t nextOff_ = 0; // next reverse read end (exclusive)
    uint64_t streamed_ = 0;
#ifdef _WIN32
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
#endif
    bool resolvePath(std::string& out);
    bool readAt(uint64_t off, void* dst, size_t n, size_t& got);
};

} // namespace Deep2
