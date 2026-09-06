// ============================================================================
// MemoryMappedFile.hpp — additive zero-copy GGUF shard access
// Maps a GGUF shard into the process address space so tensor payloads can be
// referenced by pointer without read() copies. The OS pages data in/out on demand,
// which is the core enabler for running 600 GB models on 32 GB VRAM / 64 GB RAM.
// ============================================================================
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace Deep2 {

struct MemoryMappedFile {
    std::string path;
    uint64_t fileSize = 0;
    const uint8_t* data = nullptr;
#ifdef _WIN32
    void* fileHandle = nullptr;   // HANDLE
    void* mappingHandle = nullptr; // HANDLE
#else
    int fd = -1;
#endif
    bool ok = false;
    std::string error;

    bool Map(const char* filePath);
    void Unmap();
    bool Prefetch(uint64_t offset, uint64_t size);

    const uint8_t* At(uint64_t offset, uint64_t size) const {
        if (!data || offset > fileSize || size > (fileSize - offset)) return nullptr;
        return data + offset;
    }

    ~MemoryMappedFile() { Unmap(); }
};

} // namespace Deep2
