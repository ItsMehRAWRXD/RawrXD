// gguf_probe.cpp — read a GGUF header and report what the file CLAIMS to be.
//
// Exists because file size and filename are not evidence. A set of shards named
// "-of-00011" totalling 266 GB cannot be a 32B Q4_K_M model, which is ~19 GB.
// This reads the header the loader itself would read, so the answer comes from
// the bytes rather than from the directory listing.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>

#include "GGUFLoader.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static uint64_t fileSizeOf(const char* p) {
    WIN32_FILE_ATTRIBUTE_DATA fa{};
    if (!GetFileAttributesExA(p, GetFileExInfoStandard, &fa)) return 0;
    return (static_cast<uint64_t>(fa.nFileSizeHigh) << 32) | fa.nFileSizeLow;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: gguf_probe <file.gguf>\n");
        return 2;
    }
    const char* path = argv[1];

    // ---- raw magic, independent of the loader ----
    {
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::printf("CANNOT_OPEN=%s\n", path); return 1; }
        char m[4] = {0,0,0,0};
        f.read(m, 4);
        uint32_t magic = 0;
        std::memcpy(&magic, m, 4);
        std::printf("FILE=%s\n", path);
        std::printf("FILE_BYTES=%llu\n", (unsigned long long)fileSizeOf(path));
        std::printf("MAGIC_RAW=0x%08x\n", magic);
        std::printf("IS_GGUF=%d\n", (magic == 0x46554747u) ? 1 : 0);
        if (magic != 0x46554747u) {
            std::printf("VERDICT=NOT_A_GGUF_FILE\n");
            return 1;
        }
    }

    // ---- now let the production loader describe it ----
    Deep2::GGUFLoader loader;
    if (!loader.load(path)) {
        // The loader's own reason. Printing only "rejected" is the same defect
        // as reporting a verdict without evidence: the reader cannot tell a
        // damaged file from an unsupported architecture, and those demand
        // opposite responses.
        std::printf("LOADER_REJECTED=1\n");
        std::printf("LOADER_ERROR=%s\n", loader.error().c_str());
        std::printf("VERDICT=HEADER_UNREADABLE\n");
        return 1;
    }
    std::printf("LOADER_ACCEPTED=1\n");
    std::printf("LOADER_ERROR=%s\n", loader.error().c_str());

    const auto names = loader.listTensors();
    std::printf("TENSOR_COUNT=%zu\n", names.size());

    uint64_t claimed = 0, maxOff = 0;
    std::vector<uint32_t> typeHistogram;
    for (const auto& n : names) {
        const auto* t = loader.getTensor(n);
        if (!t) continue;
        claimed += t->sizeBytes;
        const uint64_t end = t->fileOffset + t->sizeBytes;
        if (end > maxOff) maxOff = end;
    }
    std::printf("TENSOR_BYTES_CLAIMED=%llu\n", (unsigned long long)claimed);
    std::printf("TENSOR_DATA_END_OFFSET=%llu\n", (unsigned long long)maxOff);

    const uint64_t onDisk = fileSizeOf(path);
    // Anything past the last tensor is not weight data. A large tail means the
    // file carries something other than the tensors it advertises.
    const double tailPct = onDisk ? (100.0 * (double)(onDisk - maxOff) / (double)onDisk) : 0.0;
    std::printf("NONTENSOR_TAIL_BYTES=%llu\n",
                (unsigned long long)(onDisk > maxOff ? onDisk - maxOff : 0));
    std::printf("NONTENSOR_TAIL_PERCENT=%.3f\n", tailPct);

    std::printf("FIRST_TENSORS=");
    for (size_t i = 0; i < names.size() && i < 10; ++i)
        std::printf("%s%s", i ? "," : "", names[i].c_str());
    std::printf("\n");

    const char* keys[] = {"general.architecture", "general.name",
                          "general.parameter_count", "general.file_type"};
    for (const char* k : keys) {
        const std::string v = loader.getMetaString(k, "");
        if (!v.empty()) std::printf("META %s=%s\n", k, v.c_str());
    }

    std::printf("VERDICT=HEADER_READ\n");
    return 0;
}
