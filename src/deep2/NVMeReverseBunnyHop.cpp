// NVMeReverseBunnyHop.cpp — unlaidout reverse-chunk hotpatch bunnyhop
#include "NVMeReverseBunnyHop.hpp"
#include <cstdio>
#include <filesystem>
namespace fs = std::filesystem;
namespace Deep2 {

bool NVMeReverseBunnyHop::resolvePath(std::string& out) {
    if (cfg_.path.empty()) return false;
    fs::path p(cfg_.path);
    if (fs::is_regular_file(p)) { out = p.string(); return true; }
    if (!fs::is_directory(p)) return false;
    for (auto& e : fs::directory_iterator(p))
        if (e.is_regular_file() && e.path().extension() == ".gguf") {
            out = e.path().string(); return true;
        }
    return false;
}

bool NVMeReverseBunnyHop::readAt(uint64_t off, void* dst, size_t n, size_t& got) {
    got = 0;
#ifdef _WIN32
    OVERLAPPED ov{};
    ov.Offset = (DWORD)(off & 0xffffffffu);
    ov.OffsetHigh = (DWORD)(off >> 32);
    DWORD rd = 0;
    if (!ReadFile(hFile_, dst, (DWORD)n, &rd, &ov) && GetLastError() != ERROR_HANDLE_EOF)
        return false;
    got = (size_t)rd;
    return got > 0;
#else
    (void)off; (void)dst; (void)n; return false;
#endif
}

bool NVMeReverseBunnyHop::initialize(const NVMeBunnyHopConfig& cfg) {
    shutdown();
    cfg_ = cfg;
    cfg_.chunkBytes = (cfg_.chunkBytes < 4096 ? 4096 : cfg_.chunkBytes);
    cfg_.chunkBytes = (cfg_.chunkBytes + 4095ull) & ~4095ull;
    std::string path;
    if (!resolvePath(path)) {
        printf("[NVMeBunnyHop] FAIL resolve path='%s'\n", cfg_.path.c_str());
        return false;
    }
#ifdef _WIN32
    hFile_ = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile_ == INVALID_HANDLE_VALUE) {
        printf("[NVMeBunnyHop] FAIL open %s err=%lu\n", path.c_str(), GetLastError());
        return false;
    }
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(hFile_, &sz)) { shutdown(); return false; }
    fileBytes_ = (uint64_t)sz.QuadPart;
    for (int i = 0; i < 2; ++i) {
        slots_[i].cap = cfg_.chunkBytes;
        slots_[i].buf = (uint8_t*)VirtualAlloc(
            nullptr, slots_[i].cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!slots_[i].buf) { shutdown(); return false; }
    }
#else
    return false;
#endif
    nextOff_ = fileBytes_; streamed_ = 0; active_ = true;
    (void)hopReverseChunk();
    printf("[NVMeBunnyHop] %s %s %.2fGB c=%zu u=%d hp=%d\n", modeName(),
           path.c_str(), fileBytes_ / 1e9, cfg_.chunkBytes,
           (int)cfg_.unlaidout, (int)cfg_.hotpatchRelive);
    return true;
}

bool NVMeReverseBunnyHop::hopReverseChunk() {
    if (!active_ || nextOff_ == 0) return false;
    size_t want = cfg_.chunkBytes;
    if (want > nextOff_) want = (size_t)nextOff_;
    want &= ~4095ull;
    if (!want) want = (size_t)((nextOff_ >= 4096) ? 4096 : nextOff_);
    const uint64_t off = nextOff_ - want;
    size_t got = 0;
    if (!readAt(off, slots_[io_].buf, want, got)) return false;
    slots_[io_].ready = got; nextOff_ = off; streamed_ += got;
    std::swap(compute_, io_);
    return got > 0;
}

void NVMeReverseBunnyHop::shutdown() {
    active_ = false;
    for (int i = 0; i < 2; ++i) {
        if (slots_[i].buf) VirtualFree(slots_[i].buf, 0, MEM_RELEASE);
        slots_[i] = {};
    }
#ifdef _WIN32
    if (hFile_ != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile_); hFile_ = INVALID_HANDLE_VALUE;
    }
#endif
    fileBytes_ = nextOff_ = streamed_ = 0;
}

} // namespace Deep2
