#pragma once
/* Extension-agnostic model path: .gguf OR Ollama blob (GGUF magic / embedded). */
#include "ollama_blob_parser.h"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>

namespace Deep2 {
namespace GgufPath {

inline constexpr uint32_t kGgufMagic = 0x46554747u; /* 'GGUF' LE */

inline std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

inline bool HasGgufExt(const std::filesystem::path& p) {
    return ToLower(p.extension().string()) == ".gguf";
}

inline bool MagicAtZero(const std::filesystem::path& p) {
    FILE* f = nullptr;
#if defined(_MSC_VER)
    if (fopen_s(&f, p.string().c_str(), "rb") != 0 || !f) return false;
#else
    f = std::fopen(p.string().c_str(), "rb");
    if (!f) return false;
#endif
    uint32_t m = 0;
    const size_t n = std::fread(&m, 1, sizeof(m), f);
    std::fclose(f);
    return n == sizeof(m) && m == kGgufMagic;
}

inline bool NameLooksMmproj(const std::filesystem::path& p) {
    return ToLower(p.filename().string()).find("mmproj") != std::string::npos;
}

/* True for .gguf, extensionless/sha256 blobs, or any file with GGUF payload. */
inline bool IsLoadableModelFile(const std::filesystem::path& p) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::is_regular_file(p, ec) || ec) return false;
    if (NameLooksMmproj(p)) return false;
    if (HasGgufExt(p)) return true;
    if (MagicAtZero(p)) return true;
    const std::string n = ToLower(p.filename().string());
    const bool blobish =
        n.find("sha256-") != std::string::npos || p.extension().empty();
    if (!blobish) return false;
    uint64_t off = 0;
    rawrxd::ollama::OllamaBlobDetector det;
    return det.ContainsGGUF(p.string(), off);
}

inline bool NeedsBlobResolve(const std::filesystem::path& p) {
    if (!IsLoadableModelFile(p)) return false;
    if (HasGgufExt(p) && MagicAtZero(p)) return false;
    return !HasGgufExt(p) || !MagicAtZero(p);
}

} // namespace GgufPath
} // namespace Deep2
