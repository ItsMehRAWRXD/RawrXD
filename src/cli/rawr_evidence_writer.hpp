#pragma once
#include "rawr_output_router.hpp"
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
namespace rawr {
inline void SealEvidence(const char* dir, const char* gate, const char* verdict) {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(dir, nullptr);
#endif
    std::string path = std::string(dir) + "\\" + gate + ".seal";
    EvidenceWriter ew(path.c_str());
    ew.fmt("%s=%s", gate, verdict);
}
} // namespace rawr
