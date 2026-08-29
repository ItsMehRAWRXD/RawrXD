// hexmag_ide_link_probe.cpp — HEXMAG_IDE_LINK_001
// Forces HexMag_* MASM symbols into RawrXD-Win32IDE.exe and emits startup proof.
#include "core/hexmag_swarm.hpp"
#include "core/hexmag_repeat_tuner.hpp"

#include <cstdio>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace RawrXD {
namespace HexMag {

struct IdeLinkReport {
    bool linked = false;
    bool backendMasm = false;
    uint32_t isInitialized = 0;
    const char* backend = "NONE";
};

IdeLinkReport probeIdeLink() {
    IdeLinkReport r;
#ifdef RAWR_HAS_MASM
    r.linked = true;
    r.backendMasm = true;
    r.backend = "MASM";
    // Touch symbols so /OPT:REF cannot strip them from the IDE image.
    r.isInitialized = HexMag_IsInitialized();
    (void)HexMag_BotCount();
    (void)HexMag_GetParallelAgents();
    (void)HexMag_Tuner_GenerationId();
#else
    r.backend = "STUB";
#endif
    return r;
}

std::string formatIdeLinkDiagnostic() {
    const IdeLinkReport r = probeIdeLink();
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "HEXMAG_BACKEND=%s\nHEXMAG_LINKED=%d\nHEXMAG_INIT=%u\n",
                  r.backend, r.linked ? 1 : 0, r.isInitialized);
    return std::string(buf);
}

// Called from Win32IDE startup. Also runs once via dynamic initializer for
// early OutputDebugString proof before UI exists.
void emitIdeLinkDiagnostic() {
    const std::string msg = formatIdeLinkDiagnostic();
#ifdef _WIN32
    OutputDebugStringA(msg.c_str());
#endif
    std::fputs(msg.c_str(), stderr);
    std::fflush(stderr);
}

} // namespace HexMag
} // namespace RawrXD

extern "C" void RawrXD_HexMag_EmitIdeLinkDiagnostic() {
    RawrXD::HexMag::emitIdeLinkDiagnostic();
}

namespace {
struct HexMagIdeLinkBoot {
    HexMagIdeLinkBoot() { RawrXD::HexMag::emitIdeLinkDiagnostic(); }
};
static HexMagIdeLinkBoot g_hexmagIdeLinkBoot;
} // namespace
