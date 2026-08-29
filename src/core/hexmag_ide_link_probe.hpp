// hexmag_ide_link_probe.hpp — HEXMAG_IDE_LINK_001 startup proof
#pragma once
#include <string>

namespace RawrXD {
namespace HexMag {
std::string formatIdeLinkDiagnostic();
void emitIdeLinkDiagnostic();
} // namespace HexMag
} // namespace RawrXD

extern "C" void RawrXD_HexMag_EmitIdeLinkDiagnostic();
