#pragma once

// Legacy include/gguf_loader.h — forward-declaration-only shim.
// This exists so code that includes "gguf_loader.h" via the include/
// directory gets the types it needs without conflicting with the
// canonical src/gguf_loader.h (which has the full definitions).
// 
// NOTE: Do NOT add using declarations here — they will conflict
// with the identical using declarations in src/gguf_loader.h when
// both files are included (which happens when both include/ and src/
// are in the include path).

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>

// Forward declarations only — full definitions in src/gguf_loader.h.
// GGUFMetadata lives in the RawrXD namespace (see RawrXD_Interfaces.h). We do
// NOT forward-declare a conflicting global ::GGUFMetadata here, and we mark the
// using-alias block in src/gguf_loader.h as already-provided to avoid a
// multiple-declaration (C2874) when both headers land in one TU.
#ifndef RAWRXD_GGUF_USING_ALIASES_DEFINED
#define RAWRXD_GGUF_USING_ALIASES_DEFINED
#endif
namespace RawrXD { struct GGUFMetadata; }
using RawrXD::GGUFMetadata;
class GGUFLoader;
