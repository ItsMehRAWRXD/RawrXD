#pragma once
#include <cstddef>
#include <cstdint>
namespace Deep2 {
namespace kv_probe {
inline bool Enabled() { return false; }
inline void EmitAdvance(const char*, size_t, size_t, const char*) {}
inline void EmitAdvance(const char*, size_t, size_t, size_t, const char*) {}
inline void EmitPriorSlot(int, int, const float*, size_t) {}
inline void EmitPriorSlot(size_t, int, const float*, size_t) {}
inline void EmitWrite(const char*, int, uint32_t, size_t, size_t,
                      const float*, size_t) {}
inline void EmitWrite(const char*, size_t, uint32_t, size_t, size_t,
                      const float*, size_t) {}
inline void EmitAttend(int, int, size_t, size_t, size_t, const float*,
                       size_t) {}
} // namespace kv_probe
namespace kv_own {
inline void Nop() {}
}
} // namespace Deep2
