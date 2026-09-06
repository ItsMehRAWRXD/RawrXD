// Minimal watchdog init — ASM RawrXD_Watchdog.obj historically lacked this export.
// Kept separate from unlinked_symbols_batch_004 to avoid hotpatch/snapshot ODR with MASM.
#include <cstdint>

extern "C" bool asm_watchdog_init()
{
    return true;
}
