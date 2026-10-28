// mag_registry.hpp — MagBuf C registry API (mesh/neural/hwsynth/speciator)
// Owner TU: unlinked_symbols_batch_001.cpp (MagShutdown clears live handles).
// Init TUs (006–008) register slot tokens; tables are unbounded vector<void*>.
// No fixed MagBuf payload size/alignment constants. PROMOTE=0 TIP_CLIMB=HOLD.
#pragma once

#include <cstdint>

extern "C" {

// Canonical register entry points (alias: mag_publish_*)
void asm_magbuf_register_mesh(void* handle);
void asm_magbuf_register_neural(void* handle);
void asm_magbuf_register_hwsynth(void* handle);
void asm_magbuf_register_speciator(void* handle);

// Compat aliases used by earlier Quintile A join notes
void mag_publish_mesh_node(void* handle);
void mag_publish_neural_channel(void* handle);
void mag_publish_hwsynth_lut(void* handle);
void mag_publish_speciator_genome(void* handle);

void mag_publish_watchdog_region(void* region, uint32_t bytes);
void mag_watchdog_region_peek(void** outRegion, uint32_t* outBytes);

// B04: CRC of published MagBuf watchdog region (0 if unpublished).
uint32_t mag_watchdog_crc32_region(void);

uint32_t asm_magbuf_count_mesh(void);
uint32_t asm_magbuf_count_neural(void);
uint32_t asm_magbuf_count_hwsynth(void);
uint32_t asm_magbuf_count_speciator(void);
uint64_t asm_magbuf_epoch(void);
uint64_t mag_registry_epoch(void); // alias of asm_magbuf_epoch

} // extern "C"
