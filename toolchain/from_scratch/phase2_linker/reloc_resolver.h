/*
 * Relocation resolver — apply REL32/ADDR64 fixups in section data.
 */
#ifndef PHASE2_RELOC_RESOLVER_H
#define PHASE2_RELOC_RESOLVER_H

#include "coff_reader.h"
#include "import_builder.h"  /* Phase 3: Import support */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Apply one relocation in place. section_data = mutable bytes, section_rva = RVA of section start,
   offset = offset within section where reloc applies, type = IMAGE_REL_AMD64_*, target_rva = resolved symbol RVA. */
void reloc_apply(uint8_t* section_data, uint32_t section_rva, uint32_t offset, uint16_t type, uint32_t target_rva);

/* Apply all relocations from objs into merged .text. obj_text_offsets[i] = offset in text_data where obj i's .text starts.
   main_rva = resolved RVA for external symbol "main". __main_rva = RVA of stub ret (GCC __main shim); do not resolve __main to main.
   ib = import builder for resolving external symbols to IAT entries (Phase 3).
   Returns 0 on success, -1 on undefined symbol (with diagnostic to stderr). */
int reloc_resolver_apply(uint8_t* text_data, uint32_t text_rva,
    const uint32_t* obj_text_offsets, CoffFile** objs, int num_objs, 
    uint32_t main_rva, uint32_t __main_rva,
    import_builder_t* ib);  /* Phase 3: Import symbol resolution */

#ifdef __cplusplus
}
#endif

#endif /* PHASE2_RELOC_RESOLVER_H */
