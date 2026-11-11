#ifndef RELOC_GEN_H
#define RELOC_GEN_H

/*==========================================================================
 * Base Relocation Generator - RawrXD native PE linker
 *
 * Produces a `.reloc` section so the image can be rebased by the Windows
 * loader. Without a valid base relocation table the loader must load the
 * image at exactly its preferred base, which defeats ASLR and is refused
 * outright on modern Windows configurations.
 *
 * A base relocation block has the layout:
 *
 *   +----------------+------------------+-------------------+
 *   | VirtualAddress | SizeOfBlock     | TypeOffset[]      |
 *   | (DWORD)        | (DWORD)         | (WORD each)       |
 *   +----------------+------------------+-------------------+
 *
 * `VirtualAddress` is the page RVA, `SizeOfBlock` covers the whole block
 * including the 8-byte header, and each `TypeOffset` word packs a 4-bit
 * type in the high bits and a 12-bit page offset in the low bits.
 *
 * The relocation types used here:
 *   IMAGE_REL_BASED_ABSOLUTE   (0) - padding, ignored by the loader
 *   IMAGE_REL_BASED_DIR64      (10) - the 8 bytes at the offset are an
 *                                     absolute address that must be
 *                                     adjusted by the load delta
 *=========================================================================*/

#include <stdint.h>
#include <stddef.h>

#include "section_merge.h"

/* ---- Relocation kinds ---- */
typedef enum reloc_kind {
  RELOC_ABSOLUTE = 0,   /* padding entry */
  RELOC_DIR64   = 10,   /* 64-bit absolute address */
  RELOC_HIGHLOW = 3,    /* 32-bit absolute address (32-bit images) */
} reloc_kind_t;

/* One recorded absolute address that needs rebasing. */
typedef struct reloc_site {
  uint32_t rva;          /* RVA of the 8-byte absolute address */
  reloc_kind_t kind;
} reloc_site_t;

/* ---- Collector ---- */
typedef struct reloc_table {
  reloc_site_t *sites;
  int num_sites;
  int capacity;
  int error;
} reloc_table_t;

reloc_table_t *reloc_table_new(void);
void           reloc_table_free(reloc_table_t *rt);

/* Records an absolute address that must be rebased. */
int reloc_add_site(reloc_table_t *rt, uint32_t rva, reloc_kind_t kind);

/*
 * Builds the `.reloc` section payload and installs it into `reloc_sec`.
 * The section must already have an RVA assigned.
 *
 * Returns 0 on success, -1 on failure.
 */
int reloc_build(reloc_table_t *rt, merged_section_t *reloc_sec, uint32_t *out_rva,
                uint32_t *out_size);

/* Diagnostic dump. */
void reloc_table_dump(reloc_table_t *rt, void *out);

#endif /* RELOC_GEN_H */
