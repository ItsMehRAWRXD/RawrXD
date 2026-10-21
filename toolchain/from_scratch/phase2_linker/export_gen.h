#ifndef EXPORT_GEN_H
#define EXPORT_GEN_H

/*==========================================================================
 * Export Table Generator - RawrXD native PE linker
 *
 * Builds a `.edata` section containing a complete PE32+ export directory
 * so the linker can produce a DLL that other modules can import from.
 *
 * The layout is:
 *
 *   IMAGE_EXPORT_DIRECTORY        40 bytes
 *   Export Address Table          (n + 1) x 4 bytes, zero terminated
 *   Name Pointer Table            (n + 1) x 4 bytes, zero terminated
 *   Ordinal Table                 (n + 1) x 2 bytes, zero terminated
 *   DLL name                      NUL terminated ASCII
 *   Export name strings           NUL terminated ASCII, one per export
 *
 * The export directory:
 *
 *   offset  size  field
 *   0       4     Characteristics       (0)
 *   4       4     TimeDateStamp         (0 for a reproducible build)
 *   8       2     MajorVersion
 *   10      2     MinorVersion
 *   12      4     Name                  RVA of the DLL name
 *   16      4     Base                  the ordinal of the first export
 *   20      4     NumberOfFunctions
 *   24      4     NumberOfNames
 *   28      4     AddressOfFunctions    RVA of the export address table
 *   32      4     AddressOfNames        RVA of the name pointer table
 *   36      4     AddressOfNameOrdinals RVA of the ordinal table
 *
 * The directory is 44 bytes: eleven 32-bit fields.
 *
 * The export address table holds the RVA of the exported function, so the
 * loader can patch it to the real address.
 *=========================================================================*/

#include <stdint.h>
#include <stddef.h>

#include "section_merge.h"

/* One exported function. */
typedef struct export_entry {
  char    name[256];
  uint32_t function_rva;   /* the RVA of the exported code */
  int     has_ordinal;     /* 1 when an explicit ordinal was requested */
  uint16_t ordinal;
} export_entry_t;

typedef struct export_table {
  export_entry_t *entries;
  int num_entries;
  int capacity;
  uint16_t base_ordinal;
  char dll_name[260];
  uint8_t *data;      /* the generated .edata payload */
  size_t data_len;
  uint32_t data_rva;  /* the RVA of the .edata section */
  uint32_t dir_size;  /* the size of the export directory proper */
} export_table_t;

export_table_t *export_table_new(void);
void export_table_free(export_table_t *et);

/* Registers an exported function. Returns the export index, or -1. */
int export_add(export_table_t *et, const char *name, uint32_t function_rva);

/*
 * Builds the .edata payload. The section must already have an RVA.
 * Returns 0 on success.
 */
int export_build(export_table_t *et, merged_section_t *edata);

/* Diagnostic dump. */
void export_table_dump(export_table_t *et, void *out);

#endif /* EXPORT_GEN_H */
