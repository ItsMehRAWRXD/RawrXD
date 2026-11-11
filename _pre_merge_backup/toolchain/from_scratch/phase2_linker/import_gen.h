#ifndef IMPORT_GEN_H
#define IMPORT_GEN_H

/*==========================================================================
 * Import Table Generator - RawrXD native PE linker
 *
 * Builds a complete PE32+ import table from the undefined external symbols
 * referenced by the input COFF objects.
 *
 * The generated image contains, inside a dedicated `.idata` section:
 *
 *   +----------------+  Import Directory Table
 *   | IMAGE_IMPORT_  |  one 20-byte descriptor per DLL, plus a null
 *   | DESCRIPTOR[]   |  terminator.
 *   +----------------+
 *   | Import Lookup  |  one array per DLL, terminated by a null quadword.
 *   | Table (ILT)[]  |
 *   +----------------+
 *   | Import Address |  one array per DLL, terminated by a null quadword.
 *   | Table (IAT)[]  |  The loader overwrites these with real addresses.
 *   +----------------+
 *   | Hint/Name      |  WORD hint + ASCII name + NUL, padded to 2 bytes.
 *   | entries        |
 *   +----------------+
 *   | DLL name       |  NUL-terminated ASCII strings.
 *   | strings        |
 *   +----------------+
 *
 * Every RVA stored in these structures is image-relative, i.e.
 * `idata_section_rva + offset_within_section`. Writing the bare offset is
 * the classic failure that produces STATUS_DLL_NOT_FOUND at load time.
 *
 * Call sites are redirected through a 6-byte thunk placed in `.text`:
 *
 *   FF 25 <disp32>      jmp qword ptr [rip + disp32]
 *
 * The thunk's displacement targets the IAT slot, so after the loader binds
 * the import the thunk jumps straight to the real function.
 *=========================================================================*/

#include <stdint.h>
#include <stddef.h>

#include "coff_reader.h"
#include "section_merge.h"

/* ---- Per-symbol import record ---- */
typedef struct import_symbol {
  char     name[256];      /* the exported symbol name */
  char     dll[64];        /* the DLL that exports it */
  uint16_t ordinal;        /* import-by-ordinal value (0 when by name) */
  int      is_ordinal;     /* 1 = import by ordinal */
  uint32_t iat_rva;        /* RVA of this symbol's IAT slot */
  uint32_t thunk_rva;      /* RVA of the redirect thunk (0 = none needed) */
  int      needs_thunk;    /* 1 = call sites point at a thunk */
} import_symbol_t;

/* ---- Per-DLL grouping ---- */
typedef struct import_dll {
  char     name[64];       /* DLL file name, e.g. "kernel32.dll" */
  int      first_symbol;   /* index of the first symbol in the flat array */
  int      num_symbols;
  uint32_t ilt_rva;        /* RVA of this DLL's lookup table */
  uint32_t iat_rva;        /* RVA of this DLL's address table */
  uint32_t name_rva;       /* RVA of this DLL's name string */
} import_dll_t;

#define IMPORT_MAX_DLLS   64
#define IMPORT_MAX_SYMBOLS 4096

typedef struct import_table {
  import_symbol_t symbols[IMPORT_MAX_SYMBOLS];
  int             num_symbols;

  import_dll_t    dlls[IMPORT_MAX_DLLS];
  int             num_dlls;

  /* Generated `.idata` payload and its placement. */
  uint8_t *idata;
  size_t   idata_len;
  uint32_t idata_rva;
  uint32_t idata_size;      /* size of the import directory proper */

  int      num_thunks;
  int      unresolved;      /* symbols with no known DLL */
} import_table_t;

/* ---- API ---- */

import_table_t *import_table_new(void);
void           import_table_free(import_table_t *it);

/* Registers a symbol, grouping it under `dll`. Returns the symbol index. */
int  import_add_symbol(import_table_t *it, const char *name, const char *dll,
                       uint16_t ordinal, int is_ordinal);

/* Returns the index of `name`, or -1. */
int  import_find_symbol(import_table_t *it, const char *name);

/*
 * Phase 1.5 - Scan the COFF inputs for undefined external symbols and
 * resolve each one to the DLL that exports it.
 *
 * This runs before section merging because the `.idata` section has to
 * exist in the merge before the RVA assignment pass, otherwise the import
 * structures would be laid out at an address that does not match the
 * section header.
 */
int import_scan(import_table_t *it, coff_file_t **files, int num_files);

/*
 * Phase 2.5 - Lay out the `.idata` section, emit the redirect thunks into
 * `.text`, and point the global symbol table at the results.
 *
 * `text` is the merged `.text` section that receives the thunks; `idata`
 * is the merged `.idata` section that receives the import structures.
 * Both must already have their RVAs assigned.
 */
int import_layout(import_table_t *it, merge_context_t *ctx,
                   merged_section_t *text, merged_section_t *idata);

/* Combined scan + layout, for callers that do not need the split. */
int import_generate(import_table_t *it, merge_context_t *ctx,
                    coff_file_t **files, int num_files,
                    merged_section_t *text, merged_section_t *idata);

/* Diagnostic dump. */
void import_table_dump(import_table_t *it, void *out);

#endif /* IMPORT_GEN_H */
