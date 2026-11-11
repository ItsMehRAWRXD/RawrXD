/*==========================================================================
 * Export Table Generator - RawrXD native PE linker
 *=========================================================================*/

#include "export_gen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Little-endian writers ---- */
static void w16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void w32(uint8_t *p, uint32_t v) {
  p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

/* The IMAGE_EXPORT_DIRECTORY is 40 bytes.
 *
 * The version fields are WORDs, not DWORDs, which shifts every field after
 * offset 8. Getting this wrong makes the loader read the DLL name field as
 * zero, and the module then appears to have no exports at all:
 *
 *   0  Characteristics        4
 *   4  TimeDateStamp          4
 *   8  MajorVersion           2   (WORD)
 *  10  MinorVersion           2   (WORD)
 *  12  Name                   4
 *  16  Base                   4
 *  20  NumberOfFunctions      4
 *  24  NumberOfNames          4
 *  28  AddressOfFunctions     4
 *  32  AddressOfNames         4
 *  36  AddressOfNameOrdinals  4
 */
#define EXPORT_DIR_SIZE 40

export_table_t *export_table_new(void) {
  export_table_t *et = (export_table_t *)calloc(1, sizeof(export_table_t));
  if (!et) return NULL;
  et->base_ordinal = 1;
  return et;
}

void export_table_free(export_table_t *et) {
  if (!et) return;
  if (et->entries) free(et->entries);
  if (et->data) free(et->data);
  free(et);
}

int export_add(export_table_t *et, const char *name, uint32_t function_rva) {
  if (!et || !name) return -1;

  for (int i = 0; i < et->num_entries; ++i) {
    if (strcmp(et->entries[i].name, name) == 0) return i;
  }

  if (et->num_entries >= et->capacity) {
    int new_cap = et->capacity ? et->capacity * 2 : 32;
    export_entry_t *grown = (export_entry_t *)realloc(
        et->entries, (size_t)new_cap * sizeof(export_entry_t));
    if (!grown) return -1;
    et->entries = grown;
    et->capacity = new_cap;
  }

  int idx = et->num_entries++;
  export_entry_t *e = &et->entries[idx];
  memset(e, 0, sizeof(*e));
  strncpy(e->name, name, sizeof(e->name) - 1);
  e->function_rva = function_rva;
  e->has_ordinal = 0;
  return idx;
}

/*--------------------------------------------------------------------------
 * Builds the .edata payload.
 *------------------------------------------------------------------------*/
int export_build(export_table_t *et, merged_section_t *edata) {
  if (!et || !edata) return -1;
  if (et->num_entries == 0) return 0;

  int n = et->num_entries;

  /* ---- Compute the layout ----
   *
   * The export directory is followed by the three tables and then the
   * strings. Every table has one extra entry, which terminates it.
   */
  uint32_t addr_table_off  = EXPORT_DIR_SIZE;
  uint32_t name_table_off  = addr_table_off + (uint32_t)(n + 1) * 4;
  uint32_t ordinal_off     = name_table_off + (uint32_t)(n + 1) * 4;
  uint32_t strings_off     = ordinal_off + (uint32_t)(n + 1) * 2;

  /* The DLL name goes first in the string area, then the export names. */
  uint32_t dll_name_off = strings_off;
  uint32_t cursor = strings_off + (uint32_t)strlen(et->dll_name) + 1;

  uint32_t *name_string_offsets = (uint32_t *)calloc((size_t)n, sizeof(uint32_t));
  if (!name_string_offsets) return -1;
  for (int i = 0; i < n; ++i) {
    name_string_offsets[i] = cursor;
    cursor += (uint32_t)strlen(et->entries[i].name) + 1;
  }

  uint32_t total = cursor;
  uint32_t base_rva = edata->rva;

  /* ---- Allocate and fill the payload ---- */
  uint8_t *buf = (uint8_t *)calloc(1, total ? total : 1);
  if (!buf) { free(name_string_offsets); return -1; }

  /* IMAGE_EXPORT_DIRECTORY */
  uint8_t *dir = buf;
  w32(dir + 0,  0);                                  /* Characteristics */
  w32(dir + 4,  0);                                  /* TimeDateStamp */
  w16(dir + 8,  0);                                  /* MajorVersion */
  w16(dir + 10, 0);                                  /* MinorVersion */
  w32(dir + 12, base_rva + dll_name_off);             /* Name */
  w32(dir + 16, et->base_ordinal);                   /* Base */
  w32(dir + 20, (uint32_t)n);                        /* NumberOfFunctions */
  w32(dir + 24, (uint32_t)n);                        /* NumberOfNames */
  w32(dir + 28, base_rva + addr_table_off);          /* AddressOfFunctions */
  w32(dir + 32, base_rva + name_table_off);          /* AddressOfNames */
  w32(dir + 36, base_rva + ordinal_off);             /* AddressOfNameOrdinals */

  /* Export Address Table: the RVA of each exported function. */
  for (int i = 0; i < n; ++i) {
    w32(buf + addr_table_off + (uint32_t)i * 4, et->entries[i].function_rva);
  }
  /* The terminator is already zero. */

  /* Name Pointer Table: the RVA of each export name string. */
  for (int i = 0; i < n; ++i) {
    w32(buf + name_table_off + (uint32_t)i * 4, base_rva + name_string_offsets[i]);
  }

  /* Ordinal Table: the index into the address table for each name.
   *
   * The loader indexes the address table directly with this value, so it
   * is the index and not the export ordinal. */
  for (int i = 0; i < n; ++i) {
    w16(buf + ordinal_off + (uint32_t)i * 2, (uint16_t)i);
  }

  /* The DLL name and the export names. */
  memcpy(buf + dll_name_off, et->dll_name, strlen(et->dll_name) + 1);
  for (int i = 0; i < n; ++i) {
    memcpy(buf + name_string_offsets[i], et->entries[i].name,
           strlen(et->entries[i].name) + 1);
  }

  /* ---- Install the payload ---- */
  size_t needed = edata->data_len + total;
  if (needed > edata->data_capacity) {
    size_t new_cap = edata->data_capacity ? edata->data_capacity : 4096;
    while (new_cap < needed) new_cap *= 2;
    uint8_t *new_data = (uint8_t *)realloc(edata->data, new_cap);
    if (!new_data) { free(buf); free(name_string_offsets); return -1; }
    memset(new_data + edata->data_len, 0, new_cap - edata->data_len);
    edata->data = new_data;
    edata->data_capacity = new_cap;
  }
  memcpy(edata->data + edata->data_len, buf, total);
  edata->data_len += total;
  edata->virtual_size = edata->data_len;

  et->data = buf;
  et->data_len = total;
  et->data_rva = base_rva;
  et->dir_size = EXPORT_DIR_SIZE;

  free(name_string_offsets);
  return 0;
}

void export_table_dump(export_table_t *et, void *out) {
  FILE *f = out ? (FILE *)out : stderr;
  if (!et) return;
  fprintf(f, "[export] %d export(s) in %u bytes\n", et->num_entries, (unsigned)et->data_len);
  for (int i = 0; i < et->num_entries && i < 32; ++i) {
    fprintf(f, "    %-40s rva=0x%08X ordinal=%u\n", et->entries[i].name,
            et->entries[i].function_rva, (unsigned)(et->base_ordinal + i));
  }
}
