/*==========================================================================
 * Base Relocation Generator - RawrXD native PE linker
 *=========================================================================*/

#include "reloc_gen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- PE constants ---- */
#define PE_PAGE_SIZE        0x1000
#define PE_RELOC_BLOCK_SIZE 0x1000   /* 4 KiB per relocation block */
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_DIR64   10
#define IMAGE_REL_BASED_HIGHLOW 3

/* ---- Little-endian writers ---- */
static void w16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void w32(uint8_t *p, uint32_t v) {
  p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

reloc_table_t *reloc_table_new(void) {
  return (reloc_table_t *)calloc(1, sizeof(reloc_table_t));
}

void reloc_table_free(reloc_table_t *rt) {
  if (!rt) return;
  if (rt->sites) free(rt->sites);
  free(rt);
}

int reloc_add_site(reloc_table_t *rt, uint32_t rva, reloc_kind_t kind) {
  if (!rt) return 0;
  if (rt->num_sites >= rt->capacity) {
    int new_cap = rt->capacity ? rt->capacity * 2 : 64;
    reloc_site_t *new_sites = (reloc_site_t *)realloc(rt->sites,
                                                       (size_t)new_cap * sizeof(reloc_site_t));
    if (!new_sites) { rt->error = 1; return 0; }
    rt->sites = new_sites;
    rt->capacity = new_cap;
  }
  rt->sites[rt->num_sites].rva = rva;
  rt->sites[rt->num_sites].kind = kind;
  rt->num_sites++;
  return 1;
}

/*--------------------------------------------------------------------------
 * Builds the .reloc payload.
 *------------------------------------------------------------------------*/
int reloc_build(reloc_table_t *rt, merged_section_t *reloc_sec, uint32_t *out_rva,
                uint32_t *out_size) {
  if (!rt || !reloc_sec) return -1;

  if (rt->num_sites == 0) {
    if (out_rva) *out_rva = 0;
    if (out_size) *out_size = 0;
    return 0;
  }

  /* Group the sites by page. The number of blocks is bounded by the page
   * count, so a small fixed array of page indices is enough for any
   * realistic image; fall back to a growable list if needed. */
  uint32_t *pages = NULL;
  int num_pages = 0;
  int page_capacity = 0;

  /* Upper bound: one page per site, so this is always sufficient. */
  page_capacity = rt->num_sites;
  pages = (uint32_t *)calloc((size_t)page_capacity, sizeof(uint32_t));
  if (!pages) return -1;

  for (int i = 0; i < rt->num_sites; i++) {
    uint32_t page = rt->sites[i].rva & ~(PE_PAGE_SIZE - 1);
    int found = 0;
    for (int p = 0; p < num_pages; p++) {
      if (pages[p] == page) { found = 1; break; }
    }
    if (!found) pages[num_pages++] = page;
  }

  /* Compute the size of each block: 8-byte header plus one 2-byte entry
   * per site on that page, plus a trailing ABSOLUTE pad entry when the
   * entry count is odd (the loader requires 4-byte alignment of blocks). */
  uint32_t total = 0;
  for (int p = 0; p < num_pages; p++) {
    uint32_t page = pages[p];
    int entries = 0;
    for (int i = 0; i < rt->num_sites; i++) {
      if ((rt->sites[i].rva & ~(PE_PAGE_SIZE - 1)) == page) entries++;
    }
    uint32_t entry_bytes = (uint32_t)entries * 2;
    if (entry_bytes & 3) entry_bytes += 2;   /* pad to a 4-byte boundary */
    total += 8 + entry_bytes;
  }

  uint8_t *buf = (uint8_t *)calloc(1, total ? total : 1);
  if (!buf) { free(pages); return -1; }

  uint32_t cursor = 0;
  for (int p = 0; p < num_pages; p++) {
    uint32_t page = pages[p];
    uint32_t block_start = cursor;

    /* Count the entries on this page. */
    int entries = 0;
    for (int i = 0; i < rt->num_sites; i++) {
      if ((rt->sites[i].rva & ~(PE_PAGE_SIZE - 1)) == page) entries++;
    }

    uint32_t entry_bytes = (uint32_t)entries * 2;
    if (entry_bytes & 3) entry_bytes += 2;

    /* Block header. SizeOfBlock covers the header and the entries. */
    w32(buf + cursor + 0, page);
    w32(buf + cursor + 4, 8 + entry_bytes);
    cursor += 8;

    uint32_t entry_cursor = cursor;
    for (int i = 0; i < rt->num_sites; i++) {
      if ((rt->sites[i].rva & ~(PE_PAGE_SIZE - 1)) != page) continue;
      uint16_t type = (rt->sites[i].kind == RELOC_DIR64)
                          ? IMAGE_REL_BASED_DIR64
                          : IMAGE_REL_BASED_HIGHLOW;
      uint16_t offset = (uint16_t)(rt->sites[i].rva & 0xFFF);
      w16(buf + entry_cursor, (uint16_t)((type << 12) | offset));
      entry_cursor += 2;
    }

    /* Pad the block to a 4-byte boundary with an ABSOLUTE entry. */
    if ((entry_bytes - (uint32_t)entries * 2) != 0) {
      w16(buf + entry_cursor, IMAGE_REL_BASED_ABSOLUTE);
      entry_cursor += 2;
    }

    cursor = block_start + 8 + entry_bytes;
  }

  /* Install the payload into the .reloc section. */
  size_t needed = reloc_sec->data_len + total;
  if (needed > reloc_sec->data_capacity) {
    size_t new_cap = reloc_sec->data_capacity ? reloc_sec->data_capacity : 4096;
    while (new_cap < needed) new_cap *= 2;
    uint8_t *new_data = (uint8_t *)realloc(reloc_sec->data, new_cap);
    if (!new_data) { free(buf); free(pages); return -1; }
    memset(new_data + reloc_sec->data_len, 0, new_cap - reloc_sec->data_len);
    reloc_sec->data = new_data;
    reloc_sec->data_capacity = new_cap;
  }
  memcpy(reloc_sec->data + reloc_sec->data_len, buf, total);
  reloc_sec->data_len += total;
  if (reloc_sec->virtual_size < reloc_sec->data_len)
    reloc_sec->virtual_size = reloc_sec->data_len;

  if (out_rva) *out_rva = reloc_sec->rva;
  if (out_size) *out_size = total;

  free(buf);
  free(pages);
  return 0;
}

void reloc_table_dump(reloc_table_t *rt, void *out) {
  FILE *f = out ? (FILE *)out : stderr;
  if (!rt) return;
  fprintf(f, "[reloc] %d relocation site(s)\n", rt->num_sites);
  for (int i = 0; i < rt->num_sites && i < 32; i++) {
    fprintf(f, "    RVA 0x%08X type %d\n", rt->sites[i].rva, (int)rt->sites[i].kind);
  }
  if (rt->num_sites > 32) fprintf(f, "    ... %d more\n", rt->num_sites - 32);
}
