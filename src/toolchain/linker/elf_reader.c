/*==========================================================================
 * Phase 6 (R1): ELF64 Loader - Fully Reverse Engineered
 *
 * Parses 64-bit little-endian ELF64 executable images:
 *   - ELF identification (magic, class, data, version)
 *   - ELF header fields (type, machine, entry, program header table)
 *   - Program headers -> load segments (PT_LOAD)
 *
 * Layout: [ELF Header][Program Headers][Segment Data]
 *=========================================================================*/

#include "elf_reader.h"
#include <stdio.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t) p[3] << 24); }
static uint64_t rd64(const uint8_t *p) { return (uint64_t) rd32(p) | ((uint64_t) rd32(p + 4) << 32); }

int elf_read(const char *path, elf_info_t *info, char *err, size_t errlen)
{
  memset(info, 0, sizeof(*info));
  err[0] = '\0';

  FILE *f = fopen(path, "rb");
  if (!f) { snprintf(err, errlen, "cannot open %s", path); return -1; }

  uint8_t e_ident[16];
  if (fread(e_ident, 1, 16, f) != 16) { snprintf(err, errlen, "short read at ident"); fclose(f); return -1; }
  if (e_ident[0] != ELF_MAGIC0 || e_ident[1] != (uint8_t) 'E' || e_ident[2] != (uint8_t) 'L' || e_ident[3] != (uint8_t) 'F') {
    snprintf(err, errlen, "bad ELF magic"); fclose(f); return -1;
  }
  if (e_ident[4] != ELFCLASS64) { snprintf(err, errlen, "not ELFCLASS64"); fclose(f); return -1; }
  if (e_ident[5] != ELFDATA2LSB) { snprintf(err, errlen, "not ELFDATA2LSB"); fclose(f); return -1; }
  if (e_ident[6] != EV_CURRENT) { snprintf(err, errlen, "unsupported ELF version"); fclose(f); return -1; }

  uint8_t hdr[48];
  if (fread(hdr, 1, 48, f) != 48) { snprintf(err, errlen, "short read at header"); fclose(f); return -1; }

  info->type = rd16(hdr + 0);
  info->machine = rd16(hdr + 2);
  info->version = rd32(hdr + 4);
  info->entry = rd64(hdr + 8);
  uint64_t phoff = rd64(hdr + 16);     /* e_phoff @ file 32 */
  uint16_t phentsize = rd16(hdr + 38); /* e_phentsize @ file 54 */
  info->phnum = rd16(hdr + 40);        /* e_phnum @ file 56 */
  info->shnum = rd16(hdr + 44);        /* e_shnum @ file 60 */

  if (info->phnum > ELF_MAX_SEGMENTS) { snprintf(err, errlen, "too many program headers"); fclose(f); return -1; }

  for (uint16_t i = 0; i < info->phnum; i++) {
    uint64_t off = phoff + ((uint64_t) i * phentsize);
    if (fseek(f, (long) off, SEEK_SET) != 0) { snprintf(err, errlen, "fseek failed"); fclose(f); return -1; }
    uint8_t ph[ELF_PHDR_SIZE];
    if (fread(ph, 1, ELF_PHDR_SIZE, f) != ELF_PHDR_SIZE) { snprintf(err, errlen, "short read at phdr"); fclose(f); return -1; }
    elf_segment_t *slot = &info->segments[i];
    slot->type = rd32(ph + 0);
    slot->flags = rd32(ph + 4);
    slot->offset = rd64(ph + 8);
    slot->vaddr = rd64(ph + 16);
    slot->paddr = rd64(ph + 24);
    slot->filesz = rd64(ph + 32);
    slot->memsz = rd64(ph + 40);
    slot->align = rd64(ph + 48);
  }

  fclose(f);
  return 0;
}