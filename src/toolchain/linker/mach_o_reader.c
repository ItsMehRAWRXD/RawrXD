/*==========================================================================
 * Phase 6 (R1): Mach-O 64 Loader - Fully Reverse Engineered
 *
 * Parses 64-bit little-endian Mach-O executable images:
 *   - Mach-O magic / CPU type / file type / command header
 *   - Load commands (LC_SEGMENT_64 etc.) -> segments
 *
 * Layout: [Mach-O Header (32B)][Load Commands][Section Data]
 *=========================================================================*/

#include "mach_o_reader.h"
#include <stdio.h>
#include <string.h>

static uint32_t rd32(const uint8_t *p) { return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24); }
static uint64_t rd64(const uint8_t *p) { return (uint64_t) rd32(p) | ((uint64_t) rd32(p + 4) << 32); }

int mach_o_read(const char *path, mach_o_info_t *info, char *err, size_t errlen)
{
  memset(info, 0, sizeof(*info));
  err[0] = '\0';

  FILE *f = fopen(path, "rb");
  if (!f) { snprintf(err, errlen, "cannot open %s", path); return -1; }

  uint8_t hdr[32];
  if (fread(hdr, 1, 32, f) != 32) { snprintf(err, errlen, "short read at header"); fclose(f); return -1; }

  if (rd32(hdr) != MH_MAGIC) { snprintf(err, errlen, "bad Mach-O magic"); fclose(f); return -1; }
  if (rd32(hdr + 4) != MH_CPUTYPE_X86_64) { snprintf(err, errlen, "unsupported CPU type"); fclose(f); return -1; }

  info->type = rd32(hdr + 12);
  info->cputype = rd32(hdr + 4);
  info->ncmds = rd32(hdr + 16);
  info->flags = rd32(hdr + 24);
  info->entry = 0;

  if (info->ncmds > MH_MAX_SEGMENTS) { snprintf(err, errlen, "too many load commands"); fclose(f); return -1; }

  uint32_t sizeofcmds = rd32(hdr + 20);
  uint32_t segment_count = 0;
  uint32_t pf_x = 0x1; /* PF_X */
  info->nsegments = 0;

  for (uint32_t i = 0; i < info->ncmds; i++) {
    uint64_t off = 32 + ((uint64_t) i * sizeofcmds);
    if (fseek(f, (long) off, SEEK_SET) != 0) { snprintf(err, errlen, "fseek failed"); fclose(f); return -1; }
    uint8_t cmdbuf[256];
    if (fread(cmdbuf, 1, sizeofcmds, f) != sizeofcmds) { snprintf(err, errlen, "short read at load command"); fclose(f); return -1; }
    if (rd32(cmdbuf) != LC_SEGMENT_64) continue;

    if (segment_count >= MH_MAX_SEGMENTS) break;

    mach_o_segment_t *slot = &info->segments[segment_count++];
    slot->cmd = LC_SEGMENT_64;
    slot->cmdsize = sizeofcmds;
    slot->flags = rd32(cmdbuf + 68);
    slot->vmaddr = rd64(cmdbuf + 24);
    slot->vmsize = rd64(cmdbuf + 32);
    slot->fileoff = rd64(cmdbuf + 40);
    slot->filesize = rd64(cmdbuf + 48);
    slot->maxprot = rd32(cmdbuf + 56);
    slot->initprot = rd32(cmdbuf + 60);
    slot->nsects = rd32(cmdbuf + 64);
  }
  info->nsegments = segment_count;

  /* Entry point: first executable segment (PF_X), else first segment. */
  for (uint32_t i = 0; i < segment_count; i++) {
    if (info->segments[i].flags & pf_x) { info->entry = info->segments[i].vmaddr; break; }
  }
  if (segment_count == 0) {
    info->entry = 0;
  }

  fclose(f);
  return 0;
}