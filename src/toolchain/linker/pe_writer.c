/*==========================================================================
 * Phase 4: PE Executable Writer - Fully Reverse Engineered
 *
 * Builds a complete PE32+ executable from merged sections.
 *
 * File layout produced:
 *   [DOS Header 64B][DOS Stub 64B][PE Sig 4B][COFF Hdr 20B]
 *   [Optional Header 240B][Section Headers 40B * N]
 *   [Padding to FileAlign]
 *   [Section 1 raw data, padded to FileAlign]
 *   [Section 2 raw data, padded to FileAlign]
 *   ...
 *
 * Key constants:
 *   FileAlignment    = 0x200  (512 bytes)
 *   SectionAlignment = 0x1000 (4096 bytes)
 *   ImageBase        = 0x0000000140000000 (default x64)
 *   PE Signature offset (e_lfanew) = 0xC0
 *=========================================================================*/
#include "pe_writer.h"
#include "section_merge.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define PE_FILE_ALIGNMENT    0x200
#define PE_SECTION_ALIGNMENT 0x1000
#define PE_DEFAULT_IMAGE_BASE 0x0000000140000000ULL
#define PE_MAX_SECTIONS      96
#define PE_LFANEW_OFFSET     0xC0
#define PE_OPTIONAL_HDR_SIZE 0xF0   /* PE32+ optional header = 240 bytes */
#define PE_NUM_DATA_DIRS     16
#define PE_MAX_IMPORTS       32

/* Data directory indices (PE32+ optional header) */
#define PE_DATA_DIR_EXPORT       0
#define PE_DATA_DIR_IMPORT       1
#define PE_DATA_DIR_RESOURCE     2
#define PE_DATA_DIR_EXCEPTION    3
#define PE_DATA_DIR_SECURITY     4
#define PE_DATA_DIR_BASERELOC    5
#define PE_DATA_DIR_DEBUG        6
#define PE_DATA_DIR_ARCHITECTURE 7
#define PE_DATA_DIR_GLOBALPTR    8
#define PE_DATA_DIR_TLS          9
#define PE_DATA_DIR_LOAD_CONFIG  10
#define PE_DATA_DIR_BOUND_IMPORT 11
#define PE_DATA_DIR_IAT          12
#define PE_DATA_DIR_DELAY_IMPORT 13
#define PE_DATA_DIR_CLR_HEADER   14
#define PE_DATA_DIR_RESERVED     15

/* ---- Internal import record ---- */
typedef struct {
  char  dllName[64];
  char  funcName[64];
  uint32_t iatRva;       /* RVA of IAT slot for this function */
  uint32_t hintNameRva;  /* RVA of hint/name entry */
} pe_import_t;

/* ---- Internal section record ---- */
typedef struct {
  char     name[9];
  uint8_t *data;
  size_t   data_len;       /* actual data bytes */
  uint32_t virtual_size;   /* virtual size (>= data_len for BSS) */
  uint32_t rva;            /* virtual address relative to image base */
  uint32_t raw_offset;     /* file offset to raw data */
  uint32_t raw_size;       /* file-aligned raw data size */
  uint32_t characteristics;
  int      owns_data;      /* 1 if we malloc'd data (need to free) */
} pe_section_t;

/* ---- PE builder state ---- */
struct pe_builder {
  uint16_t machine;
  uint16_t subsystem;
  uint32_t entry_rva;
  uint64_t image_base;
  uint64_t stack_reserve;
  uint64_t stack_commit;
  uint64_t heap_reserve;
  uint64_t heap_commit;

  pe_section_t sections[PE_MAX_SECTIONS];
  int num_sections;

  pe_import_t imports[PE_MAX_IMPORTS];
  int num_imports;

  /* Entry stub injection */
  uint8_t entry_stub_code[256];
  size_t entry_stub_size;
  uint32_t entry_stub_rva;
  uint32_t entry_stub_main_rva;
  uint32_t entry_stub_exit_process_iat_rva;
  int has_entry_stub;

  uint32_t size_of_headers;  /* file-aligned headers size */
  uint32_t size_of_image;    /* section-aligned total image size */
  uint32_t timestamp;
};

/* ---- Alignment helpers ---- */
static uint32_t falign(uint32_t v) { return (v + PE_FILE_ALIGNMENT - 1) & ~(PE_FILE_ALIGNMENT - 1); }
static uint32_t salign(uint32_t v) { return (v + PE_SECTION_ALIGNMENT - 1) & ~(PE_SECTION_ALIGNMENT - 1); }

/* ---- Little-endian write helpers ---- */
static void w16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void w32(uint8_t *p, uint32_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void w64(uint8_t *p, uint64_t v) { w32(p,(uint32_t)v); w32(p+4,(uint32_t)(v>>32)); }

/*--------------------------------------------------------------------------
 * Create a new PE builder.
 *------------------------------------------------------------------------*/
pe_builder_t *pe_builder_new(uint16_t machine) {
  pe_builder_t *pb = (pe_builder_t *)calloc(1, sizeof(pe_builder_t));
  if (!pb) return NULL;
  pb->machine       = machine;
  pb->subsystem     = PE_SUBSYS_CONSOLE;
  pb->image_base    = PE_DEFAULT_IMAGE_BASE;
  pb->stack_reserve = 0x100000;   /* 1 MB */
  pb->stack_commit  = 0x1000;     /* 4 KB */
  pb->heap_reserve  = 0x100000;
  pb->heap_commit   = 0x1000;
  pb->entry_rva     = 0;
  pb->timestamp     = (uint32_t)time(NULL);
  return pb;
}

void pe_builder_free(pe_builder_t *pb) {
  if (!pb) return;
  for (int i = 0; i < pb->num_sections; i++) {
    if (pb->sections[i].owns_data)
      free(pb->sections[i].data);
  }
  free(pb);
}

void pe_builder_add_import(pe_builder_t *pb, const char *dllName,
                           const char *funcName) {
  if (!pb || pb->num_imports >= PE_MAX_IMPORTS) return;
  pe_import_t *imp = &pb->imports[pb->num_imports++];
  memset(imp, 0, sizeof(*imp));
  strncpy(imp->dllName, dllName, sizeof(imp->dllName) - 1);
  strncpy(imp->funcName, funcName, sizeof(imp->funcName) - 1);
  imp->iatRva = 0;
  imp->hintNameRva = 0;
}

void pe_builder_set_entry_stub(pe_builder_t *pb, const uint8_t *code,
                               size_t codeSize, uint32_t mainRva,
                               uint32_t exitProcessIatRva) {
  if (!pb || !code || codeSize == 0 || codeSize > sizeof(pb->entry_stub_code))
    return;
  memcpy(pb->entry_stub_code, code, codeSize);
  pb->entry_stub_size = codeSize;
  pb->entry_stub_main_rva = mainRva;
  pb->entry_stub_exit_process_iat_rva = exitProcessIatRva;
  pb->has_entry_stub = 1;
}

void pe_builder_set_entry(pe_builder_t *pb, uint32_t rva)         { if (pb) pb->entry_rva = rva; }
void pe_builder_set_image_base(pe_builder_t *pb, uint64_t base)   { if (pb) pb->image_base = base; }
void pe_builder_set_subsystem(pe_builder_t *pb, uint16_t subsys)  { if (pb) pb->subsystem = subsys; }
void pe_builder_set_stack(pe_builder_t *pb, uint64_t r, uint64_t c) { if (pb) { pb->stack_reserve=r; pb->stack_commit=c; } }
void pe_builder_set_heap(pe_builder_t *pb, uint64_t r, uint64_t c)  { if (pb) { pb->heap_reserve=r; pb->heap_commit=c; } }

/*--------------------------------------------------------------------------
 * Add a section manually.
 *------------------------------------------------------------------------*/
void pe_builder_add_section(pe_builder_t *pb, const char *name,
                            const uint8_t *data, size_t len, uint32_t characteristics) {
  if (!pb || pb->num_sections >= PE_MAX_SECTIONS) return;
  pe_section_t *s = &pb->sections[pb->num_sections];
  size_t nlen = strlen(name);
  if (nlen > 8) nlen = 8;
  memcpy(s->name, name, nlen);
  s->name[nlen] = '\0';
  if (data && len > 0) {
    s->data = (uint8_t *)malloc(len);
    if (s->data) memcpy(s->data, data, len);
    s->data_len = len;
    s->owns_data = 1;
  }
  s->virtual_size = (uint32_t)len;
  s->characteristics = characteristics;
  pb->num_sections++;
}

/*--------------------------------------------------------------------------
 * Import sections from merge context.
 *------------------------------------------------------------------------*/
int pe_builder_from_merge(pe_builder_t *pb, merge_context_t *ctx) {
  if (!pb || !ctx || !ctx->head) return -1;

  for (merged_section_t *m = ctx->head; m; m = m->next) {
    if (pb->num_sections >= PE_MAX_SECTIONS) break;
    pe_section_t *s = &pb->sections[pb->num_sections];
    strncpy(s->name, m->name, 8);
    s->name[8] = '\0';
    s->data = m->data;
    s->data_len = m->data_len;
    s->virtual_size = m->virtual_size;
    s->rva = m->rva;
    s->characteristics = m->characteristics;
    s->owns_data = 0; /* merge context owns the data */
    pb->num_sections++;
  }
  return 0;
}

/*--------------------------------------------------------------------------
 * Build import directory data block.
 *
 * Linear layout (all offsets relative to start of this buffer, which will
 * be placed at the .idata section's raw offset):
 *
 *   [Import Directory Table]        (numDlls + 1) entries x 20 bytes
 *   [DLL name strings]              null-terminated, concatenated
 *   [Import Lookup Tables]          per DLL: (numFuncs + 1) x 8-byte entries
 *   [Import Address Tables]         per DLL: (numFuncs + 1) x 8-byte entries
 *   [Hint/Name entries]             per function: 2-byte hint + name + NUL
 *
 * Returns malloc'd buffer (caller frees), or NULL on failure.
 * Sets *outSize to total bytes, *outImportDirRva to offset of directory table.
 *------------------------------------------------------------------------*/
static uint8_t *build_import_data(pe_builder_t *pb,
                                   uint32_t *outSize,
                                   uint32_t *outImportDirRva,
                                   uint32_t *outFirstIatEntryRva) {
  if (!pb || pb->num_imports == 0 || !outSize || !outImportDirRva) return NULL;

  /* Count unique DLLs and functions per DLL */
  char dllNames[PE_MAX_IMPORTS][64];
  int  dllFuncCounts[PE_MAX_IMPORTS];
  char dllFuncNames[PE_MAX_IMPORTS][PE_MAX_IMPORTS][64];
  int numDlls = 0;

  for (int i = 0; i < pb->num_imports; i++) {
    pe_import_t *imp = &pb->imports[i];
    int found = -1;
    for (int g = 0; g < numDlls; g++) {
      if (strcmp(dllNames[g], imp->dllName) == 0) { found = g; break; }
    }
    if (found < 0) {
      found = numDlls++;
      strcpy(dllNames[found], imp->dllName);
      dllFuncCounts[found] = 0;
    }
    strcpy(dllFuncNames[found][dllFuncCounts[found]++], imp->funcName);
  }

  /* Precompute per-DLL ILT and IAT start offsets */
  uint32_t iltStarts[PE_MAX_IMPORTS];
  uint32_t iatStarts[PE_MAX_IMPORTS];
  uint32_t hintNameRVAs[PE_MAX_IMPORTS][PE_MAX_IMPORTS];

  /* Calculate section sizes */
  uint32_t dirTableSize  = (uint32_t)(numDlls + 1) * 20;
  uint32_t dllNamesSize  = 0;
  uint32_t iltSize       = 0;
  uint32_t iatSize       = 0;
  uint32_t hintNameSize  = 0;

  uint32_t runningILT = 0;
  uint32_t runningIAT = 0;
  uint32_t runningHint = 0;

  for (int g = 0; g < numDlls; g++) {
    iltStarts[g] = runningILT;
    iatStarts[g] = runningIAT;
    runningILT += (uint32_t)(dllFuncCounts[g] + 1) * 8;
    runningIAT += (uint32_t)(dllFuncCounts[g] + 1) * 8;

    dllNamesSize += (uint32_t)strlen(dllNames[g]) + 1;
    for (int f = 0; f < dllFuncCounts[g]; f++) {
      hintNameRVAs[g][f] = runningHint;
      runningHint += 2 + (uint32_t)strlen(dllFuncNames[g][f]) + 1;
    }
  }

  iltSize = runningILT;
  iatSize = runningIAT;
  hintNameSize = runningHint;

  uint32_t totalSize = dirTableSize + dllNamesSize + iltSize + iatSize + hintNameSize;
  uint8_t *buf = (uint8_t *)calloc(1, totalSize);
  if (!buf) return NULL;

  /* Offsets within buffer */
  uint32_t dirTableOff    = 0;
  uint32_t dllNamesOff    = dirTableSize;
  uint32_t iltOff         = dllNamesOff + dllNamesSize;
  uint32_t iatOff         = iltOff + iltSize;
  uint32_t hintNameOff    = iatOff + iatSize;

  *outSize = totalSize;
  *outImportDirRva = dirTableOff;

  uint32_t curDllNameOff = dllNamesOff;
  uint32_t curHintNameOff = hintNameOff;

  /* Hint/Name blobs — section-relative RVAs = hintNameOff + local offs */
  for (int g = 0; g < numDlls; g++) {
    for (int f = 0; f < dllFuncCounts[g]; f++) {
      uint16_t hint = 0;
      size_t nameLen = strlen(dllFuncNames[g][f]);
      uint32_t hnRel = hintNameOff + hintNameRVAs[g][f];
      memcpy(buf + hnRel, &hint, 2);
      memcpy(buf + hnRel + 2, dllFuncNames[g][f], nameLen + 1);
    }
  }

  /* ILT / IAT: store section-relative Hint/Name RVAs (base added after layout) */
  uint32_t curILTOff = iltOff;
  for (int g = 0; g < numDlls; g++) {
    for (int f = 0; f < dllFuncCounts[g]; f++) {
      w64(buf + curILTOff, hintNameOff + hintNameRVAs[g][f]);
      curILTOff += 8;
    }
    w64(buf + curILTOff, 0);
    curILTOff += 8;
  }
  uint32_t curIATOff = iatOff;
  for (int g = 0; g < numDlls; g++) {
    for (int f = 0; f < dllFuncCounts[g]; f++) {
      w64(buf + curIATOff, hintNameOff + hintNameRVAs[g][f]);
      curIATOff += 8;
    }
    w64(buf + curIATOff, 0);
    curIATOff += 8;
  }

  /* DLL names + directory (section-relative RVAs) */
  uint32_t dllNameRvas[PE_MAX_IMPORTS];
  for (int g = 0; g < numDlls; g++) {
    dllNameRvas[g] = curDllNameOff;
    memcpy(buf + curDllNameOff, dllNames[g], strlen(dllNames[g]) + 1);
    curDllNameOff += (uint32_t)strlen(dllNames[g]) + 1;
  }
  for (int g = 0; g < numDlls; g++) {
    w32(buf + dirTableOff + g * 20 + 0, iltOff + iltStarts[g]);
    w32(buf + dirTableOff + g * 20 + 4, 0);
    w32(buf + dirTableOff + g * 20 + 8, 0);
    w32(buf + dirTableOff + g * 20 + 12, dllNameRvas[g]);
    w32(buf + dirTableOff + g * 20 + 16, iatOff + iatStarts[g]);
  }

  *outSize = totalSize;
  *outImportDirRva = dirTableOff;
  if (outFirstIatEntryRva) *outFirstIatEntryRva = iatOff + iatStarts[0];
  return buf;
}

/*--------------------------------------------------------------------------
 * Calculate layout and write the PE file.
 *
 * Layout calculation:
 *   1. Headers size = DOS(64) + stub(64) + PEsig(4) + COFF(20) +
 *                     OptHdr(240) + SecHdrs(40*N)
 *   2. Round headers to FileAlignment
 *   3. For each section:
 *      - raw_offset = current file position (file-aligned)
 *      - raw_size = file-aligned data length
 *      - rva = section-aligned virtual address
 *      - virtual_size = max(data_len, virtual_size)
 *   4. size_of_image = section-aligned end of last section
 *------------------------------------------------------------------------*/
int pe_builder_write(pe_builder_t *pb, const char *out_path) {
  if (!pb || !out_path) return -1;

  /*==== Step 1a: Build import directory and add .idata section ====*/
  uint8_t *importData = NULL;
  uint32_t importDataSize = 0;
  uint32_t importDirRvaInSection = 0;
  uint32_t firstIatEntryRva = 0;
  if (pb->num_imports > 0) {
    importData = build_import_data(pb, &importDataSize, &importDirRvaInSection,
                                   &firstIatEntryRva);
    if (!importData) { return -1; }
    /* add_section copies bytes; safe to free builder buffer after. */
    pe_builder_add_section(pb, ".idata", importData, importDataSize,
                           0xC0000040); /* INITIALIZED_DATA | READ | WRITE */
    free(importData);
    importData = NULL;
  } /* close num_imports — required before stub section */

  /*==== Step 1b: Add entry stub section if needed ====*/
  if (pb->has_entry_stub) {
    pe_builder_add_section(pb, ".stub", pb->entry_stub_code, pb->entry_stub_size,
                           0x60000020); /* CODE | EXECUTE | READ */
  }

  /*==== Step 1c: Header sizes AFTER all sections are known ====*/
  uint32_t dos_hdr_size    = 64;
  uint32_t dos_stub_size   = PE_LFANEW_OFFSET - dos_hdr_size;
  uint32_t pe_sig_size     = 4;
  uint32_t coff_hdr_size   = 20;
  uint32_t opt_hdr_size    = PE_OPTIONAL_HDR_SIZE;
  uint32_t sec_hdrs_size   = (uint32_t)pb->num_sections * 40;
  uint32_t raw_headers     = PE_LFANEW_OFFSET + pe_sig_size + coff_hdr_size +
                             opt_hdr_size + sec_hdrs_size;
  pb->size_of_headers = falign(raw_headers);

  /*==== Step 2: Calculate section layout ====*/
  uint32_t file_offset = pb->size_of_headers;
  uint32_t virt_offset = PE_SECTION_ALIGNMENT; /* first section at 0x1000 */

  for (int i = 0; i < pb->num_sections; i++) {
    pe_section_t *s = &pb->sections[i];

    /* Virtual layout */
    if (s->rva == 0) s->rva = virt_offset;
    if (s->virtual_size < (uint32_t)s->data_len)
      s->virtual_size = (uint32_t)s->data_len;

    /* File layout */
    s->raw_offset = file_offset;
    s->raw_size = (s->data_len > 0) ? falign((uint32_t)s->data_len) : 0;

    file_offset += s->raw_size;
    virt_offset = salign(s->rva + s->virtual_size);
  }

  pb->size_of_image = virt_offset;

  /*==== Step 2a: Fixup .idata RVAs to absolute, patch entry stub ====*/
  int idataSectionIdx = -1;
  int stubSectionIdx = -1;
  for (int i = 0; i < pb->num_sections; i++) {
    if (strcmp(pb->sections[i].name, ".idata") == 0) idataSectionIdx = i;
    if (strcmp(pb->sections[i].name, ".stub") == 0) stubSectionIdx = i;
  }

  /* Import table fields are section-relative until now — promote to image RVAs. */
  if (idataSectionIdx >= 0 && pb->num_imports > 0) {
    pe_section_t *idataSec = &pb->sections[idataSectionIdx];
    uint8_t *id = idataSec->data;
    uint32_t base = idataSec->rva;
    if (id && idataSec->data_len >= 20) {
      for (int g = 0; ; g++) {
        uint32_t oft = id[g * 20 + 0] | (id[g * 20 + 1] << 8) |
                       (id[g * 20 + 2] << 16) | (id[g * 20 + 3] << 24);
        uint32_t name = id[g * 20 + 12] | (id[g * 20 + 13] << 8) |
                        (id[g * 20 + 14] << 16) | (id[g * 20 + 15] << 24);
        uint32_t ft = id[g * 20 + 16] | (id[g * 20 + 17] << 8) |
                      (id[g * 20 + 18] << 16) | (id[g * 20 + 19] << 24);
        if (oft == 0 && name == 0 && ft == 0) break;
        w32(id + g * 20 + 0, oft + base);
        w32(id + g * 20 + 12, name + base);
        w32(id + g * 20 + 16, ft + base);
        /* Promote ILT + IAT Hint/Name RVAs (qword entries until null). */
        for (int t = 0; t < 2; t++) {
          uint32_t table = (t == 0 ? oft : ft) + base;
          uint32_t off = table - base;
          while (off + 8 <= idataSec->data_len) {
            uint64_t ent = 0;
            memcpy(&ent, id + off, 8);
            if (ent == 0) break;
            if ((ent >> 63) == 0) { /* not ordinal */
              uint64_t abs = (ent & 0x7FFFFFFFu) + base;
              memcpy(id + off, &abs, 8);
            }
            off += 8;
          }
        }
      }
      firstIatEntryRva = base + firstIatEntryRva;
    }
  }

  if (pb->has_entry_stub && stubSectionIdx >= 0) {
    pe_section_t *stubSec = &pb->sections[stubSectionIdx];
    uint32_t stubRva = stubSec->rva;
    uint32_t mainRva = pb->entry_stub_main_rva;
    uint8_t *stubCode = stubSec->data;
    if (!stubCode || stubSec->data_len < 0x12) return -1;

    /* E8 @ +4: disp @ +5; next insn @ stubRva+9 */
    if (stubCode[4] != 0xE8) {
      fprintf(stderr, "[pe_writer] ERROR: stub missing E8 call main\n");
      return -1;
    }
    int64_t deltaMain = (int64_t)mainRva - (int64_t)(stubRva + 9);
    if (deltaMain < INT32_MIN || deltaMain > INT32_MAX) {
      fprintf(stderr, "[pe_writer] ERROR: call main REL32 overflow\n");
      return -1;
    }
    w32(stubCode + 5, (uint32_t)deltaMain);

    /* FF 15 @ +0x0B: disp @ +0x0D; next insn @ stubRva+0x11 */
    if (stubSec->data_len < 0x12 ||
        stubCode[0x0B] != 0xFF || stubCode[0x0C] != 0x15) {
      fprintf(stderr, "[pe_writer] ERROR: stub missing FF15 IAT call\n");
      return -1;
    }
    uint32_t iatSlotRva = firstIatEntryRva;
    if (iatSlotRva == 0 && pb->entry_stub_exit_process_iat_rva)
      iatSlotRva = pb->entry_stub_exit_process_iat_rva;
    if (iatSlotRva != 0) {
      int64_t deltaIat = (int64_t)iatSlotRva - (int64_t)(stubRva + 0x11);
      if (deltaIat < INT32_MIN || deltaIat > INT32_MAX) {
        fprintf(stderr, "[pe_writer] ERROR: IAT RIP-rel overflow\n");
        return -1;
      }
      w32(stubCode + 0x0D, (uint32_t)deltaIat);
    }

    pb->entry_rva = stubRva;
  }

  /*==== Step 3: Build the file in memory ====*/
  uint32_t total_file_size = file_offset;
  uint8_t *image = (uint8_t *)calloc(1, total_file_size);
  if (!image) return -1;

  /*---- DOS Header (64 bytes) ----
   * Only critical fields: e_magic (MZ) and e_lfanew (offset to PE sig)
   */
  image[0] = 0x4D; image[1] = 0x5A; /* "MZ" */
  w32(image + 0x3C, PE_LFANEW_OFFSET); /* e_lfanew */

  /*---- DOS Stub (PE_LFANEW_OFFSET - 64 bytes) ----
   * Minimal stub: "This program cannot be run in DOS mode.\r\n$"
   */
  static const char dos_msg[] = "This program cannot be run in DOS mode.\r\n$";
  if (dos_stub_size > sizeof(dos_msg))
    memcpy(image + dos_hdr_size, dos_msg, sizeof(dos_msg));

  uint32_t pe_off = PE_LFANEW_OFFSET;

  /*---- PE Signature (4 bytes) ----*/
  image[pe_off] = 'P'; image[pe_off+1] = 'E';
  image[pe_off+2] = 0;  image[pe_off+3] = 0;
  pe_off += 4;

  /*---- COFF File Header (20 bytes) ----
   * Offset  Size  Field
   * 0       2     Machine
   * 2       2     NumberOfSections
   * 4       4     TimeDateStamp
   * 8       4     PointerToSymbolTable (0)
   * 12      4     NumberOfSymbols (0)
   * 16      2     SizeOfOptionalHeader
   * 18      2     Characteristics
   */
  w16(image + pe_off + 0, pb->machine);
  w16(image + pe_off + 2, (uint16_t)pb->num_sections);
  w32(image + pe_off + 4, pb->timestamp);
  w32(image + pe_off + 8, 0);  /* no symbol table in exe */
  w32(image + pe_off + 12, 0);
  w16(image + pe_off + 16, PE_OPTIONAL_HDR_SIZE);
  /* Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE */
  w16(image + pe_off + 18, 0x0022);
  pe_off += 20;

  /*---- Optional Header PE32+ (240 bytes) ----
   * Standard fields (24 bytes):
   *   0     2   Magic (0x020B = PE32+)
   *   2     1   MajorLinkerVersion
   *   3     1   MinorLinkerVersion
   *   4     4   SizeOfCode
   *   8     4   SizeOfInitializedData
   *   12    4   SizeOfUninitializedData
   *   16    4   AddressOfEntryPoint
   *   20    4   BaseOfCode
   *
   * Windows-specific fields (88 bytes):
   *   24    8   ImageBase
   *   32    4   SectionAlignment
   *   36    4   FileAlignment
   *   40    2   MajorOSVersion
   *   42    2   MinorOSVersion
   *   44    2   MajorImageVersion
   *   46    2   MinorImageVersion
   *   48    2   MajorSubsystemVersion
   *   50    2   MinorSubsystemVersion
   *   52    4   Win32VersionValue (0)
   *   56    4   SizeOfImage
   *   60    4   SizeOfHeaders
   *   64    4   CheckSum (0, filled by tools)
   *   68    2   Subsystem
   *   70    2   DllCharacteristics
   *   72    8   SizeOfStackReserve
   *   80    8   SizeOfStackCommit
   *   88    8   SizeOfHeapReserve
   *   96    8   SizeOfHeapCommit
   *   104   4   LoaderFlags (0)
   *   108   4   NumberOfRvaAndSizes
   *
   * Data directories (128 bytes = 16 x 8):
   *   112   8   Export Table RVA + Size
   *   120   8   Import Table
   *   128   8   Resource Table
   *   136   8   Exception Table
   *   144   8   Certificate Table
   *   152   8   Base Relocation Table
   *   160   8   Debug
   *   168   8   Architecture (0)
   *   176   8   Global Ptr (0)
   *   184   8   TLS Table
   *   192   8   Load Config Table
   *   200   8   Bound Import
   *   208   8   IAT
   *   216   8   Delay Import Descriptor
   *   224   8   CLR Runtime Header
   *   232   8   Reserved (0)
   */
  uint8_t *opt = image + pe_off;

  /* Standard fields */
  w16(opt + 0, 0x020B);   /* PE32+ magic */
  opt[2] = 1;              /* Major linker version */
  opt[3] = 0;              /* Minor linker version */

  /* Calculate code/data sizes */
  uint32_t code_size = 0, idata_size = 0, udata_size = 0;
  uint32_t base_of_code = 0;
  for (int i = 0; i < pb->num_sections; i++) {
    pe_section_t *s = &pb->sections[i];
    if (s->characteristics & 0x00000020) { /* CODE */
      code_size += s->raw_size;
      if (base_of_code == 0) base_of_code = s->rva;
    }
    if (s->characteristics & 0x00000040) idata_size += s->raw_size;
    if (s->characteristics & 0x00000080) udata_size += s->virtual_size;
  }

  w32(opt + 4, code_size);
  w32(opt + 8, idata_size);
  w32(opt + 12, udata_size);
  w32(opt + 16, pb->entry_rva);
  w32(opt + 20, base_of_code);

  /* Windows-specific fields */
  w64(opt + 24, pb->image_base);
  w32(opt + 32, PE_SECTION_ALIGNMENT);
  w32(opt + 36, PE_FILE_ALIGNMENT);
  w16(opt + 40, 6);   /* MajorOSVersion (Windows Vista+) */
  w16(opt + 42, 0);
  w16(opt + 44, 0);   /* Image version */
  w16(opt + 46, 0);
  w16(opt + 48, 6);   /* MajorSubsystemVersion */
  w16(opt + 50, 0);
  w32(opt + 52, 0);   /* Win32VersionValue */
  w32(opt + 56, pb->size_of_image);
  w32(opt + 60, pb->size_of_headers);
  w32(opt + 64, 0);   /* CheckSum */
  w16(opt + 68, pb->subsystem);
  w16(opt + 70, PE_DLL_DYNAMIC_BASE | PE_DLL_NX_COMPAT | PE_DLL_HIGH_ENTROPY_VA | PE_DLL_TERMINAL_SERVER);
  w64(opt + 72, pb->stack_reserve);
  w64(opt + 80, pb->stack_commit);
  w64(opt + 88, pb->heap_reserve);
  w64(opt + 96, pb->heap_commit);
  w32(opt + 104, 0);  /* LoaderFlags */
  w32(opt + 108, PE_NUM_DATA_DIRS);

  /* Data directories (112..239) - all zero for minimal exe */
  /* Exception table (.pdata) - if present */
  for (int i = 0; i < pb->num_sections; i++) {
    if (strcmp(pb->sections[i].name, ".pdata") == 0) {
      w32(opt + 112 + 3*8 + 0, pb->sections[i].rva);       /* Exception RVA */
      w32(opt + 112 + 3*8 + 4, pb->sections[i].virtual_size); /* Exception Size */
      break;
    }
  }

  /* Import Directory (index 1): RVA @ opt+120, Size @ opt+124 */
  if (pb->num_imports > 0) {
    for (int i = 0; i < pb->num_sections; i++) {
      if (strcmp(pb->sections[i].name, ".idata") == 0) {
        pe_section_t *idataSec = &pb->sections[i];
        uint32_t importDirRva = idataSec->rva + importDirRvaInSection;
        uint32_t importDirSize = 40; /* 1 DLL + null descriptor default */
        if (idataSec->data && idataSec->data_len >= 20) {
          uint8_t *id = idataSec->data;
          int n = 0;
          while ((uint32_t)((n + 1) * 20) <= idataSec->data_len) {
            uint32_t oft = id[n*20]| (id[n*20+1]<<8)|(id[n*20+2]<<16)|(id[n*20+3]<<24);
            uint32_t nm  = id[n*20+12]|(id[n*20+13]<<8)|(id[n*20+14]<<16)|(id[n*20+15]<<24);
            uint32_t ft  = id[n*20+16]|(id[n*20+17]<<8)|(id[n*20+18]<<16)|(id[n*20+19]<<24);
            if (oft == 0 && nm == 0 && ft == 0) break;
            n++;
          }
          importDirSize = (uint32_t)(n + 1) * 20;
        }
        w32(opt + 120 + 0, importDirRva);
        w32(opt + 120 + 4, importDirSize);
        (void)importDataSize;
        break;
      }
    }
  }

  pe_off += PE_OPTIONAL_HDR_SIZE;

  /*---- Section Headers (40 bytes each) ----
   * Offset  Size  Field
   * 0       8     Name
   * 8       4     VirtualSize
   * 12      4     VirtualAddress
   * 16      4     SizeOfRawData
   * 20      4     PointerToRawData
   * 24      4     PointerToRelocations (0 in exe)
   * 28      4     PointerToLinenumbers (0)
   * 32      2     NumberOfRelocations (0)
   * 34      2     NumberOfLinenumbers (0)
   * 36      4     Characteristics
   */
  for (int i = 0; i < pb->num_sections; i++) {
    pe_section_t *s = &pb->sections[i];
    uint8_t *sh = image + pe_off;
    memcpy(sh, s->name, 8);
    w32(sh + 8,  s->virtual_size);
    w32(sh + 12, s->rva);
    w32(sh + 16, s->raw_size);
    w32(sh + 20, s->raw_offset);
    w32(sh + 24, 0); /* no relocs in exe */
    w32(sh + 28, 0);
    w16(sh + 32, 0);
    w16(sh + 34, 0);
    w32(sh + 36, s->characteristics);
    pe_off += 40;
  }

  /*---- Section Raw Data ----*/
  for (int i = 0; i < pb->num_sections; i++) {
    pe_section_t *s = &pb->sections[i];
    if (s->data && s->data_len > 0 && s->raw_offset + s->data_len <= total_file_size) {
      memcpy(image + s->raw_offset, s->data, s->data_len);
    }
  }

  /*==== Step 4: Write to disk ====*/
  FILE *f = fopen(out_path, "wb");
  if (!f) {
    fprintf(stderr, "[pe_writer] cannot create: %s\n", out_path);
    free(image);
    return -1;
  }

  size_t written = fwrite(image, 1, total_file_size, f);
  fclose(f);
  free(image);

  if (written != total_file_size) {
    fprintf(stderr, "[pe_writer] write error: %zu/%u bytes\n", written, total_file_size);
    return -1;
  }

  fprintf(stderr, "[pe_writer] %s: %u bytes, %d sections, entry=0x%X, base=0x%llX\n",
          out_path, total_file_size, pb->num_sections, pb->entry_rva,
          (unsigned long long)pb->image_base);
  return 0;
}

/*--------------------------------------------------------------------------
 * Dump PE builder state for diagnostics.
 *------------------------------------------------------------------------*/
void pe_builder_dump(pe_builder_t *pb, FILE *out) {
  if (!pb || !out) return;
  fprintf(out, "=== PE Builder ===\n");
  fprintf(out, "  Machine: 0x%04X  Subsystem: %u\n", pb->machine, pb->subsystem);
  fprintf(out, "  ImageBase: 0x%llX  Entry: 0x%08X\n",
          (unsigned long long)pb->image_base, pb->entry_rva);
  fprintf(out, "  SizeOfHeaders: 0x%X  SizeOfImage: 0x%X\n",
          pb->size_of_headers, pb->size_of_image);
  fprintf(out, "  Stack: reserve=0x%llX commit=0x%llX\n",
          (unsigned long long)pb->stack_reserve, (unsigned long long)pb->stack_commit);
  fprintf(out, "  Heap:  reserve=0x%llX commit=0x%llX\n",
          (unsigned long long)pb->heap_reserve, (unsigned long long)pb->heap_commit);
  fprintf(out, "  Sections: %d\n", pb->num_sections);
  for (int i = 0; i < pb->num_sections; i++) {
    pe_section_t *s = &pb->sections[i];
    fprintf(out, "    [%d] %-8s  RVA=0x%08X  VSize=0x%X  RawOff=0x%X  RawSz=0x%X  Chars=0x%08X\n",
            i, s->name, s->rva, s->virtual_size, s->raw_offset, s->raw_size, s->characteristics);
  }
  fprintf(out, "\n");
}
