/*==========================================================================
 * COFF Object Fixture Generator - RawrXD linker test suite
 *
 * Produces COFF .obj files for the linker tests without depending on any
 * external compiler. This is deliberately plain C99 with no dependencies
 * so the linker can be certified on a machine with no toolchain installed.
 *
 * The generated objects exercise:
 *
 *   fixture_exit42.obj   calls kernel32!ExitProcess(42)
 *   fixture_multi.obj    imports from three different DLLs
 *   fixture_undef.obj    references an undefined symbol with no DLL, so the
 *                        linker must refuse to produce an image
 *   fixture_addr64.obj   holds a global pointer, so the image needs base
 *                        relocations
 *=========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---- COFF constants ---- */
#define COFF_MACHINE_AMD64   0x8664
#define SCN_CNT_CODE         0x00000020
#define SCN_CNT_INITIALIZED  0x00000040
#define SCN_MEM_EXECUTE      0x20000000
#define SCN_MEM_READ         0x40000000
#define SCN_MEM_WRITE        0x80000000
#define SCN_ALIGN_16BYTES    0x00500000
#define SYM_CLASS_EXTERNAL   2
#define SYM_CLASS_STATIC     3
#define REL_AMD64_REL32      0x0004

/* ---- Little-endian writers ---- */
static void w8(uint8_t *p, uint8_t v) { p[0] = v; }
static void w16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void w32(uint8_t *p, uint32_t v) {
  p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

/* ---- A symbol to emit ---- */
typedef struct {
  const char *name;
  uint32_t value;
  int16_t  section_num;   /* 1-based; 0 = undefined; -1 = absolute; -2 = debug */
  uint16_t type;
  uint8_t  storage_class;
} sym_t;

/* ---- A relocation to emit ---- */
typedef struct {
  uint32_t offset;
  uint32_t symbol_index;
  uint16_t type;
} reloc_t;

/* ---- A section to emit ---- */
typedef struct {
  const char *name;
  const uint8_t *data;
  uint32_t size;
  uint32_t characteristics;
  uint32_t alignment;
  const reloc_t *relocs;
  uint32_t num_relocs;
} sect_t;

/*
 * Writes a COFF object file.
 */
static int write_coff(const char *path,
                      const sect_t *sections, uint32_t num_sections,
                      const sym_t *symbols, uint32_t num_symbols) {
  /* The string table holds any symbol name longer than 8 characters. */
  char strtab[4096];
  uint32_t strtab_size = 4;         /* the first DWORD is the size */
  uint32_t strtab_offsets[64];
  uint32_t num_long = 0;

  if (num_symbols > 64) { fprintf(stderr, "too many symbols\n"); return -1; }

  for (uint32_t i = 0; i < num_symbols; i++) {
    size_t n = strlen(symbols[i].name);
    if (n <= 8) { strtab_offsets[i] = 0; continue; }
    strtab_offsets[i] = strtab_size;
    memcpy(strtab + strtab_size, symbols[i].name, n + 1);
    strtab_size += (uint32_t)(n + 1);
    num_long++;
  }
  w32(strtab, strtab_size);
  (void)num_long;

  /* Layout: header, section headers, section data, relocations, symbols,
   * string table. */
  uint32_t header_size = 20 + num_sections * 40;

  uint32_t offset = header_size;
  uint32_t section_offsets[32];
  for (uint32_t i = 0; i < num_sections; i++) {
    section_offsets[i] = offset;
    offset += (sections[i].size + 1) & ~1u;   /* align to 2 */
  }

  uint32_t reloc_offsets[32];
  for (uint32_t i = 0; i < num_sections; i++) {
    reloc_offsets[i] = offset;
    offset += sections[i].num_relocs * 10;
  }

  uint32_t symtab_offset = offset;
  offset += num_symbols * 18;

  uint32_t strtab_offset = offset;
  offset += strtab_size;

  uint8_t *buf = (uint8_t *)calloc(1, offset);
  if (!buf) { fprintf(stderr, "out of memory\n"); return -1; }

  /* ---- COFF file header ---- */
  w16(buf + 0, COFF_MACHINE_AMD64);
  w16(buf + 2, (uint16_t)num_sections);
  w32(buf + 4, 0x6AD88007);        /* a fixed timestamp keeps output deterministic */
  w32(buf + 8, symtab_offset);
  w32(buf + 12, num_symbols);
  w16(buf + 16, 0);                 /* no optional header */
  w16(buf + 18, 0);                 /* characteristics */

  /* ---- Section headers ---- */
  for (uint32_t i = 0; i < num_sections; i++) {
    uint8_t *sh = buf + 20 + i * 40;
    size_t n = strlen(sections[i].name);
    if (n > 8) n = 8;
    memcpy(sh, sections[i].name, n);
    w32(sh + 8,  0);                        /* virtual size */
    w32(sh + 12, 0);                        /* virtual address */
    w32(sh + 16, sections[i].size);         /* raw size */
    w32(sh + 20, section_offsets[i]);       /* raw offset */
    w32(sh + 24, sections[i].num_relocs ? reloc_offsets[i] : 0);
    w16(sh + 28, 0);                        /* line numbers */
    w32(sh + 32, sections[i].num_relocs);
    w32(sh + 36, sections[i].characteristics | sections[i].alignment);
  }

  /* ---- Section data ---- */
  for (uint32_t i = 0; i < num_sections; i++) {
    if (sections[i].size && sections[i].data) {
      memcpy(buf + section_offsets[i], sections[i].data, sections[i].size);
    }
  }

  /* ---- Relocations ---- */
  for (uint32_t i = 0; i < num_sections; i++) {
    for (uint32_t r = 0; r < sections[i].num_relocs; r++) {
      uint8_t *re = buf + reloc_offsets[i] + r * 10;
      w32(re + 0, sections[i].relocs[r].offset);
      w32(re + 4, sections[i].relocs[r].symbol_index);
      w16(re + 8, sections[i].relocs[r].type);
    }
  }

  /* ---- Symbol table ---- */
  for (uint32_t i = 0; i < num_symbols; i++) {
    uint8_t *sy = buf + symtab_offset + i * 18;
    size_t n = strlen(symbols[i].name);
    if (n <= 8) {
      memcpy(sy, symbols[i].name, n);
    } else {
      w32(sy, 0);                      /* zeroes + string table offset */
      w32(sy + 4, strtab_offsets[i]);
    }
    w32(sy + 8,  symbols[i].value);
    w16(sy + 12, (uint16_t)symbols[i].section_num);
    w16(sy + 14, symbols[i].type);
    w8 (sy + 16, symbols[i].storage_class);
    w8 (sy + 17, 0);                   /* aux symbol count */
  }

  /* ---- String table ---- */
  memcpy(buf + strtab_offset, strtab, strtab_size);

  FILE *f = fopen(path, "wb");
  if (!f) { fprintf(stderr, "cannot create %s\n", path); free(buf); return -1; }
  fwrite(buf, 1, offset, f);
  fclose(f);
  free(buf);
  return 0;
}

/*==========================================================================
 * Fixture 1: calls kernel32!ExitProcess(42)
 *
 *   0: 48 83 EC 28              sub  rsp, 0x28
 *   4: B9 2A 00 00 00           mov  ecx, 42
 *   9: FF 15 00 00 00 00        call qword ptr [rip + 0]   <- reloc at 11
 *  15: 48 83 C4 28              add  rsp, 0x28
 *  19: C3                       ret
 *
 * Note the encodings. `48 83 EC 28` is `sub rsp, 0x28`: the REX.W prefix
 * plus the 83 /5 opcode with the ModRM byte EC selects RSP. The two byte
 * form `48 2D 28 00 00 00` would be `sub rbp, 0x28`, because the 2D
 * opcode takes its destination register from the low three bits of the
 * opcode byte itself.
 *
 * The frame is 0x28 bytes: 32 bytes of Win64 shadow space plus 8 bytes
 * so that the stack is 16-byte aligned at the call boundary.
 *=========================================================================*/
static const uint8_t kExit42Code[] = {
  0x48, 0x83, 0xEC, 0x28,
  0xB9, 0x2A, 0x00, 0x00, 0x00,
  0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
  0x48, 0x83, 0xC4, 0x28,
  0xC3
};

static int make_exit42(const char *path) {
  static const reloc_t kRelocs[] = { { 11, 2, REL_AMD64_REL32 } };
  static const sect_t kSections[] = {
    { ".text", kExit42Code, sizeof(kExit42Code),
      SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ, SCN_ALIGN_16BYTES,
      kRelocs, 1 }
  };
  /* Symbol 0 is the file symbol, 1 the entry, 2 the import. */
  static const sym_t kSymbols[] = {
    { ".file",              0, -2, 0,    SYM_CLASS_STATIC },
    { "entry",              0,  1, 0x20, SYM_CLASS_EXTERNAL },
    { "__imp_ExitProcess",  0,  0, 0,    SYM_CLASS_EXTERNAL }
  };
  return write_coff(path, kSections, 1, kSymbols, 3);
}

/*==========================================================================
 * Fixture 2: imports from three different DLLs.
 *
 * Every call goes through a single 0x28-byte frame, so the stack stays
 * 16-byte aligned at each call boundary and the Win64 shadow space is
 * reserved.
 *
 *   0: 48 83 EC 28              sub  rsp, 0x28
 *   4: B9 01 00 00 00           mov  ecx, 1
 *   9: FF 15 00 00 00 00        call [rip+0]   -> GetStdHandle          reloc 11
 *  15: B9 02 00 00 00           mov  ecx, 2
 *  20: FF 15 00 00 00 00        call [rip+0]   -> GetCurrentProcessId   reloc 22
 *  26: B9 03 00 00 00           mov  ecx, 3
 *  31: FF 15 00 00 00 00        call [rip+0]   -> GetTickCount          reloc 33
 *  37: B9 2A 00 00 00           mov  ecx, 42
 *  42: FF 15 00 00 00 00        call [rip+0]   -> ExitProcess           reloc 44
 *  48: 48 83 C4 28              add  rsp, 0x28
 *  52: C3                       ret
 *=========================================================================*/
static const uint8_t kMultiCode[] = {
  0x48, 0x83, 0xEC, 0x28,
  0xB9, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
  0xB9, 0x02, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
  0xB9, 0x03, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
  0xB9, 0x2A, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
  0x48, 0x83, 0xC4, 0x28,
  0xC3
};

static int make_multi(const char *path) {
  static const reloc_t kRelocs[] = {
    { 11, 2, REL_AMD64_REL32 },   /* GetStdHandle        */
    { 22, 3, REL_AMD64_REL32 },   /* GetCurrentProcessId */
    { 33, 4, REL_AMD64_REL32 },   /* GetTickCount        */
    { 44, 1, REL_AMD64_REL32 }    /* ExitProcess         */
  };
  static const sect_t kSections[] = {
    { ".text", kMultiCode, sizeof(kMultiCode),
      SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ, SCN_ALIGN_16BYTES,
      kRelocs, 4 }
  };
  static const sym_t kSymbols[] = {
    { ".file",                   0, -2, 0,    SYM_CLASS_STATIC },
    { "__imp_ExitProcess",       0,  0, 0,    SYM_CLASS_EXTERNAL },
    { "__imp_GetStdHandle",      0,  0, 0,    SYM_CLASS_EXTERNAL },
    { "__imp_GetCurrentProcessId",0,  0, 0,    SYM_CLASS_EXTERNAL },
    { "__imp_GetTickCount",      0,  0, 0,    SYM_CLASS_EXTERNAL },
    { "entry",                   0,  1, 0x20, SYM_CLASS_EXTERNAL }
  };
  return write_coff(path, kSections, 1, kSymbols, 6);
}

/*==========================================================================
 * Fixture 3: an undefined symbol with no known DLL.
 *
 * The linker must refuse to emit an image for this object rather than
 * silently resolving the symbol to RVA 0.
 *=========================================================================*/
static const uint8_t kUndefCode[] = {
  0xB9, 0x07, 0x00, 0x00, 0x00,
  0xE8, 0x00, 0x00, 0x00, 0x00,
  0xC3
};

static int make_undef(const char *path) {
  static const reloc_t kRelocs[] = { { 6, 1, REL_AMD64_REL32 } };
  static const sect_t kSections[] = {
    { ".text", kUndefCode, sizeof(kUndefCode),
      SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ, SCN_ALIGN_16BYTES,
      kRelocs, 1 }
  };
  static const sym_t kSymbols[] = {
    { ".file",                          0, -2, 0,    SYM_CLASS_STATIC },
    { "ThisSymbolDoesNotExistAnywhere", 0,  0, 0,    SYM_CLASS_EXTERNAL },
    { "entry",                          0,  1, 0x20, SYM_CLASS_EXTERNAL }
  };
  return write_coff(path, kSections, 1, kSymbols, 3);
}

/*==========================================================================
 * Fixture 4: a global 64-bit pointer, so the image needs base relocations.
 *
 *   0: 48 8B 0D 00 00 00 00     mov rcx, qword ptr [rip + 0]   <- reloc at 3
 *   7: 48 89 C8                 mov rax, rcx
 *  10: C3                       ret
 *=========================================================================*/
static const uint8_t kAddr64Code[] = {
  0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
  0x48, 0x89, 0xC8,
  0xC3
};
static const uint8_t kAddr64Data[] = {
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

static int make_addr64(const char *path) {
  static const reloc_t kRelocs[] = { { 3, 1, REL_AMD64_REL32 } };
  static const sect_t kSections[] = {
    { ".text", kAddr64Code, sizeof(kAddr64Code),
      SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ, SCN_ALIGN_16BYTES,
      kRelocs, 1 },
    { ".data", kAddr64Data, sizeof(kAddr64Data),
      SCN_CNT_INITIALIZED | SCN_MEM_READ | SCN_MEM_WRITE, 0, NULL, 0 }
  };
  static const sym_t kSymbols[] = {
    { ".file",  0, -2, 0,    SYM_CLASS_STATIC },
    { "gValue", 0,  2, 0,    SYM_CLASS_STATIC },
    { "entry",  0,  1, 0x20, SYM_CLASS_EXTERNAL }
  };
  return write_coff(path, kSections, 2, kSymbols, 3);
}

/*==========================================================================
 * Fixture 5: a tail jump to the imported function, with no stack
 * adjustment and no call.
 *
 *   0: B9 2A 00 00 00           mov  ecx, 42
 *   5: FF 25 00 00 00 00        jmp  qword ptr [rip + 0]    <- reloc at 7
 *=========================================================================*/
static const uint8_t kTailCode[] = {
  0xB9, 0x2A, 0x00, 0x00, 0x00,
  0xFF, 0x25, 0x00, 0x00, 0x00, 0x00
};

static int make_tail(const char *path) {
  static const reloc_t kRelocs[] = { { 7, 2, REL_AMD64_REL32 } };
  static const sect_t kSections[] = {
    { ".text", kTailCode, sizeof(kTailCode),
      SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ, SCN_ALIGN_16BYTES,
      kRelocs, 1 }
  };
  static const sym_t kSymbols[] = {
    { ".file",              0, -2, 0,    SYM_CLASS_STATIC },
    { "entry",              0,  1, 0x20, SYM_CLASS_EXTERNAL },
    { "__imp_ExitProcess",  0,  0, 0,    SYM_CLASS_EXTERNAL }
  };
  return write_coff(path, kSections, 1, kSymbols, 3);
}

/*==========================================================================
 * Fixture 6: a call to the imported function with a proper frame.
 *
 *   0: 48 83 EC 28              sub  rsp, 0x28
 *   4: B9 07 00 00 00           mov  ecx, 7
 *   9: FF 15 00 00 00 00        call qword ptr [rip + 0]    <- reloc at 11
 *  15: 48 83 C4 28              add  rsp, 0x28
 *  19: C3                       ret
 *=========================================================================*/
static const uint8_t kCallCode[] = {
  0x48, 0x83, 0xEC, 0x28,
  0xB9, 0x07, 0x00, 0x00, 0x00,
  0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
  0x48, 0x83, 0xC4, 0x28,
  0xC3
};

static int make_call(const char *path) {
  static const reloc_t kRelocs[] = { { 11, 2, REL_AMD64_REL32 } };
  static const sect_t kSections[] = {
    { ".text", kCallCode, sizeof(kCallCode),
      SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ, SCN_ALIGN_16BYTES,
      kRelocs, 1 }
  };
  static const sym_t kSymbols[] = {
    { ".file",              0, -2, 0,    SYM_CLASS_STATIC },
    { "entry",              0,  1, 0x20, SYM_CLASS_EXTERNAL },
    { "__imp_ExitProcess",  0,  0, 0,    SYM_CLASS_EXTERNAL }
  };
  return write_coff(path, kSections, 1, kSymbols, 3);
}

/*==========================================================================
 * main
 *==========================================================================*/
int main(int argc, char **argv) {
  const char *outdir = (argc > 1) ? argv[1] : ".";
  char path[1024];

  snprintf(path, sizeof(path), "%s/fixture_exit42.obj", outdir);
  if (make_exit42(path) != 0) return 1;

  snprintf(path, sizeof(path), "%s/fixture_multi.obj", outdir);
  if (make_multi(path) != 0) return 1;

  snprintf(path, sizeof(path), "%s/fixture_undef.obj", outdir);
  if (make_undef(path) != 0) return 1;

  snprintf(path, sizeof(path), "%s/fixture_addr64.obj", outdir);
  if (make_addr64(path) != 0) return 1;

  snprintf(path, sizeof(path), "%s/fixture_tail.obj", outdir);
  if (make_tail(path) != 0) return 1;

  snprintf(path, sizeof(path), "%s/fixture_call.obj", outdir);
  if (make_call(path) != 0) return 1;

  printf("fixtures written to %s\n", outdir);
  return 0;
}
