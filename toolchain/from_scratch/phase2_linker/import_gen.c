/*==========================================================================
 * Import Table Generator - RawrXD native PE linker
 *=========================================================================*/

#include "import_gen.h"
#include "known_imports.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- PE structure sizes ---- */
#define IMAGE_IMPORT_DESCRIPTOR_SIZE 20
#define THUNK_SIZE 6                 /* FF 25 disp32 */

/* ---- Section characteristics for .idata ----
 * The loader writes the resolved addresses into the IAT, so the section
 * must be writable. */
#define IDATA_CHARACTERISTICS 0xC0000040u  /* INITIALIZED_DATA | READ | WRITE */

/* ---- Little-endian writers ---- */
static void w16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void w32(uint8_t *p, uint32_t v) {
  p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static void w64(uint8_t *p, uint64_t v) { w32(p,(uint32_t)v); w32(p+4,(uint32_t)(v>>32)); }

/* ---- Case-insensitive compare ----
 * MSVC's C runtime does not provide strcasecmp / strncasecmp, so the
 * linker carries its own. */
static int rawr_tolower(int c) {
  return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int rawr_strncasecmp(const char *a, const char *b, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    int ca = rawr_tolower((unsigned char)a[i]);
    int cb = rawr_tolower((unsigned char)b[i]);
    if (ca != cb) return ca < cb ? -1 : 1;
    if (ca == 0) return 0;
  }
  return 0;
}

static int rawr_strcasecmp(const char *a, const char *b) {
  for (;;) {
    int ca = rawr_tolower((unsigned char)*a);
    int cb = rawr_tolower((unsigned char)*b);
    if (ca != cb) return ca < cb ? -1 : 1;
    if (ca == 0) return 0;
    ++a; ++b;
  }
}

/*--------------------------------------------------------------------------
 * Lifetime
 *------------------------------------------------------------------------*/
import_table_t *import_table_new(void) {
  import_table_t *it = (import_table_t *)calloc(1, sizeof(import_table_t));
  return it;
}

void import_table_free(import_table_t *it) {
  if (!it) return;
  if (it->idata) free(it->idata);
  free(it);
}

/*--------------------------------------------------------------------------
 * Symbol registration
 *------------------------------------------------------------------------*/
int import_find_symbol(import_table_t *it, const char *name) {
  if (!it || !name) return -1;
  for (int i = 0; i < it->num_symbols; i++) {
    if (strcmp(it->symbols[i].name, name) == 0) return i;
  }
  return -1;
}

static int find_or_add_dll(import_table_t *it, const char *dll) {
  for (int i = 0; i < it->num_dlls; i++) {
    if (strcmp(it->dlls[i].name, dll) == 0) return i;
  }
  if (it->num_dlls >= IMPORT_MAX_DLLS) return -1;

  int idx = it->num_dlls++;
  memset(&it->dlls[idx], 0, sizeof(import_dll_t));
  strncpy(it->dlls[idx].name, dll, sizeof(it->dlls[idx].name) - 1);
  it->dlls[idx].name[sizeof(it->dlls[idx].name) - 1] = '\0';
  it->dlls[idx].first_symbol = it->num_symbols;
  it->dlls[idx].num_symbols = 0;
  return idx;
}

int import_add_symbol(import_table_t *it, const char *name, const char *dll,
                      uint16_t ordinal, int is_ordinal) {
  if (!it || !name || !dll) return -1;

  int existing = import_find_symbol(it, name);
  if (existing >= 0) return existing;

  if (it->num_symbols >= IMPORT_MAX_SYMBOLS) return -1;

  int didx = find_or_add_dll(it, dll);
  if (didx < 0) return -1;

  int sidx = it->num_symbols++;
  import_symbol_t *s = &it->symbols[sidx];
  memset(s, 0, sizeof(*s));
  strncpy(s->name, name, sizeof(s->name) - 1);
  s->name[sizeof(s->name) - 1] = '\0';
  strncpy(s->dll, dll, sizeof(s->dll) - 1);
  s->dll[sizeof(s->dll) - 1] = '\0';
  s->ordinal = ordinal;
  s->is_ordinal = is_ordinal;

  it->dlls[didx].num_symbols++;
  return sidx;
}

/*--------------------------------------------------------------------------
 * DLL resolution
 *
 * A COFF object does not record which DLL an undefined symbol comes from;
 * that information normally lives in an import library. RawrXD resolves it
 * from two sources:
 *
 *   1. The `.drectve` section, using the standard MSVC `/DEFAULTLIB:`
 *      directive. The RawrXD compiler emits this section, so compiler
 *      output never depends on the built-in table.
 *   2. A built-in table of well-known Windows exports, used for assembly
 *      sources that declare `EXTERN Foo:PROC` without naming a DLL.
 *------------------------------------------------------------------------*/

/* Extracts the DLL name from a `/DEFAULTLIB:xxx.lib` directive.
 * Returns 1 on success. */
static int parse_defaultlib(const char *text, size_t len, char *out, size_t out_size) {
  static const char kTag[] = "/DEFAULTLIB:";
  const size_t tag_len = sizeof(kTag) - 1;

  for (size_t i = 0; i + tag_len < len; i++) {
    if (rawr_strncasecmp(text + i, kTag, tag_len) != 0) continue;

    size_t start = i + tag_len;
    size_t end = start;
    while (end < len && text[end] != ' ' && text[end] != '\t' &&
           text[end] != '\r' && text[end] != '\n' && text[end] != '"') {
      ++end;
    }
    if (end == start) return 0;

    size_t n = end - start;
    /* Strip a trailing ".lib".
     *
     * The comparison has to be bounded: the section data is not NUL
     * terminated, so an unbounded strcasecmp would read past the end of
     * the buffer and compare against whatever follows in the file. */
    if (n > 4 && rawr_strncasecmp(text + end - 4, ".lib", 4) == 0) n -= 4;
    if (n == 0 || n + 4 >= out_size) return 0;

    memcpy(out, text + start, n);
    out[n] = '\0';
    /* Turn the library name into the module name the loader expects. */
    strcat(out, ".dll");
    return 1;
  }
  return 0;
}

/* Finds the `.drectve` section of an object and extracts its default
 * library. Returns 1 when a default library was found. */
static int object_default_lib(coff_file_t *cf, char *out, size_t out_size) {
  for (uint16_t s = 0; s < cf->num_sections; s++) {
    coff_section_t *sec = &cf->sections[s];
    if (strcmp(sec->name, ".drectve") != 0) continue;
    if (!sec->data || sec->raw_size == 0) continue;
    if (parse_defaultlib((const char *)sec->data, sec->raw_size, out, out_size)) {
      return 1;
    }
  }
  return 0;
}

/* Resolves the DLL that exports `symbol`. `default_lib` may be NULL. */
static const char *resolve_dll(const char *symbol, const char *default_lib) {
  if (default_lib && default_lib[0]) return default_lib;
  return known_import_dll(symbol);
}

/*--------------------------------------------------------------------------
 * Merged section helpers
 *------------------------------------------------------------------------*/

/* Ensures the merged section can hold `extra` more bytes, growing the
 * buffer with realloc and preserving existing content. */
static int section_reserve(merged_section_t *m, size_t extra) {
  if (!m) return 0;
  size_t needed = m->data_len + extra;
  if (needed <= m->data_capacity) return 1;

  size_t new_cap = m->data_capacity ? m->data_capacity : 4096;
  while (new_cap < needed) new_cap *= 2;

  uint8_t *new_data = (uint8_t *)realloc(m->data, new_cap);
  if (!new_data) return 0;
  memset(new_data + m->data_len, 0, new_cap - m->data_len);
  m->data = new_data;
  m->data_capacity = new_cap;
  return 1;
}

/*--------------------------------------------------------------------------
 * Import generation
 *------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------
 * Definitions seen across the link.
 *
 * The import scanner needs to know which symbols are defined by one of
 * the input objects, because those are cross-object references rather
 * than imports.
 *------------------------------------------------------------------------*/
typedef struct defined_set {
  char **names;
  int count;
  int capacity;
} defined_set_t;

static void defined_set_add(defined_set_t *set, const char *name) {
  for (int i = 0; i < set->count; ++i) {
    if (strcmp(set->names[i], name) == 0) return;
  }
  if (set->count >= set->capacity) {
    int new_cap = set->capacity ? set->capacity * 2 : 64;
    char **grown = (char **)realloc(set->names, (size_t)new_cap * sizeof(char *));
    if (!grown) return;
    set->names = grown;
    set->capacity = new_cap;
  }
  size_t n = strlen(name) + 1;
  char *copy = (char *)malloc(n);
  if (!copy) return;
  memcpy(copy, name, n);
  set->names[set->count++] = copy;
}

static int defined_set_has(defined_set_t *set, const char *name) {
  for (int i = 0; i < set->count; ++i) {
    if (strcmp(set->names[i], name) == 0) return 1;
  }
  return 0;
}

static void defined_set_free(defined_set_t *set) {
  for (int i = 0; i < set->count; ++i) free(set->names[i]);
  if (set->names) free(set->names);
  set->names = NULL;
  set->count = 0;
  set->capacity = 0;
}
/*--------------------------------------------------------------------------
 * Per-symbol import directives.
 *
 * A `/DEFAULTLIB:` directive names a library for every undefined symbol in
 * the object, which is not precise enough when a program imports from
 * several modules. The RawrXD compiler therefore also emits
 *
 *     /RAWRXD_IMPORT:<dll>:<symbol>
 *
 * which binds one symbol to one module. These directives take precedence
 * over the default library and over the built-in table.
 *------------------------------------------------------------------------*/
static const char kImportTag[] = "/RAWRXD_IMPORT:";

/* Finds the per-symbol import directive for `symbol` in a .drectve
 * section. Returns 1 and fills `out` when one is present. */
static int find_symbol_import(const char *text, size_t len, const char *symbol,
                              char *out, size_t out_size) {
  const size_t tag_len = sizeof(kImportTag) - 1;

  for (size_t i = 0; i + tag_len < len; i++) {
    if (rawr_strncasecmp(text + i, kImportTag, tag_len) != 0) continue;

    size_t start = i + tag_len;
    size_t sep = start;
    while (sep < len && text[sep] != ':' && text[sep] != ' ' &&
           text[sep] != '\t' && text[sep] != '\r' && text[sep] != '\n') {
      ++sep;
    }
    if (sep >= len || text[sep] != ':') continue;

    size_t dll_len = sep - start;
    if (dll_len == 0 || dll_len >= out_size) continue;

    size_t sym_start = sep + 1;
    size_t sym_end = sym_start;
    while (sym_end < len && text[sym_end] != ' ' && text[sym_end] != '\t' &&
           text[sym_end] != '\r' && text[sym_end] != '\n') {
      ++sym_end;
    }
    size_t sym_len = sym_end - sym_start;
    if (sym_len == 0) continue;

    /* Compare the symbol name without reading past the section. */
    if (sym_len != strlen(symbol)) continue;
    if (rawr_strncasecmp(text + sym_start, symbol, sym_len) != 0) continue;

    memcpy(out, text + start, dll_len);
    out[dll_len] = '\0';
    return 1;
  }
  return 0;
}
/*--------------------------------------------------------------------------
 * Phase 1.5: discover undefined external symbols
 *------------------------------------------------------------------------*/
int import_scan(import_table_t *it, coff_file_t **files, int num_files) {
  if (!it || !files) return -1;

  /* ---- Collect the symbols that are DEFINED somewhere in the link ----
   *
   * A symbol that is undefined in one object but defined in another is a
   * normal cross-object reference, not an import. Treating it as an import
   * would turn the reference into a jump through an import address table
   * that the loader then has to fill in from a DLL that does not export
   * the symbol.
   */
  defined_set_t defined;
  memset(&defined, 0, sizeof(defined));

  for (int obj = 0; obj < num_files; obj++) {
    coff_file_t *cf = files[obj];
    if (!cf || !cf->symbols) continue;
    for (uint32_t si = 0; si < cf->num_symbols; si++) {
      coff_symbol_t *sym = &cf->symbols[si];
      if (!sym->name[0]) continue;
      if (sym->section_num <= 0) continue;             /* undefined or absolute */
      if (sym->storage_class != SYM_CLASS_EXTERNAL) continue;
      /* Record the definition so the relocation scan below can skip it. */
      defined_set_add(&defined, sym->name);
    }
  }

  for (int obj = 0; obj < num_files; obj++) {
    coff_file_t *cf = files[obj];
    if (!cf || !cf->symbols) continue;

    char default_lib[64];
    int have_default = object_default_lib(cf, default_lib, sizeof(default_lib));

    /* The raw .drectve payload, used for the per-symbol import
     * directives. */
    const char *directives_text = NULL;
    size_t drectve_len = 0;
    for (uint16_t ds = 0; ds < cf->num_sections; ds++) {
      if (strcmp(cf->sections[ds].name, ".drectve") == 0 && cf->sections[ds].data) {
        directives_text = (const char *)cf->sections[ds].data;
        drectve_len = cf->sections[ds].raw_size;
        break;
      }
    }

    for (uint16_t si = 0; si < cf->num_sections; si++) {
      coff_section_t *sec = &cf->sections[si];
      if (!sec->relocs || sec->reloc_count == 0) continue;

      for (uint32_t ri = 0; ri < sec->reloc_count; ri++) {
        coff_reloc_t *rel = &sec->relocs[ri];
        if (rel->symbol_index >= cf->num_symbols) continue;

        coff_symbol_t *sym = &cf->symbols[rel->symbol_index];
        if (!sym->name[0]) continue;

        /* An undefined external is an import reference. */
        if (sym->section_num != 0) continue;
        if (sym->storage_class != SYM_CLASS_EXTERNAL) continue;

        /* A symbol that another object defines is a cross-object
         * reference, not an import. */
        if (defined_set_has(&defined, sym->name)) continue;

        /* The MSVC convention imports through `__imp_<name>`; the real
         * export name is the part after the prefix. */
        const char *import_name = sym->name;
        int needs_thunk = 1;
        if (strncmp(import_name, "__imp_", 6) == 0) {
          import_name += 6;
          /* References to `__imp_X` point straight at the IAT slot, so no
           * redirect thunk is required for them. */
          needs_thunk = 0;
        }

        if (import_find_symbol(it, import_name) >= 0) continue;

        /* A per-symbol directive is the most precise source of truth. */
        char symbol_dll[64];
        int have_symbol_dll = 0;
        if (drectve_len) {
            have_symbol_dll = find_symbol_import(directives_text, drectve_len,
                                                 import_name, symbol_dll,
                                                 sizeof(symbol_dll));
        }

        const char *dll = have_symbol_dll ? symbol_dll
                       : resolve_dll(import_name, have_default ? default_lib : NULL);
        if (!dll) {
          /* Not an import we can resolve. The relocation pass reports this
           * as an error rather than silently resolving it to RVA 0. */
          fprintf(stderr, "[import] no DLL known for '%s' (not an import)\n",
                  import_name);
          it->unresolved++;
          continue;
        }

        int sidx = import_add_symbol(it, import_name, dll, 0, 0);
        if (sidx >= 0) it->symbols[sidx].needs_thunk = needs_thunk;
      }
    }
  }

  defined_set_free(&defined);
  return 0;
}

/*--------------------------------------------------------------------------
 * Phase 2.5: lay out the import structures and emit the thunks
 *------------------------------------------------------------------------*/
int import_layout(import_table_t *it, merge_context_t *ctx,
                   merged_section_t *text, merged_section_t *idata) {
  if (!it || !ctx || !text || !idata) return -1;

  if (it->num_dlls == 0) {
    /* No imports: nothing to generate. */
    return 0;
  }

  /* ---- Step 1: lay out the .idata section ----
   *
   * Layout (all offsets relative to the start of .idata):
   *
   *   [0]                        Import Directory Table
   *   [dir_size]                 ILT + IAT arrays, per DLL
   *   [thunk_tables_size]        Hint/Name entries
   *   [hint_names_size]          DLL name strings
   */
  uint32_t dir_size = (uint32_t)(it->num_dlls + 1) * IMAGE_IMPORT_DESCRIPTOR_SIZE;

  /* ILT and IAT arrays, grouped per DLL. */
  uint32_t *ilt_off = (uint32_t *)calloc(it->num_dlls, sizeof(uint32_t));
  uint32_t *iat_off = (uint32_t *)calloc(it->num_dlls, sizeof(uint32_t));
  uint32_t *hn_off  = (uint32_t *)calloc(it->num_symbols ? it->num_symbols : 1, sizeof(uint32_t));
  uint32_t *dllname_off = (uint32_t *)calloc(it->num_dlls, sizeof(uint32_t));
  if (!ilt_off || !iat_off || !hn_off || !dllname_off) {
    free(ilt_off); free(iat_off); free(hn_off); free(dllname_off);
    return -1;
  }

  uint32_t cursor = dir_size;
  for (int d = 0; d < it->num_dlls; d++) {
    uint32_t count = (uint32_t)it->dlls[d].num_symbols;
    uint32_t array_size = (count + 1) * 8;   /* +1 for the null terminator */
    ilt_off[d] = cursor;  cursor += array_size;
    iat_off[d] = cursor;  cursor += array_size;
  }

  uint32_t hn_base = cursor;
  for (int s = 0; s < it->num_symbols; s++) {
    import_symbol_t *sym = &it->symbols[s];
    hn_off[s] = cursor;
    /* 2-byte hint + name + NUL, padded to an even boundary. */
    uint32_t len = 2 + (uint32_t)strlen(sym->name) + 1;
    if (len & 1) len++;
    cursor += len;
  }

  uint32_t names_base = cursor;
  for (int d = 0; d < it->num_dlls; d++) {
    dllname_off[d] = cursor;
    cursor += (uint32_t)strlen(it->dlls[d].name) + 1;
  }

  uint32_t total = cursor;
  (void)hn_base; (void)names_base;

  /* ---- Step 2: build the .idata payload ---- */
  uint8_t *buf = (uint8_t *)calloc(1, total ? total : 1);
  if (!buf) {
    free(ilt_off); free(iat_off); free(hn_off); free(dllname_off);
    return -1;
  }

  uint32_t idata_rva = idata->rva;

  /* Hint/Name entries and DLL name strings. */
  for (int s = 0; s < it->num_symbols; s++) {
    import_symbol_t *sym = &it->symbols[s];
    uint8_t *hn = buf + hn_off[s];
    w16(hn, 0);                       /* hint ordinal (unused by the loader) */
    memcpy(hn + 2, sym->name, strlen(sym->name) + 1);
  }
  for (int d = 0; d < it->num_dlls; d++) {
    memcpy(buf + dllname_off[d], it->dlls[d].name, strlen(it->dlls[d].name) + 1);
  }

  /* Assign the IAT RVA of every symbol now that the layout is known. */
  for (int d = 0; d < it->num_dlls; d++) {
    it->dlls[d].ilt_rva = idata_rva + ilt_off[d];
    it->dlls[d].iat_rva = idata_rva + iat_off[d];
    it->dlls[d].name_rva = idata_rva + dllname_off[d];

    int base = it->dlls[d].first_symbol;
    for (int k = 0; k < it->dlls[d].num_symbols; k++) {
      import_symbol_t *sym = &it->symbols[base + k];
      sym->iat_rva = idata_rva + iat_off[d] + (uint32_t)k * 8;
    }
  }

  /* ILT and IAT arrays, plus the import descriptors. */
  for (int d = 0; d < it->num_dlls; d++) {
    int base = it->dlls[d].first_symbol;
    for (int k = 0; k < it->dlls[d].num_symbols; k++) {
      import_symbol_t *sym = &it->symbols[base + k];
      uint64_t value;
      if (sym->is_ordinal) {
        value = 0x8000000000000000ull | sym->ordinal;
      } else {
        /* The hint/name entry RVA. */
        value = idata_rva + hn_off[base + k];
      }
      w64(buf + ilt_off[d] + (uint32_t)k * 8, value);
      w64(buf + iat_off[d] + (uint32_t)k * 8, value);
    }
    /* The null terminators are already zero from calloc. */

    /* IMAGE_IMPORT_DESCRIPTOR: five 32-bit fields, 20 bytes total.
     * Every RVA here is image-relative, i.e. idata_rva + offset. */
    uint8_t *desc = buf + (uint32_t)d * IMAGE_IMPORT_DESCRIPTOR_SIZE;
    w32(desc + 0,  it->dlls[d].ilt_rva);   /* OriginalFirstThunk (ILT) */
    w32(desc + 4,  0);                      /* TimeDateStamp */
    w32(desc + 8,  0);                      /* ForwarderChain */
    w32(desc + 12, it->dlls[d].name_rva);  /* Name (DLL string) */
    w32(desc + 16, it->dlls[d].iat_rva);   /* FirstThunk (IAT) */
  }
  /* The null terminator descriptor is already zeroed. */

  /* ---- Step 3: emit the redirect thunks into .text ----
   *
   * A thunk is:  FF 25 <disp32>      jmp qword ptr [rip + disp32]
   *
   * The displacement is relative to the end of the instruction, so it
   * targets the IAT slot. After the loader binds the import, the thunk
   * jumps to the real function.
   */
  if (!section_reserve(text, (size_t)it->num_symbols * THUNK_SIZE)) {
    free(buf); free(ilt_off); free(iat_off); free(hn_off); free(dllname_off);
    return -1;
  }

  for (int s = 0; s < it->num_symbols; s++) {
    import_symbol_t *sym = &it->symbols[s];
    if (!sym->needs_thunk) continue;

    uint32_t thunk_off = (uint32_t)text->data_len;
    uint32_t thunk_rva = text->rva + thunk_off;
    sym->thunk_rva = thunk_rva;

    uint8_t *code = text->data + thunk_off;
    code[0] = 0xFF;   /* jmp */
    code[1] = 0x25;   /* [rip + disp32] */
    int32_t disp = (int32_t)(sym->iat_rva - (thunk_rva + THUNK_SIZE));
    w32(code + 2, (uint32_t)disp);

    text->data_len += THUNK_SIZE;
    if (text->virtual_size < text->data_len) text->virtual_size = text->data_len;
    it->num_thunks++;
  }

  /* ---- Step 4: install the .idata payload ---- */
  if (!section_reserve(idata, total)) {
    free(buf); free(ilt_off); free(iat_off); free(hn_off); free(dllname_off);
    return -1;
  }
  memcpy(idata->data + idata->data_len, buf, total);
  idata->data_len += total;
  /* The true content size is now known. The page that was reserved
   * during layout keeps the following sections where they were placed, so
   * the reservation can be released here. */
  idata->virtual_size = idata->data_len;

  it->idata = buf;
  it->idata_len = total;
  it->idata_rva = idata_rva;
  it->idata_size = dir_size;

  /* ---- Step 5: point the global symbol table at the thunks ----
   *
   * The relocation resolver looks symbols up by name, so updating the
   * global table is enough to make every call site resolve correctly.
   */
  for (int s = 0; s < it->num_symbols; s++) {
    import_symbol_t *sym = &it->symbols[s];

    /* A call site that references the plain symbol name is redirected to
     * the redirect thunk; a call site that references `__imp_<name>`
     * dereferences the IAT slot directly. */
    uint32_t target = sym->needs_thunk ? sym->thunk_rva : sym->iat_rva;

    for (uint32_t g = 0; g < ctx->num_global_symbols; g++) {
      if (strcmp(ctx->global_symbols[g].name, sym->name) == 0) {
        ctx->global_symbols[g].resolved_rva = target;
        ctx->global_symbols[g].resolved = 1;
      }
    }

    /* The MSVC `__imp_<name>` convention always points at the IAT slot,
     * whether or not a redirect thunk was emitted. */
    char imp_name[260];
    snprintf(imp_name, sizeof(imp_name), "__imp_%s", sym->name);
    for (uint32_t g = 0; g < ctx->num_global_symbols; g++) {
      if (strcmp(ctx->global_symbols[g].name, imp_name) == 0) {
        ctx->global_symbols[g].resolved_rva = sym->iat_rva;
        ctx->global_symbols[g].resolved = 1;
      }
    }
  }

  free(ilt_off); free(iat_off); free(hn_off); free(dllname_off);
  return 0;
}

int import_generate(import_table_t *it, merge_context_t *ctx,
                    coff_file_t **files, int num_files,
                    merged_section_t *text, merged_section_t *idata) {
  if (import_scan(it, files, num_files) != 0) return -1;
  return import_layout(it, ctx, text, idata);
}

/*--------------------------------------------------------------------------
 * Diagnostics
 *------------------------------------------------------------------------*/
void import_table_dump(import_table_t *it, void *out) {
  FILE *f = out ? (FILE *)out : stderr;
  if (!it) return;

  fprintf(f, "[import] %d DLL(s), %d symbol(s), %d thunk(s), %u bytes of .idata\n",
          it->num_dlls, it->num_symbols, it->num_thunks, (unsigned)it->idata_len);
  for (int d = 0; d < it->num_dlls; d++) {
    import_dll_t *dl = &it->dlls[d];
    fprintf(f, "  %-20s ILT=0x%05X IAT=0x%05X name=0x%05X  %d symbol(s)\n",
            dl->name, dl->ilt_rva, dl->iat_rva, dl->name_rva, dl->num_symbols);
    int base = dl->first_symbol;
    for (int k = 0; k < dl->num_symbols; k++) {
      import_symbol_t *s = &it->symbols[base + k];
      fprintf(f, "      %-40s IAT=0x%05X thunk=0x%05X\n",
              s->name, s->iat_rva, s->thunk_rva);
    }
  }
}
