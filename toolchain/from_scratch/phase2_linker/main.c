/*==========================================================================
 * rawrxd_link - Phase 2 PE/COFF Linker (Fully Reverse Engineered)
 *
 * Complete linking pipeline orchestrator. Executes all 5 phases:
 *
 *   Phase 1 (coff_reader):     Parse input .obj files
 *   Phase 2 (section_merge):   Merge sections, assign RVAs
 *   Phase 3 (reloc_resolver):  Apply relocations
 *   Phase 4 (pe_writer):       Write PE32+ executable
 *   Phase 5 (entry_stub):      Inject CRT entry if needed
 *
 * Usage: rawrxd_link [-o output.exe] [-v] [-base 0xNNNN] [-subsys N]
 *                    [-entry symbol] [-stack N] [-heap N] file.obj ...
 *
 * Options:
 *   -o <path>      Output file (default: a.exe)
 *   -v             Verbose: dump COFF info, merge map, PE layout
 *   -base <hex>    Image base address (default: 0x140000000)
 *   -subsys <N>    Subsystem: 2=GUI, 3=Console (default: 3)
 *   -entry <sym>   Entry point symbol (default: mainCRTStartup or main)
 *   -stack <N>     Stack reserve size in bytes
 *   -heap <N>      Heap reserve size in bytes
 *   -map           Write .map file alongside executable
 *=========================================================================*/
#include "coff_reader.h"
#include "pe_writer.h"
#include "section_merge.h"
#include "import_gen.h"
#include "reloc_gen.h"
#include "export_gen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* External: relocation resolver */
extern int reloc_resolve_all(merge_context_t *ctx, coff_file_t **files,
                             int num_files, uint64_t image_base,
                             reloc_table_t *relocs);

/* External: entry stub data */
extern uint8_t entry_stub_code[];
extern const size_t entry_stub_size;

/* ---- Entry point search order ---- */
static const char *entry_candidates[] = {
  "mainCRTStartup",
  "main",
  "wmainCRTStartup",
  "wmain",
  "WinMainCRTStartup",
  "WinMain",
  "wWinMainCRTStartup",
  "wWinMain",
  "_start",
  "entry",
  NULL
};

/*--------------------------------------------------------------------------
 * Find entry point RVA from global symbol table.
 *------------------------------------------------------------------------*/
static uint32_t find_entry_rva(merge_context_t *ctx, const char *explicit_entry) {
  if (!ctx) return 0;

  /* If explicit entry given, search for it */
  if (explicit_entry && explicit_entry[0]) {
    for (uint32_t i = 0; i < ctx->num_global_symbols; i++) {
      if (strcmp(ctx->global_symbols[i].name, explicit_entry) == 0)
        return ctx->global_symbols[i].resolved_rva;
    }
    fprintf(stderr, "[linker] warning: entry point '%s' not found\n", explicit_entry);
  }

  /* Auto-detect: search candidates in order */
  for (int c = 0; entry_candidates[c]; c++) {
    for (uint32_t i = 0; i < ctx->num_global_symbols; i++) {
      if (strcmp(ctx->global_symbols[i].name, entry_candidates[c]) == 0) {
        fprintf(stderr, "[linker] auto-detected entry: %s at RVA 0x%X\n",
                entry_candidates[c], ctx->global_symbols[i].resolved_rva);
        return ctx->global_symbols[i].resolved_rva;
      }
    }
  }

  fprintf(stderr, "[linker] warning: no entry point found, using 0x1000\n");
  return 0x1000;
}

/*--------------------------------------------------------------------------
 * Write a .map file with symbol and section info.
 *------------------------------------------------------------------------*/
static void write_map_file(const char *out_path, merge_context_t *ctx, uint64_t image_base) {
  char map_path[268];
  size_t len = strlen(out_path);
  memcpy(map_path, out_path, len + 1);
  /* Replace extension with .map */
  char *dot = strrchr(map_path, '.');
  if (dot) strcpy(dot, ".map");
  else strcat(map_path, ".map");

  FILE *f = fopen(map_path, "w");
  if (!f) return;

  fprintf(f, " rawrxd_link Linker Map\n\n");
  fprintf(f, " Image Base: 0x%016llX\n\n", (unsigned long long)image_base);

  /* Sections */
  fprintf(f, " Start         Length     Name                   Class\n");
  for (merged_section_t *m = ctx->head; m; m = m->next) {
    fprintf(f, " %04X:00000000 %08XH %-24s",
            0, m->virtual_size, m->name);
    if (m->characteristics & 0x00000020) fprintf(f, "CODE");
    else if (m->characteristics & 0x00000040) fprintf(f, "DATA");
    else if (m->characteristics & 0x00000080) fprintf(f, "BSS");
    fprintf(f, "\n");
  }

  /* Symbols */
  fprintf(f, "\n  Address         Publics by Value\n\n");
  for (uint32_t i = 0; i < ctx->num_global_symbols; i++) {
    coff_symbol_t *sym = &ctx->global_symbols[i];
    if (!sym->name[0]) continue;
    if (sym->storage_class != 2 && sym->storage_class != 3) continue;
    fprintf(f, " 0000:%08X       %s\n", sym->resolved_rva, sym->name);
  }

  fclose(f);
  fprintf(stderr, "[linker] wrote map: %s\n", map_path);
}

/*--------------------------------------------------------------------------
 * Main: parse args, execute all phases.
 *------------------------------------------------------------------------*/
int main(int argc, char **argv) {
  const char *out_path = "a.exe";
  const char *entry_name = NULL;
  uint64_t image_base = 0x0000000140000000ULL;
  uint16_t subsystem = 3; /* Console */
  uint64_t stack_reserve = 0x100000;
  uint64_t heap_reserve = 0x100000;
  int verbose = 0;
  int write_map = 0;
  int deterministic = 0;
  int make_dll = 0;
  const char* export_name = NULL;
  const char* dll_out = NULL;

  int num_objs = 0;
  coff_file_t **objs = NULL;

  /*==== Parse command line ====*/
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
      out_path = argv[++i];
    } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
      verbose = 1;
    } else if (strcmp(argv[i], "-base") == 0 && i + 1 < argc) {
      image_base = strtoull(argv[++i], NULL, 0);
    } else if (strcmp(argv[i], "-subsys") == 0 && i + 1 < argc) {
      subsystem = (uint16_t)atoi(argv[++i]);
    } else if (strcmp(argv[i], "-entry") == 0 && i + 1 < argc) {
      entry_name = argv[++i];
    } else if (strcmp(argv[i], "-stack") == 0 && i + 1 < argc) {
      stack_reserve = strtoull(argv[++i], NULL, 0);
    } else if (strcmp(argv[i], "-heap") == 0 && i + 1 < argc) {
      heap_reserve = strtoull(argv[++i], NULL, 0);
    } else if (strcmp(argv[i], "-map") == 0) {
      write_map = 1;
    } else if (strcmp(argv[i], "-dll") == 0 || strcmp(argv[i], "--shared") == 0) {
      make_dll = 1;
    } else if (strcmp(argv[i], "-deterministic") == 0 ||
               strcmp(argv[i], "--deterministic") == 0 ||
               strcmp(argv[i], "-reproducible") == 0) {
      deterministic = 1;
    } else if (strcmp(argv[i], "-export") == 0 && i + 1 < argc) {
      export_name = argv[++i];
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "rawrxd_link: unknown option '%s'\n", argv[i]);
      return 1;
    } else {
      /*==== Phase 1: Read COFF object file ====*/
      coff_file_t *cf = coff_read(argv[i]);
      if (!cf) {
        fprintf(stderr, "rawrxd_link: cannot read '%s'\n", argv[i]);
        continue;
      }
      if (verbose) coff_dump(cf, stderr);

      coff_file_t **new_objs = (coff_file_t **)realloc(objs, (size_t)(num_objs + 1) * sizeof(coff_file_t *));
      if (!new_objs) { coff_free(cf); break; }
      objs = new_objs;
      objs[num_objs++] = cf;
    }
  }

  if (num_objs == 0) {
    fprintf(stderr,
      "rawrxd_link - RawrXD PE/COFF Linker (from scratch)\n"
      "Usage: rawrxd_link [-o out.exe] [-v] [-entry sym] [-base 0xN]\n"
      "                   [-subsys N] [-stack N] [-heap N] [-map] file.obj ...\n"
      "\n"
      "Phases:\n"
      "  1. COFF Reader     - Parse object files (headers, sections, symbols, relocs)\n"
      "  2. Section Merger  - Merge same-named sections, assign RVAs\n"
      "  3. Reloc Resolver  - Apply x64 relocations (REL32, ADDR64, etc.)\n"
      "  4. PE Writer       - Generate PE32+ executable with full headers\n"
      "  5. Entry Stub      - Inject CRT entry point if needed\n");
    return 1;
  }

  fprintf(stderr, "[linker] phase 1 complete: %d object file(s) loaded\n", num_objs);

  /*==== Phase 1.5: Scan for imports ====*/
  import_table_t *imports = import_table_new();
  if (!imports) {
    fprintf(stderr, "rawrxd_link: out of memory\n");
    for (int j = 0; j < num_objs; j++) coff_free(objs[j]);
    free(objs);
    return 1;
  }
  import_scan(imports, objs, num_objs);
  if (verbose && imports->num_dlls > 0) {
    fprintf(stderr, "[linker] phase 1.5 complete: %d import DLL(s), %d symbol(s)\n",
            imports->num_dlls, imports->num_symbols);
  }

  /*==== Phase 2: Merge sections ====*/
  /* The .idata section is created inside the merge so that its RVA is
   * final before the import structures are laid out. */
  merge_context_t *ctx = section_merge_context_ex(objs, num_objs,
                                                   imports->num_dlls > 0, 1, make_dll);
  if (!ctx) {
    fprintf(stderr, "rawrxd_link: section merge failed\n");
    import_table_free(imports);
    for (int j = 0; j < num_objs; j++) coff_free(objs[j]);
    free(objs);
    return 1;
  }

  if (verbose) merged_section_dump(ctx->head, stderr);
  fprintf(stderr, "[linker] phase 2 complete: %d merged section(s), next RVA=0x%X\n",
          ctx->num_sections, ctx->next_rva);

  /*==== Phase 2.5: Lay out the import table ====*/
  if (imports->num_dlls > 0) {
    merged_section_t *text = merged_section_find(ctx->head, ".text");
    merged_section_t *idata = merged_section_find(ctx->head, ".idata");
    if (!text || !idata) {
      fprintf(stderr, "rawrxd_link: internal error: missing .text or .idata section\n");
      merge_context_free(ctx);
      import_table_free(imports);
      for (int j = 0; j < num_objs; j++) coff_free(objs[j]);
      free(objs);
      return 1;
    }
    if (import_layout(imports, ctx, text, idata) != 0) {
      fprintf(stderr, "rawrxd_link: import table generation failed\n");
      merge_context_free(ctx);
      import_table_free(imports);
      for (int j = 0; j < num_objs; j++) coff_free(objs[j]);
      free(objs);
      return 1;
    }
    if (verbose) import_table_dump(imports, stderr);
    fprintf(stderr, "[linker] phase 2.5 complete: %d DLL(s), %d symbol(s), %d thunk(s)\n",
            imports->num_dlls, imports->num_symbols, imports->num_thunks);
  }

  /*==== Phase 2.7: Collect the exported symbols ====*/
  export_table_t *exports = NULL;
  uint32_t export_rva = 0, export_size = 0;

  if (make_dll) {
    exports = export_table_new();
    if (!exports) {
      fprintf(stderr, "rawrxd_link: out of memory\n");
      merge_context_free(ctx);
      import_table_free(imports);
      for (int j = 0; j < num_objs; j++) coff_free(objs[j]);
      free(objs);
      return 1;
    }
    /* The DLL name is what consumers see in the export directory. */
    {
      const char* base = strrchr(out_path, '/');
      if (!base) base = strrchr(out_path, '\\');
      strncpy(exports->dll_name, base ? base + 1 : out_path,
              sizeof(exports->dll_name) - 1);
      exports->dll_name[sizeof(exports->dll_name) - 1] = '\0';
    }

    /* Every defined external symbol is exported. A symbol that is only
     * referenced (undefined) belongs to an import, not to this module's
     * export table. */
    for (uint32_t g = 0; g < ctx->num_global_symbols; g++) {
      coff_symbol_t* sym = &ctx->global_symbols[g];
      if (!sym->name[0]) continue;
      if (sym->storage_class != SYM_CLASS_EXTERNAL) continue;
      if (sym->section_num <= 0) continue;      /* undefined or absolute */
      if (strncmp(sym->name, "__imp_", 6) == 0) continue;
      if (sym->name[0] == '_' && sym->name[1] == '_') continue;  /* runtime */
      export_add(exports, sym->name, sym->resolved_rva);
    }

    merged_section_t* edata = merged_section_find(ctx->head, ".edata");
    if (edata && exports->num_entries > 0) {
      if (export_build(exports, edata) == 0) {
        export_rva = exports->data_rva;
        export_size = (uint32_t)exports->data_len;
        if (verbose) export_table_dump(exports, stderr);
        fprintf(stderr, "[linker] phase 2.7 complete: %d export(s)\n",
                exports->num_entries);
      }
    } else if (edata) {
      /* A DLL with no exports has no export table, so the section is
       * removed rather than left empty. */
      section_merge_remove(ctx, ".edata");
    }
  }

  /*==== Phase 3: Resolve relocations ====*/
  reloc_table_t *relocs = reloc_table_new();
  int reloc_errors = reloc_resolve_all(ctx, objs, num_objs, image_base, relocs);
  fprintf(stderr, "[linker] phase 3 complete: relocation errors=%d\n", reloc_errors);

  if (reloc_errors > 0) {
    fprintf(stderr, "rawrxd_link: %d relocation error(s); refusing to emit an image\n",
            reloc_errors);
    reloc_table_free(relocs);
    merge_context_free(ctx);
    import_table_free(imports);
    for (int j = 0; j < num_objs; j++) coff_free(objs[j]);
    free(objs);
    return 1;
  }

  /*==== Phase 3.5: Build the base relocation table ====*/
  uint32_t reloc_rva = 0, reloc_size = 0;
  merged_section_t *reloc_sec = merged_section_find(ctx->head, ".reloc");
  if (reloc_sec && relocs && relocs->num_sites > 0) {
    if (reloc_build(relocs, reloc_sec, &reloc_rva, &reloc_size) == 0) {
      fprintf(stderr, "[linker] phase 3.5 complete: %d base relocation(s), %u bytes\n",
              relocs->num_sites, reloc_size);
    }
  } else if (reloc_sec) {
    /* No absolute addresses were emitted, so the image is not relocatable.
     * Advertising DYNAMIC_BASE without a relocation table would be a lie
     * that the loader would have to work around, and a section that claims
     * initialized data but has no raw data is not a valid PE section. */
    reloc_rva = 0;
    reloc_size = 0;
    section_merge_remove(ctx, ".reloc");
  }

  /*==== Phase 5: Find/inject entry point ====*/
  uint32_t entry_rva = find_entry_rva(ctx, entry_name);

  /*==== Phase 4: Write PE executable ====*/
  pe_builder_t *pb = pe_builder_new(0x8664);
  if (!pb) {
    merge_context_free(ctx);
    import_table_free(imports);
    reloc_table_free(relocs);
    for (int j = 0; j < num_objs; j++) coff_free(objs[j]);
    free(objs);
    return 1;
  }

  pe_builder_set_entry(pb, entry_rva);
  pe_builder_set_image_base(pb, image_base);
  pe_builder_set_subsystem(pb, subsystem);
  /* Commit sizes are the standard 4 KiB, not a fraction of the reserve. */
  pe_builder_set_stack(pb, stack_reserve, 0x1000);
  pe_builder_set_heap(pb, heap_reserve, 0x1000);
  pe_builder_from_merge(pb, ctx);
  if (deterministic) {
    /* A reproducible build must not embed the wall-clock time. */
    pe_builder_set_deterministic(pb, 1);
    pe_builder_set_timestamp(pb, 0);
  }

  /* Data directories. Every RVA here is image-relative. */
  if (imports->num_dlls > 0) {
    pe_builder_set_import_dir(pb, imports->idata_rva, imports->idata_size);
    /* The IAT directory spans the address tables of every imported DLL. */
    uint32_t iat_start = 0xFFFFFFFFu, iat_end = 0;
    for (int d = 0; d < imports->num_dlls; d++) {
      uint32_t start = imports->dlls[d].iat_rva;
      uint32_t end = start + (uint32_t)(imports->dlls[d].num_symbols + 1) * 8;
      if (start < iat_start) iat_start = start;
      if (end > iat_end) iat_end = end;
    }
    if (iat_start != 0xFFFFFFFFu) {
      pe_builder_set_iat_dir(pb, iat_start, iat_end - iat_start);
    }
  }
  if (reloc_rva) {
    pe_builder_set_reloc_dir(pb, reloc_rva, reloc_size);
  }
  if (export_rva) {
    pe_builder_set_export_dir(pb, export_rva, export_size);
  }
  if (make_dll) {
    pe_builder_set_dll(pb, 1);
  }

  if (verbose) pe_builder_dump(pb, stderr);

  int ret = pe_builder_write(pb, out_path);
  if (exports) export_table_free(exports);
  if (ret == 0) {
    fprintf(stderr, "[linker] phase 4 complete: %s written successfully\n", out_path);
  } else {
    fprintf(stderr, "[linker] phase 4 FAILED: could not write %s\n", out_path);
  }

  /*==== Write map file if requested ====*/
  if (write_map && ret == 0)
    write_map_file(out_path, ctx, image_base);

  /*==== Cleanup ====*/
  pe_builder_free(pb);
  merge_context_free(ctx);
  for (int j = 0; j < num_objs; j++) coff_free(objs[j]);
  free(objs);

  fprintf(stderr, "[linker] all phases complete (exit %d)\n", ret != 0);
  return ret != 0;
}
