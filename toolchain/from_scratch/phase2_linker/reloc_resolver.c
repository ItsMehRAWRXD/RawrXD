/*
 * Relocation resolver — REL32 and ADDR64 fixups.
 * Type 0 = no-op; unsupported types emit a warning and are skipped (non-fatal).
 */
#include "reloc_resolver.h"
#include "coff_reader.h"
#include <stdio.h>
#include <string.h>

#define IMAGE_REL_AMD64_ABSOLUTE 0
#define IMAGE_REL_AMD64_ADDR64  0x0001
#define IMAGE_REL_AMD64_REL32   0x0004

static int is_text_section(const char* name) {
    return strcmp(name, ".text") == 0 || strncmp(name, ".text$", 6) == 0 ||
           strcmp(name, ".CODE") == 0 || strncmp(name, ".CODE$", 6) == 0;
}

static void w32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)(v >> 24);
}

void reloc_apply(uint8_t* section_data, uint32_t section_rva, uint32_t offset, uint16_t type, uint32_t target_rva) {
    uint8_t* at = section_data + offset;
    if (type == IMAGE_REL_AMD64_ABSOLUTE) {
        /* No-op; common for absolute symbols in COFF */
        (void)at;
        (void)section_rva;
        (void)target_rva;
    } else if (type == IMAGE_REL_AMD64_REL32) {
        /* rel32 = target - (site_rva + 4); addend is already in the instruction, we overwrite */
        uint32_t current_next = section_rva + offset + 4u;
        uint32_t rel32 = target_rva - current_next;
        w32(at, rel32);
    } else if (type == IMAGE_REL_AMD64_ADDR64) {
        w32(at, target_rva);
        w32(at + 4, 0);
    } else {
        fprintf(stderr, "warning: unsupported relocation type %u (non-fatal)\n", (unsigned)type);
    }
}

int reloc_resolver_apply_with_imports(uint8_t* text_data, uint32_t text_rva,
    const uint32_t* obj_text_offsets, CoffFile** objs, int num_objs, uint32_t main_rva, uint32_t __main_rva,
    const import_entry_t* imports, int num_imports) {
    fprintf(stderr, "[RELOC] Starting relocation resolution for %d objects\n", num_objs);
    for (int i = 0; i < num_objs; i++) {
        CoffFile* cf = objs[i];
        uint32_t base = obj_text_offsets[i];
        fprintf(stderr, "[RELOC] Processing object %d, base offset = 0x%X\n", i, base);

        for (uint32_t s = 0; s < cf->num_sections; s++) {
            CoffSection* sec = &cf->sections[s];
            fprintf(stderr, "[RELOC] Section %d: name='%s', num_relocs=%u\n", s, sec->name, sec->num_relocs);
            if (!is_text_section(sec->name)) continue;

            for (uint32_t r = 0; r < sec->num_relocs; r++) {
                CoffReloc* rel = &sec->relocs[r];
                fprintf(stderr, "[RELOC] Relocation %u: symbol_index=%u, type=%u, offset=0x%X\n",
                        r, rel->symbol_index, rel->type, rel->offset_in_section);
                if (rel->symbol_index >= cf->num_symbol_table_entries) {
                    fprintf(stderr, "[RELOC]   Skipping: symbol_index out of range\n");
                    continue;
                }
                uint32_t primary_idx = cf->file_symbol_index_to_primary[rel->symbol_index];
                if (primary_idx == 0xFFFFFFFFu) {
                    fprintf(stderr, "[RELOC]   Skipping: aux entry\n");
                    continue;
                }

                CoffSymbol* sym = &cf->symbols[primary_idx];
                const char* sym_name = coff_symbol_name(cf, sym);
                fprintf(stderr, "[RELOC]   Symbol: name='%s', section_number=%d, value=0x%X\n",
                        sym_name, sym->section_number, sym->value);
                uint32_t target_rva;
                int resolved = 0;

                if (sym->section_number > 0) {
                    target_rva = text_rva + base + sym->value;
                    resolved = 1;
                    fprintf(stderr, "[RELOC]   Resolved to internal RVA: 0x%X\n", target_rva);
                } else {
                    if (strcmp(sym_name, "main") == 0) {
                        target_rva = main_rva;
                        resolved = 1;
                        fprintf(stderr, "[RELOC]   Resolved 'main' to RVA: 0x%X\n", target_rva);
                    } else if (strcmp(sym_name, "__main") == 0) {
                        target_rva = __main_rva;
                        resolved = 1;
                        fprintf(stderr, "[RELOC]   Resolved '__main' to RVA: 0x%X\n", target_rva);
                    } else {
                        /* Check imports */
                        for (int j = 0; j < num_imports; j++) {
                            if (strcmp(sym_name, imports[j].name) == 0) {
                                target_rva = imports[j].iat_rva;
                                resolved = 1;
                                fprintf(stderr, "[RELOC]   Resolved import '%s' to IAT RVA: 0x%X\n", sym_name, target_rva);
                                break;
                            }
                        }
                    }
                }

                if (!resolved) {
                    fprintf(stderr, "undefined symbol: %s\n", sym_name);
                    return -1;
                }

                uint32_t reloc_offset = base + rel->offset_in_section;
                fprintf(stderr, "[RELOC]   Applying relocation at offset 0x%X, target RVA 0x%X\n", reloc_offset, target_rva);
                reloc_apply(text_data, text_rva, reloc_offset, rel->type, target_rva);
            }
            break;
        }
    }
    fprintf(stderr, "[RELOC] Relocation resolution complete\n");
    return 0;
}

int reloc_resolver_apply(uint8_t* text_data, uint32_t text_rva,
    const uint32_t* obj_text_offsets, CoffFile** objs, int num_objs, uint32_t main_rva, uint32_t __main_rva) {
    return reloc_resolver_apply_with_imports(text_data, text_rva, obj_text_offsets, objs, num_objs, 
                                               main_rva, __main_rva, NULL, 0);
}
