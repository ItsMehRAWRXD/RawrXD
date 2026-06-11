// =============================================================================
// SovereignPE_Analysis.cpp
// Self-Hosted PE Analysis Engine - Algorithm Implementations
// Extracted from CODEX v7.0, Omega-Polyglot v3.0, DumpBin Proper v6.0
// Zero Dependencies | Compatible with self-hosted compiler
// =============================================================================

#include "SovereignPE_Analysis.h"
#include <cmath>

// =============================================================================
// Self-Hosted Memory Allocator (replace with your IDE's allocator)
// =============================================================================
static void* PE_Alloc(void* ctx, size_t size) {
    // Your IDE's allocator goes here
    // For now, VirtualAlloc is the only "external" dependency
    return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void PE_Free(void* ctx, void* ptr, size_t size) {
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
}

// =============================================================================
// PE_Open - Parse a PE file from raw bytes
// =============================================================================
extern "C" PE_Analysis* PE_Open(const uint8_t* file_data, uint64_t file_size, void* alloc_ctx) {
    if (!file_data || file_size < 64) return nullptr;
    
    PE_Analysis* pe = (PE_Analysis*)PE_Alloc(alloc_ctx, sizeof(PE_Analysis));
    if (!pe) return nullptr;
    memset(pe, 0, sizeof(PE_Analysis));
    pe->file_base = file_data;
    pe->file_size = file_size;
    pe->allocator_context = alloc_ctx;
    
    // --- Parse DOS Header ---
    memcpy(&pe->dos, file_data, sizeof(PE_DOS_Header));
    if (pe->dos.e_magic != PE_DOS_MAGIC) {
        PE_Free(alloc_ctx, pe, sizeof(PE_Analysis));
        return nullptr;  // Not a PE file
    }
    
    // Check PE signature
    if (pe->dos.e_lfanew + 4 > file_size) {
        PE_Free(alloc_ctx, pe, sizeof(PE_Analysis));
        return nullptr;
    }
    uint32_t pe_sig = *(uint32_t*)(file_data + pe->dos.e_lfanew);
    if (pe_sig != PE_NT_MAGIC) {
        PE_Free(alloc_ctx, pe, sizeof(PE_Analysis));
        return nullptr;
    }
    
    // --- Parse COFF Header ---
    const uint8_t* coff_ptr = file_data + pe->dos.e_lfanew + 4;
    memcpy(&pe->coff, coff_ptr, sizeof(PE_COFF_Header));
    
    // --- Parse Optional Header ---
    const uint8_t* opt_ptr = coff_ptr + sizeof(PE_COFF_Header);
    uint16_t opt_magic = *(uint16_t*)opt_ptr;
    
    if (opt_magic == PE_OPT_MAGIC64) {
        pe->is_64bit = true;
        memcpy(&pe->opt64, opt_ptr, sizeof(PE_Optional_Header64));
    } else if (opt_magic == PE_OPT_MAGIC32) {
        pe->is_64bit = false;
        // For 32-bit, we'd parse PE_Optional_Header32
        // For now, copy the common fields
        memcpy(&pe->opt64, opt_ptr, 224);  // Partial copy
    } else {
        PE_Free(alloc_ctx, pe, sizeof(PE_Analysis));
        return nullptr;
    }
    
    pe->is_dll = (pe->coff.Characteristics & PE_CHAR_DLL) != 0;
    
    // --- Parse Section Headers ---
    pe->num_sections = pe->coff.NumberOfSections;
    size_t sec_alloc = pe->num_sections * sizeof(PE_Section_Header);
    pe->sections = (PE_Section_Header*)PE_Alloc(alloc_ctx, sec_alloc);
    if (!pe->sections) {
        PE_Free(alloc_ctx, pe, sizeof(PE_Analysis));
        return nullptr;
    }
    
    const uint8_t* sec_ptr = opt_ptr + pe->coff.SizeOfOptionalHeader;
    memcpy(pe->sections, sec_ptr, sec_alloc);
    
    // --- Calculate Entropy ---
    pe->total_entropy = PE_CalcEntropy(file_data, (uint32_t)file_size);
    
    pe->section_entropy = (float*)PE_Alloc(alloc_ctx, pe->num_sections * sizeof(float));
    for (uint32_t i = 0; i < pe->num_sections; ++i) {
        const PE_Section_Header& sec = pe->sections[i];
        if (sec.PointerToRawData + sec.SizeOfRawData <= file_size) {
            pe->section_entropy[i] = PE_CalcEntropy(
                file_data + sec.PointerToRawData, sec.SizeOfRawData);
        }
    }
    
    // --- Detect Packing ---
    pe->is_packed = PE_IsPackedHeuristic(pe);
    
    // --- Parse Rich Header ---
    PE_ParseRichHeader(pe);
    
    return pe;
}

// =============================================================================
// PE_Close
// =============================================================================
extern "C" void PE_Close(PE_Analysis* pe) {
    if (!pe) return;
    void* ctx = pe->allocator_context;
    if (pe->sections) PE_Free(ctx, pe->sections, pe->num_sections * sizeof(PE_Section_Header));
    if (pe->section_entropy) PE_Free(ctx, pe->section_entropy, pe->num_sections * sizeof(float));
    if (pe->strings) PE_Free(ctx, pe->strings, pe->string_capacity * sizeof(PE_Analysis::Extracted_String));
    if (pe->rich_entries) PE_Free(ctx, pe->rich_entries, pe->num_rich_entries * sizeof(PE_Rich_Entry));
    // Free imports/exports recursively...
    PE_Free(ctx, pe, sizeof(PE_Analysis));
}

// =============================================================================
// PE_CalcEntropy - Shannon Entropy (from CODEX v7.0)
// H(X) = -sum(p(x) * log2(p(x)))
// Range: 0.0 (all same byte) to 8.0 (perfectly random)
// Packed/encrypted sections typically > 7.0
// =============================================================================
extern "C" float PE_CalcEntropy(const uint8_t* data, uint32_t len) {
    if (!data || len == 0) return 0.0f;
    
    // Frequency table (256 possible byte values)
    uint32_t freq[256] = {0};
    for (uint32_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }
    
    float entropy = 0.0f;
    const float inv_len = 1.0f / (float)len;
    const float log2_val = 1.0f / logf(2.0f);  // 1/ln(2) for log2 conversion
    
    for (uint32_t i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        float p = (float)freq[i] * inv_len;
        entropy -= p * logf(p) * log2_val;  // -p * log2(p)
    }
    
    return entropy;
}

// =============================================================================
// PE_IsPackedHeuristic - Multi-factor packer detection
// From CODEX v7.0 + Omega-Polyglot v3.0 combined heuristics
// =============================================================================
extern "C" bool PE_IsPackedHeuristic(PE_Analysis* pe) {
    if (!pe) return false;
    
    uint32_t score = 0;
    
    // 1. High overall entropy (> 7.2)
    if (pe->total_entropy > 7.2f) score += 30;
    else if (pe->total_entropy > 6.5f) score += 15;
    
    // 2. Section name anomalies (from Omega-Polyglot)
    for (uint32_t i = 0; i < pe->num_sections; ++i) {
        const char* name = pe->sections[i].Name;
        // Common packer section names
        if (memcmp(name, "UPX", 3) == 0 || memcmp(name, "UPX0", 4) == 0) score += 40;
        if (memcmp(name, "ASPack", 6) == 0) score += 40;
        if (memcmp(name, "petite", 6) == 0) score += 40;
        if (memcmp(name, ".vmp", 4) == 0) score += 35;  // VMProtect
        if (memcmp(name, ".themida", 8) == 0) score += 35;
        if (memcmp(name, ".enigma", 7) == 0) score += 35;
        if (memcmp(name, ".text", 5) != 0 &&
            memcmp(name, ".data", 5) != 0 &&
            memcmp(name, ".rdata", 6) != 0 &&
            memcmp(name, ".bss", 4) != 0 &&
            memcmp(name, ".idata", 6) != 0 &&
            memcmp(name, ".edata", 6) != 0 &&
            memcmp(name, ".rsrc", 5) != 0 &&
            memcmp(name, ".reloc", 6) != 0) {
            score += 10;  // Non-standard section name
        }
    }
    
    // 3. High entropy in code section (from CODEX)
    for (uint32_t i = 0; i < pe->num_sections; ++i) {
        if (pe->sections[i].Characteristics & SEC_CHAR_CODE) {
            if (pe->section_entropy && pe->section_entropy[i] > 7.0f) {
                score += 25;  // Code section is encrypted/compressed
            }
        }
    }
    
    // 4. Low import count (packed binaries often have few imports)
    if (pe->num_imports < 5 && pe->num_imports > 0) score += 20;
    
    // 5. Entry point not in .text section (from DumpBin Proper)
    uint32_t ep_rva = pe->opt64.AddressOfEntryPoint;
    bool ep_in_text = false;
    for (uint32_t i = 0; i < pe->num_sections; ++i) {
        if (memcmp(pe->sections[i].Name, ".text", 5) == 0) {
            uint32_t start = pe->sections[i].VirtualAddress;
            uint32_t end = start + pe->sections[i].VirtualSize;
            if (ep_rva >= start && ep_rva < end) ep_in_text = true;
        }
    }
    if (!ep_in_text) score += 20;
    
    // Threshold: score >= 50 = likely packed
    return score >= 50;
}

// =============================================================================
// PE_ExtractStrings - String extraction (from Omega-Polyglot v3.0)
// Extracts ASCII and Unicode strings from binary data
// =============================================================================
extern "C" uint32_t PE_ExtractStrings(PE_Analysis* pe, uint32_t min_length, bool include_unicode) {
    if (!pe || !pe->file_base || pe->file_size == 0) return 0;
    
    const uint8_t* data = pe->file_base;
    uint64_t size = pe->file_size;
    
    // Initial capacity
    uint32_t capacity = 1024;
    pe->strings = (PE_Analysis::Extracted_String*)PE_Alloc(
        pe->allocator_context, capacity * sizeof(PE_Analysis::Extracted_String));
    if (!pe->strings) return 0;
    pe->string_capacity = capacity;
    pe->num_strings = 0;
    
    // --- ASCII strings ---
    uint32_t i = 0;
    while (i < size) {
        // Skip non-printable
        while (i < size && (data[i] < 0x20 || data[i] > 0x7E)) i++;
        
        uint32_t start = i;
        while (i < size && data[i] >= 0x20 && data[i] <= 0x7E) i++;
        
        uint32_t len = i - start;
        if (len >= min_length) {
            // Grow if needed
            if (pe->num_strings >= capacity) {
                capacity *= 2;
                auto* new_buf = (PE_Analysis::Extracted_String*)PE_Alloc(
                    pe->allocator_context, capacity * sizeof(PE_Analysis::Extracted_String));
                if (!new_buf) break;
                memcpy(new_buf, pe->strings, pe->num_strings * sizeof(PE_Analysis::Extracted_String));
                PE_Free(pe->allocator_context, pe->strings, pe->num_strings * sizeof(PE_Analysis::Extracted_String));
                pe->strings = new_buf;
                pe->string_capacity = capacity;
            }
            
            auto& str = pe->strings[pe->num_strings++];
            uint32_t copy_len = (len < 255) ? len : 255;
            memcpy(str.text, data + start, copy_len);
            str.text[copy_len] = '\0';
            str.file_offset = start;
            str.is_unicode = false;
            str.length = copy_len;
        }
    }
    
    // --- Unicode strings (UTF-16LE) ---
    if (include_unicode) {
        i = 0;
        while (i < size - 1) {
            // Check for ASCII-range UTF-16LE: [char][0x00]
            while (i < size - 1 && !(data[i] >= 0x20 && data[i] <= 0x7E && data[i+1] == 0)) {
                i += 2;
            }
            
            uint32_t start = i;
            while (i < size - 1 && data[i] >= 0x20 && data[i] <= 0x7E && data[i+1] == 0) {
                i += 2;
            }
            
            uint32_t len_bytes = i - start;
            uint32_t len_chars = len_bytes / 2;
            if (len_chars >= min_length) {
                if (pe->num_strings >= capacity) {
                    capacity *= 2;
                    auto* new_buf = (PE_Analysis::Extracted_String*)PE_Alloc(
                        pe->allocator_context, capacity * sizeof(PE_Analysis::Extracted_String));
                    if (!new_buf) break;
                    memcpy(new_buf, pe->strings, pe->num_strings * sizeof(PE_Analysis::Extracted_String));
                    PE_Free(pe->allocator_context, pe->strings, pe->num_strings * sizeof(PE_Analysis::Extracted_String));
                    pe->strings = new_buf;
                    pe->string_capacity = capacity;
                }
                
                auto& str = pe->strings[pe->num_strings++];
                uint32_t copy_chars = (len_chars < 127) ? len_chars : 127;
                for (uint32_t j = 0; j < copy_chars; ++j) {
                    str.text[j] = data[start + j * 2];
                }
                str.text[copy_chars] = '\0';
                str.file_offset = start;
                str.is_unicode = true;
                str.length = copy_chars;
            }
        }
    }
    
    return pe->num_strings;
}

// =============================================================================
// PE_EnumerateImports - Walk Import Directory (from CODEX v7.0)
// =============================================================================
extern "C" uint32_t PE_EnumerateImports(PE_Analysis* pe) {
    if (!pe || !pe->is_64bit) return 0;  // TODO: support 32-bit
    
    uint32_t import_dir_rva = pe->opt64.DataDirectory[static_cast<uint32_t>(PE_Directory::Import)].VirtualAddress;
    uint32_t import_dir_size = pe->opt64.DataDirectory[static_cast<uint32_t>(PE_Directory::Import)].Size;
    
    if (import_dir_rva == 0 || import_dir_size == 0) return 0;
    
    uint32_t import_offset = PE_RVAToFileOffset(pe, import_dir_rva);
    if (import_offset == 0 || import_offset + import_dir_size > pe->file_size) return 0;
    
    // Count DLLs first
    uint32_t num_dlls = 0;
    const PE_Import_Directory* dir = (const PE_Import_Directory*)(pe->file_base + import_offset);
    while (dir->NameRVA != 0) {
        num_dlls++;
        dir++;
    }
    
    pe->imports = (PE_Analysis::Import_DLL*)PE_Alloc(
        pe->allocator_context, num_dlls * sizeof(PE_Analysis::Import_DLL));
    if (!pe->imports) return 0;
    pe->num_imports = 0;
    
    // Parse each DLL
    dir = (const PE_Import_Directory*)(pe->file_base + import_offset);
    for (uint32_t d = 0; d < num_dlls; ++d) {
        auto& dll = pe->imports[pe->num_imports];
        memset(&dll, 0, sizeof(dll));
        
        // DLL name
        uint32_t name_offset = PE_RVAToFileOffset(pe, dir[d].NameRVA);
        if (name_offset > 0 && name_offset < pe->file_size) {
            const char* name = (const char*)(pe->file_base + name_offset);
            uint32_t name_len = 0;
            while (name_len < 63 && name_offset + name_len < pe->file_size && name[name_len] != '\0') {
                dll.dll_name[name_len] = name[name_len];
                name_len++;
            }
            dll.dll_name[name_len] = '\0';
        }
        
        // Count symbols
        uint32_t ilt_rva = dir[d].ImportLookupTableRVA;
        if (ilt_rva == 0) ilt_rva = dir[d].ImportAddressTableRVA;
        
        uint32_t ilt_offset = PE_RVAToFileOffset(pe, ilt_rva);
        if (ilt_offset == 0) continue;
        
        uint32_t num_syms = 0;
        if (pe->is_64bit) {
            const uint64_t* ilt = (const uint64_t*)(pe->file_base + ilt_offset);
            while (*ilt != 0) {
                num_syms++;
                ilt++;
            }
        } else {
            const uint32_t* ilt = (const uint32_t*)(pe->file_base + ilt_offset);
            while (*ilt != 0) {
                num_syms++;
                ilt++;
            }
        }
        
        dll.symbols = (PE_Analysis::Import_DLL::Import_Symbol*)PE_Alloc(
            pe->allocator_context, num_syms * sizeof(PE_Analysis::Import_DLL::Import_Symbol));
        if (!dll.symbols) continue;
        dll.num_symbols = 0;
        
        // Parse symbols
        if (pe->is_64bit) {
            const uint64_t* ilt = (const uint64_t*)(pe->file_base + ilt_offset);
            for (uint32_t s = 0; s < num_syms; ++s) {
                auto& sym = dll.symbols[dll.num_symbols++];
                memset(&sym, 0, sizeof(sym));
                
                if (ilt[s] & 0x8000000000000000ULL) {
                    // Import by ordinal
                    sym.by_ordinal = true;
                    sym.ordinal = (uint16_t)(ilt[s] & 0xFFFF);
                } else {
                    // Import by name
                    sym.by_ordinal = false;
                    uint32_t hint_name_rva = (uint32_t)(ilt[s] & 0xFFFFFFFF);
                    uint32_t hint_name_offset = PE_RVAToFileOffset(pe, hint_name_rva);
                    if (hint_name_offset > 0 && hint_name_offset + 2 < pe->file_size) {
                        const char* sym_name = (const char*)(pe->file_base + hint_name_offset + 2);
                        uint32_t sym_len = 0;
                        while (sym_len < 127 && hint_name_offset + 2 + sym_len < pe->file_size && 
                               sym_name[sym_len] != '\0') {
                            sym.name[sym_len] = sym_name[sym_len];
                            sym_len++;
                        }
                        sym.name[sym_len] = '\0';
                    }
                }
            }
        }
        
        pe->num_imports++;
    }
    
    return pe->num_imports;
}

// =============================================================================
// PE_EnumerateExports - Walk Export Directory (from CODEX v7.0)
// =============================================================================
extern "C" uint32_t PE_EnumerateExports(PE_Analysis* pe) {
    if (!pe) return 0;
    
    uint32_t export_dir_rva = pe->opt64.DataDirectory[static_cast<uint32_t>(PE_Directory::Export)].VirtualAddress;
    uint32_t export_dir_size = pe->opt64.DataDirectory[static_cast<uint32_t>(PE_Directory::Export)].Size;
    
    if (export_dir_rva == 0 || export_dir_size == 0) return 0;
    
    uint32_t export_offset = PE_RVAToFileOffset(pe, export_dir_rva);
    if (export_offset == 0 || export_offset + sizeof(PE_Export_Directory) > pe->file_size) return 0;
    
    const PE_Export_Directory* ed = (const PE_Export_Directory*)(pe->file_base + export_offset);
    
    uint32_t num_exports = ed->AddressTableEntries;
    if (num_exports == 0) return 0;
    
    pe->exports = (PE_Analysis::Export_Symbol*)PE_Alloc(
        pe->allocator_context, num_exports * sizeof(PE_Analysis::Export_Symbol));
    if (!pe->exports) return 0;
    pe->num_exports = 0;
    
    uint32_t eat_offset = PE_RVAToFileOffset(pe, ed->ExportAddressTableRVA);
    uint32_t names_offset = PE_RVAToFileOffset(pe, ed->NamePointerRVA);
    uint32_t ordinals_offset = PE_RVAToFileOffset(pe, ed->OrdinalTableRVA);
    
    if (eat_offset == 0) return 0;
    
    const uint32_t* eat = (const uint32_t*)(pe->file_base + eat_offset);
    const uint32_t* names = (names_offset > 0) ? (const uint32_t*)(pe->file_base + names_offset) : nullptr;
    const uint16_t* ordinals = (ordinals_offset > 0) ? (const uint16_t*)(pe->file_base + ordinals_offset) : nullptr;
    
    for (uint32_t i = 0; i < num_exports; ++i) {
        auto& exp = pe->exports[pe->num_exports++];
        memset(&exp, 0, sizeof(exp));
        
        exp.rva = eat[i];
        exp.ordinal = (uint16_t)(ed->OrdinalBase + i);
        
        // Check if forwarded
        if (exp.rva >= export_dir_rva && exp.rva < export_dir_rva + export_dir_size) {
            exp.forwarded = true;
            uint32_t fwd_offset = PE_RVAToFileOffset(pe, exp.rva);
            if (fwd_offset > 0 && fwd_offset < pe->file_size) {
                const char* fwd = (const char*)(pe->file_base + fwd_offset);
                uint32_t fwd_len = 0;
                while (fwd_len < 127 && fwd_offset + fwd_len < pe->file_size && fwd[fwd_len] != '\0') {
                    exp.forwarder[fwd_len] = fwd[fwd_len];
                    fwd_len++;
                }
                exp.forwarder[fwd_len] = '\0';
            }
        }
        
        // Find name by ordinal
        if (names && ordinals) {
            for (uint32_t n = 0; n < ed->NumberOfNamePointers; ++n) {
                if (ordinals[n] == i) {
                    uint32_t name_rva = names[n];
                    uint32_t name_offset = PE_RVAToFileOffset(pe, name_rva);
                    if (name_offset > 0 && name_offset < pe->file_size) {
                        const char* sym_name = (const char*)(pe->file_base + name_offset);
                        uint32_t name_len = 0;
                        while (name_len < 127 && name_offset + name_len < pe->file_size && 
                               sym_name[name_len] != '\0') {
                            exp.name[name_len] = sym_name[name_len];
                            name_len++;
                        }
                        exp.name[name_len] = '\0';
                    }
                    break;
                }
            }
        }
    }
    
    return pe->num_exports;
}

// =============================================================================
// PE_ParseRichHeader - Undocumented rich header parser (from CODEX v7.0)
// Located between DOS stub and PE header
// Format: "DanS" XOR key, then (comp_id << 16 | count) XOR key pairs
// =============================================================================
extern "C" bool PE_ParseRichHeader(PE_Analysis* pe) {
    if (!pe || pe->dos.e_lfanew < 0x80) return false;
    
    // Rich header starts after DOS stub, ends with "Rich" marker
    const uint32_t* data = (const uint32_t*)(pe->file_base + 0x80);
    uint32_t max_search = (pe->dos.e_lfanew - 0x80) / 4;
    if (max_search > 128) max_search = 128;
    
    // Find "Rich" marker (0x68636952)
    uint32_t rich_offset = 0;
    for (uint32_t i = 0; i < max_search; ++i) {
        if (data[i] == 0x68636952) {  // "Rich"
            rich_offset = i;
            break;
        }
    }
    if (rich_offset == 0) return false;
    
    // XOR key is the dword after "Rich"
    uint32_t xor_key = data[rich_offset + 1];
    
    // "DanS" marker should be at start, XORed with key
    if ((data[0] ^ xor_key) != 0x536E6144) return false;  // "DanS"
    
    // Parse entries between "DanS" and "Rich"
    uint32_t num_entries = (rich_offset - 1) / 2;  // Each entry is 2 dwords
    if (num_entries == 0) return false;
    
    pe->rich_entries = (PE_Rich_Entry*)PE_Alloc(
        pe->allocator_context, num_entries * sizeof(PE_Rich_Entry));
    if (!pe->rich_entries) return false;
    pe->num_rich_entries = 0;
    
    for (uint32_t i = 1; i < rich_offset; i += 2) {
        uint32_t val1 = data[i] ^ xor_key;
        uint32_t val2 = data[i + 1] ^ xor_key;
        
        pe->rich_entries[pe->num_rich_entries].comp_id = (uint16_t)(val1 >> 16);
        pe->rich_entries[pe->num_rich_entries].count = (uint16_t)(val1 & 0xFFFF);
        pe->num_rich_entries++;
        
        if (pe->num_rich_entries >= num_entries) break;
    }
    
    // Format XOR key as hex string
    const char* hex = "0123456789ABCDEF";
    for (int i = 0; i < 8; ++i) {
        pe->rich_xor_key_hex[i * 2] = hex[(xor_key >> (28 - i * 4)) & 0xF];
        pe->rich_xor_key_hex[i * 2 + 1] = hex[(xor_key >> (24 - i * 4)) & 0xF];
    }
    pe->rich_xor_key_hex[16] = '\0';
    
    return true;
}

// =============================================================================
// PE_GetCompilerFromRichId - Map rich header comp_id to compiler version
// From: https://github.com/dishather/richprint/blob/master/comp_id.md
// =============================================================================
extern "C" const char* PE_GetCompilerFromRichId(uint16_t comp_id) {
    // MSVC Linker IDs
    if (comp_id >= 0x00FC && comp_id <= 0x0103) return "MSVC 2022 (v17.x)";
    if (comp_id >= 0x00F4 && comp_id <= 0x00FB) return "MSVC 2019 (v16.x)";
    if (comp_id >= 0x00EB && comp_id <= 0x00F3) return "MSVC 2017 (v15.x)";
    if (comp_id >= 0x00E0 && comp_id <= 0x00EA) return "MSVC 2015 (v14.x)";
    if (comp_id >= 0x00D0 && comp_id <= 0x00DF) return "MSVC 2013 (v12.x)";
    if (comp_id >= 0x00C0 && comp_id <= 0x00CF) return "MSVC 2012 (v11.x)";
    if (comp_id >= 0x00B0 && comp_id <= 0x00BF) return "MSVC 2010 (v10.x)";
    if (comp_id >= 0x00A0 && comp_id <= 0x00AF) return "MSVC 2008 (v9.x)";
    if (comp_id >= 0x0090 && comp_id <= 0x009F) return "MSVC 2005 (v8.x)";
    
    // MSVC C++ compiler IDs
    if (comp_id >= 0x0104 && comp_id <= 0x010B) return "MSVC C++ 2022";
    if (comp_id >= 0x010C && comp_id <= 0x0113) return "MSVC C++ 2019";
    
    // MASM
    if (comp_id == 0x00FF) return "MASM (ml.exe)";
    if (comp_id == 0x0100) return "MASM64 (ml64.exe)";
    
    // Unknown
    static char buf[32];
    const char* hex = "0123456789ABCDEF";
    buf[0] = '0'; buf[1] = 'x';
    buf[2] = hex[(comp_id >> 12) & 0xF];
    buf[3] = hex[(comp_id >> 8) & 0xF];
    buf[4] = hex[(comp_id >> 4) & 0xF];
    buf[5] = hex[comp_id & 0xF];
    buf[6] = '\0';
    return buf;
}

// =============================================================================
// PE_RVAToFileOffset - Convert RVA to file offset
// =============================================================================
extern "C" uint32_t PE_RVAToFileOffset(PE_Analysis* pe, uint32_t rva) {
    if (!pe || !pe->sections || pe->num_sections == 0) {
        // If no sections, assume flat mapping (common for object files)
        return rva;
    }
    
    for (uint32_t i = 0; i < pe->num_sections; ++i) {
        const PE_Section_Header& sec = pe->sections[i];
        uint32_t start = sec.VirtualAddress;
        uint32_t end = start + sec.VirtualSize;
        if (rva >= start && rva < end) {
            return rva - start + sec.PointerToRawData;
        }
    }
    
    return 0;  // Not found
}

// =============================================================================
// PE_GetMachineName
// =============================================================================
extern "C" const char* PE_GetMachineName(uint16_t machine) {
    switch (machine) {
        case 0x014C: return "x86 (I386)";
        case 0x8664: return "x64 (AMD64)";
        case 0xAA64: return "ARM64";
        case 0x01C0: return "ARM";
        case 0xEBC:  return "EFI Byte Code";
        case 0x0200: return "IA-64 (Itanium)";
        default:     return "Unknown";
    }
}

// =============================================================================
// PE_GetSubsystemName
// =============================================================================
extern "C" const char* PE_GetSubsystemName(uint16_t subsystem) {
    switch (subsystem) {
        case 0:  return "UNKNOWN";
        case 1:  return "NATIVE (Driver)";
        case 2:  return "WINDOWS_GUI";
        case 3:  return "WINDOWS_CUI (Console)";
        case 5:  return "OS2_CUI";
        case 7:  return "POSIX_CUI";
        case 9:  return "WINDOWS_CE_GUI";
        case 10: return "EFI_APPLICATION";
        case 11: return "EFI_BOOT_SERVICE_DRIVER";
        case 12: return "EFI_RUNTIME_DRIVER";
        case 13: return "EFI_ROM";
        case 14: return "XBOX";
        case 16: return "WINDOWS_BOOT_APPLICATION";
        default: return "Unknown";
    }
}

// =============================================================================
// PE_GetSectionFlagsString
// =============================================================================
extern "C" const char* PE_GetSectionFlagsString(uint32_t flags, char* buf, size_t buf_size) {
    if (!buf || buf_size == 0) return "";
    buf[0] = '\0';
    
    if (flags & SEC_CHAR_CODE)  strncat(buf, "CODE ", buf_size - strlen(buf) - 1);
    if (flags & SEC_CHAR_DATA)  strncat(buf, "DATA ", buf_size - strlen(buf) - 1);
    if (flags & SEC_CHAR_BSS)   strncat(buf, "BSS ", buf_size - strlen(buf) - 1);
    if (flags & SEC_CHAR_EXEC)  strncat(buf, "EXEC ", buf_size - strlen(buf) - 1);
    if (flags & SEC_CHAR_READ)  strncat(buf, "READ ", buf_size - strlen(buf) - 1);
    if (flags & SEC_CHAR_WRITE) strncat(buf, "WRITE", buf_size - strlen(buf) - 1);
    
    return buf;
}

// =============================================================================
// PE_GenerateAIContext - Generate analysis summary for AI chat
// =============================================================================
extern "C" void PE_GenerateAIContext(PE_Analysis* pe, char* out_buf, size_t out_size) {
    if (!pe || !out_buf || out_size == 0) return;
    
    char* p = out_buf;
    size_t remaining = out_size;
    
    auto append = [&](const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        int n = vsnprintf(p, remaining, fmt, args);
        va_end(args);
        if (n > 0) {
            p += n;
            remaining -= n;
        }
    };
    
    append("Binary Analysis:\n");
    append("  Architecture: %s\n", PE_GetMachineName(pe->coff.Machine));
    append("  Type: %s\n", pe->is_dll ? "DLL" : "EXE");
    append("  Bits: %s\n", pe->is_64bit ? "64-bit" : "32-bit");
    append("  Subsystem: %s\n", PE_GetSubsystemName(pe->opt64.Subsystem));
    append("  Entry Point: 0x%08X\n", pe->opt64.AddressOfEntryPoint);
    append("  Image Base: 0x%016llX\n", (unsigned long long)PE_GetImageBase(pe));
    append("  Sections: %u\n", pe->num_sections);
    append("  Entropy: %.2f/8.00\n", pe->total_entropy);
    append("  Packed: %s\n", pe->is_packed ? "YES (suspicious)" : "No");
    append("  Imports: %u DLLs\n", pe->num_imports);
    append("  Exports: %u symbols\n", pe->num_exports);
    append("  Strings: %u extracted\n", pe->num_strings);
    
    if (pe->num_rich_entries > 0) {
        append("  Compiler: %s\n", PE_GetCompilerFromRichId(pe->rich_entries[0].comp_id));
    }
    
    if (pe->is_packed) {
        append("\n⚠️ This binary appears packed or encrypted.\n");
        append("   High entropy (%.2f) and non-standard section names detected.\n", 
               pe->total_entropy);
    }
}

// =============================================================================
// PE_GetImageBase / PE_GetEntryPoint
// =============================================================================
extern "C" uint64_t PE_GetImageBase(PE_Analysis* pe) {
    return pe ? (pe->is_64bit ? pe->opt64.ImageBase : (uint64_t)(*(uint32_t*)&pe->opt64.ImageBase)) : 0;
}

extern "C" uint32_t PE_GetEntryPoint(PE_Analysis* pe) {
    return pe ? pe->opt64.AddressOfEntryPoint : 0;
}
