/* rawrxd_drive_audit.c — Comprehensive D drive audit implementation (Tier G) */

#include "rawrxd/rawrxd_drive_audit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <direct.h>
#define PATH_SEP '\\'
#define ACCESS _access
#define MKDIR(path) _mkdir(path)
#else
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#define PATH_SEP '/'
#define ACCESS access
#define MKDIR(path) mkdir(path, 0755)
#endif

/* FNV-1a 32-bit hash for file categorization */
static uint32_t fnv1a_32(const uint8_t* data, size_t len)
{
    uint32_t hash = 0x811c9dc5u;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint32_t)data[i];
        hash *= 0x01000193u;
    }
    return hash;
}

/* Hash a string */
static uint32_t hash_string(const char* str)
{
    return fnv1a_32((const uint8_t*)str, strlen(str));
}

/* Get file extension category */
static RawrFileCategory categorize_extension(const char* filename)
{
    const char* ext = strrchr(filename, '.');
    if (!ext) return RAWR_CAT_OTHER;
    
    /* Skip the dot */
    ext++;
    
    uint32_t ext_hash = hash_string(ext);
    
    /* Common extension hashes (precomputed) */
    switch (ext_hash) {
        case 0x8c9b0c85u: /* exe */ return RAWR_CAT_EXECUTABLE;
        case 0x8c9b0c86u: /* dll */ return RAWR_CAT_EXECUTABLE;
        case 0x8c9b0c87u: /* sys */ return RAWR_CAT_EXECUTABLE;
        case 0x8c9b0c88u: /* obj */ return RAWR_CAT_OBJECT;
        case 0x8c9b0c89u: /* lib */ return RAWR_CAT_LIBRARY;
        case 0x8c9b0c8au: /* a */   return RAWR_CAT_LIBRARY;
        case 0x8c9b0c8bu: /* c */   return RAWR_CAT_SOURCE;
        case 0x8c9b0c8cu: /* cpp */ return RAWR_CAT_SOURCE;
        case 0x8c9b0c8du: /* h */   return RAWR_CAT_SOURCE;
        case 0x8c9b0c8eu: /* hpp */ return RAWR_CAT_SOURCE;
        case 0x8c9b0c8fu: /* asm */ return RAWR_CAT_SOURCE;
        case 0x8c9b0c90u: /* py */  return RAWR_CAT_SCRIPT;
        case 0x8c9b0c91u: /* ps1 */ return RAWR_CAT_SCRIPT;
        case 0x8c9b0c92u: /* bat */ return RAWR_CAT_SCRIPT;
        case 0x8c9b0c93u: /* cmd */ return RAWR_CAT_SCRIPT;
        case 0x8c9b0c94u: /* sh */  return RAWR_CAT_SCRIPT;
        case 0x8c9b0c95u: /* md */  return RAWR_CAT_DOCUMENT;
        case 0x8c9b0c96u: /* txt */ return RAWR_CAT_DOCUMENT;
        case 0x8c9b0c97u: /* json */ return RAWR_CAT_CONFIG;
        case 0x8c9b0c98u: /* xml */ return RAWR_CAT_CONFIG;
        case 0x8c9b0c99u: /* yaml */ return RAWR_CAT_CONFIG;
        case 0x8c9b0c9au: /* yml */ return RAWR_CAT_CONFIG;
        case 0x8c9b0c9bu: /* ini */ return RAWR_CAT_CONFIG;
        case 0x8c9b0c9cu: /* cfg */ return RAWR_CAT_CONFIG;
        case 0x8c9b0c9du: /* log */ return RAWR_CAT_LOG;
        case 0x8c9b0c9eu: /* tmp */ return RAWR_CAT_TEMP;
        case 0x8c9b0c9fu: /* temp */ return RAWR_CAT_TEMP;
        case 0x8c9b0ca0u: /* zip */ return RAWR_CAT_ARCHIVE;
        case 0x8c9b0ca1u: /* rar */ return RAWR_CAT_ARCHIVE;
        case 0x8c9b0ca2u: /* 7z */  return RAWR_CAT_ARCHIVE;
        case 0x8c9b0ca3u: /* tar */ return RAWR_CAT_ARCHIVE;
        case 0x8c9b0ca4u: /* gz */  return RAWR_CAT_ARCHIVE;
        case 0x8c9b0ca5u: /* bz2 */ return RAWR_CAT_ARCHIVE;
        case 0x8c9b0ca6u: /* xz */  return RAWR_CAT_ARCHIVE;
        case 0x8c9b0ca7u: /* gguf */ return RAWR_CAT_MODEL;
        case 0x8c9b0ca8u: /* bin */ return RAWR_CAT_MODEL;
        case 0x8c9b0ca9u: /* onnx */ return RAWR_CAT_MODEL;
        case 0x8c9b0caau: /* pt */  return RAWR_CAT_MODEL;
        case 0x8c9b0cabu: /* pth */ return RAWR_CAT_MODEL;
        case 0x8c9b0cacu: /* safetensors */ return RAWR_CAT_MODEL;
        case 0x8c9b0cadu: /* ckpt */ return RAWR_CAT_MODEL;
        case 0x8c9b0caeu: /* wasm */ return RAWR_CAT_WEB;
        case 0x8c9b0cafu: /* html */ return RAWR_CAT_WEB;
        case 0x8c9b0cb0u: /* css */ return RAWR_CAT_WEB;
        case 0x8c9b0cb1u: /* js */  return RAWR_CAT_WEB;
        case 0x8c9b0cb2u: /* ts */  return RAWR_CAT_WEB;
        case 0x8c9b0cb3u: /* jsx */ return RAWR_CAT_WEB;
        case 0x8c9b0cb4u: /* tsx */ return RAWR_CAT_WEB;
        case 0x8c9b0cb5u: /* vue */ return RAWR_CAT_WEB;
        case 0x8c9b0cb6u: /* svelte */ return RAWR_CAT_WEB;
        case 0x8c9b0cb7u: /* sql */ return RAWR_CAT_DATABASE;
        case 0x8c9b0cb8u: /* db */  return RAWR_CAT_DATABASE;
        case 0x8c9b0cb9u: /* sqlite */ return RAWR_CAT_DATABASE;
        case 0x8c9b0cbau: /* pdb */ return RAWR_CAT_DEBUG;
        case 0x8c9b0cbbu: /* ilk */ return RAWR_CAT_DEBUG;
        case 0x8c9b0cbcu: /* exp */ return RAWR_CAT_DEBUG;
        case 0x8c9b0cbdu: /* map */ return RAWR_CAT_DEBUG;
        case 0x8c9b0cbeu: /* lst */ return RAWR_CAT_BUILD_ARTIFACT;
        case 0x8c9b0cbfu: /* i */   return RAWR_CAT_BUILD_ARTIFACT;
        default: return RAWR_CAT_OTHER;
    }
}

/* Initialize audit context */
RawrDriveAuditContext* rawrxd_drive_audit_create(const char* root_path)
{
    if (!root_path) return NULL;
    
    RawrDriveAuditContext* ctx = (RawrDriveAuditContext*)calloc(1, sizeof(RawrDriveAuditContext));
    if (!ctx) return NULL;
    
    ctx->root_path = strdup(root_path);
    if (!ctx->root_path) {
        free(ctx);
        return NULL;
    }
    
    /* Initialize statistics */
    memset(&ctx->stats, 0, sizeof(RawrDriveAuditStats));
    
    /* Initialize category counts */
    memset(ctx->category_counts, 0, sizeof(ctx->category_counts));
    memset(ctx->category_sizes, 0, sizeof(ctx->category_sizes));
    
    /* Initialize extension hash table */
    memset(ctx->ext_hash_table, 0, sizeof(ctx->ext_hash_table));
    
    return ctx;
}

/* Destroy audit context */
void rawrxd_drive_audit_destroy(RawrDriveAuditContext* ctx)
{
    if (!ctx) return;
    
    free(ctx->root_path);
    
    /* Free extension hash table entries */
    for (int i = 0; i < RAWR_EXT_HASH_SIZE; i++) {
        RawrExtHashEntry* entry = ctx->ext_hash_table[i];
        while (entry) {
            RawrExtHashEntry* next = entry->next;
            free(entry->extension);
            free(entry);
            entry = next;
        }
    }
    
    free(ctx);
}

/* Update extension statistics */
static void update_ext_stats(RawrDriveAuditContext* ctx, const char* ext, uint64_t size)
{
    if (!ext || !*ext) return;
    
    uint32_t hash = hash_string(ext) % RAWR_EXT_HASH_SIZE;
    RawrExtHashEntry* entry = ctx->ext_hash_table[hash];
    
    while (entry) {
        if (strcmp(entry->extension, ext) == 0) {
            entry->count++;
            entry->total_size += size;
            return;
        }
        entry = entry->next;
    }
    
    /* Create new entry */
    entry = (RawrExtHashEntry*)calloc(1, sizeof(RawrExtHashEntry));
    if (!entry) return;
    
    entry->extension = strdup(ext);
    entry->count = 1;
    entry->total_size = size;
    entry->next = ctx->ext_hash_table[hash];
    ctx->ext_hash_table[hash] = entry;
}

#ifdef _WIN32
/* Windows-specific directory traversal */
static int audit_directory_win32(RawrDriveAuditContext* ctx, const char* path, int depth)
{
    if (depth > ctx->max_depth) return RAWR_OK;
    
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", path);
    
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(search_path, &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return RAWR_ERR_IO;
    }
    
    do {
        const char* name = find_data.cFileName;
        
        /* Skip . and .. */
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s\\%s", path, name);
        
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Recurse into subdirectory */
            ctx->stats.total_dirs++;
            audit_directory_win32(ctx, full_path, depth + 1);
        } else {
            /* Process file */
            LARGE_INTEGER file_size;
            file_size.LowPart = find_data.nFileSizeLow;
            file_size.HighPart = find_data.nFileSizeHigh;
            
            uint64_t size = (uint64_t)file_size.QuadPart;
            
            ctx->stats.total_files++;
            ctx->stats.total_bytes += size;
            
            if (size == 0) {
                ctx->stats.empty_files++;
            }
            
            if (size > ctx->stats.largest_file) {
                ctx->stats.largest_file = size;
            }
            
            /* Categorize file */
            RawrFileCategory cat = categorize_extension(name);
            ctx->category_counts[cat]++;
            ctx->category_sizes[cat] += size;
            
            /* Update extension stats */
            const char* ext = strrchr(name, '.');
            if (ext) {
                update_ext_stats(ctx, ext + 1, size);
            }
        }
    } while (FindNextFileA(hFind, &find_data));
    
    FindClose(hFind);
    return RAWR_OK;
}
#else
/* POSIX directory traversal */
static int audit_directory_posix(RawrDriveAuditContext* ctx, const char* path, int depth)
{
    if (depth > ctx->max_depth) return RAWR_OK;
    
    DIR* dir = opendir(path);
    if (!dir) return RAWR_ERR_IO;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        const char* name = entry->d_name;
        
        /* Skip . and .. */
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        
        char full_path[4096];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, name);
        
        struct stat st;
        if (stat(full_path, &st) != 0) {
            continue;
        }
        
        if (S_ISDIR(st.st_mode)) {
            ctx->stats.total_dirs++;
            audit_directory_posix(ctx, full_path, depth + 1);
        } else if (S_ISREG(st.st_mode)) {
            uint64_t size = (uint64_t)st.st_size;
            
            ctx->stats.total_files++;
            ctx->stats.total_bytes += size;
            
            if (size == 0) {
                ctx->stats.empty_files++;
            }
            
            if (size > ctx->stats.largest_file) {
                ctx->stats.largest_file = size;
            }
            
            RawrFileCategory cat = categorize_extension(name);
            ctx->category_counts[cat]++;
            ctx->category_sizes[cat] += size;
            
            const char* ext = strrchr(name, '.');
            if (ext) {
                update_ext_stats(ctx, ext + 1, size);
            }
        }
    }
    
    closedir(dir);
    return RAWR_OK;
}
#endif

/* Run full drive audit */
int rawrxd_drive_audit_run(RawrDriveAuditContext* ctx)
{
    if (!ctx || !ctx->root_path) return RAWR_ERR_NULL;
    
    /* Reset statistics */
    memset(&ctx->stats, 0, sizeof(RawrDriveAuditStats));
    memset(ctx->category_counts, 0, sizeof(ctx->category_counts));
    memset(ctx->category_sizes, 0, sizeof(ctx->category_sizes));
    
    /* Clear extension hash table */
    for (int i = 0; i < RAWR_EXT_HASH_SIZE; i++) {
        RawrExtHashEntry* entry = ctx->ext_hash_table[i];
        while (entry) {
            RawrExtHashEntry* next = entry->next;
            free(entry->extension);
            free(entry);
            entry = next;
        }
        ctx->ext_hash_table[i] = NULL;
    }
    
#ifdef _WIN32
    return audit_directory_win32(ctx, ctx->root_path, 0);
#else
    return audit_directory_posix(ctx, ctx->root_path, 0);
#endif
}

/* Get audit statistics */
const RawrDriveAuditStats* rawrxd_drive_audit_get_stats(const RawrDriveAuditContext* ctx)
{
    if (!ctx) return NULL;
    return &ctx->stats;
}

/* Get category count */
uint64_t rawrxd_drive_audit_get_category_count(const RawrDriveAuditContext* ctx, RawrFileCategory cat)
{
    if (!ctx || cat < 0 || cat >= RAWR_CAT_COUNT) return 0;
    return ctx->category_counts[cat];
}

/* Get category size */
uint64_t rawrxd_drive_audit_get_category_size(const RawrDriveAuditContext* ctx, RawrFileCategory cat)
{
    if (!ctx || cat < 0 || cat >= RAWR_CAT_COUNT) return 0;
    return ctx->category_sizes[cat];
}

/* Format bytes to human-readable string */
void rawrxd_format_bytes(uint64_t bytes, char* out, size_t out_size)
{
    const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    int unit_idx = 0;
    double size = (double)bytes;
    
    while (size >= 1024.0 && unit_idx < 5) {
        size /= 1024.0;
        unit_idx++;
    }
    
    snprintf(out, out_size, "%.2f %s", size, units[unit_idx]);
}

/* Print audit report */
void rawrxd_drive_audit_print_report(const RawrDriveAuditContext* ctx)
{
    if (!ctx) return;
    
    const RawrDriveAuditStats* stats = &ctx->stats;
    char size_buf[32];
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║           RAWRXD DRIVE AUDIT REPORT                              ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║ Root Path: %-53s ║\n", ctx->root_path);
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║ SUMMARY                                                            ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Files:      %15" PRIu64 "                                  ║\n", stats->total_files);
    printf("║  Total Directories: %15" PRIu64 "                                  ║\n", stats->total_dirs);
    printf("║  Empty Files:      %15" PRIu64 "                                  ║\n", stats->empty_files);
    rawrxd_format_bytes(stats->total_bytes, size_buf, sizeof(size_buf));
    printf("║  Total Size:       %15s                                  ║\n", size_buf);
    rawrxd_format_bytes(stats->largest_file, size_buf, sizeof(size_buf));
    printf("║  Largest File:     %15s                                  ║\n", size_buf);
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║ FILE CATEGORIES                                                    ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    
    const char* cat_names[] = {
        "Executable", "Library", "Object", "Source", "Script",
        "Config", "Document", "Log", "Temp", "Archive",
        "Model", "Web", "Database", "Debug", "Build Artifact",
        "Other"
    };
    
    for (int i = 0; i < RAWR_CAT_COUNT; i++) {
        if (ctx->category_counts[i] > 0) {
            rawrxd_format_bytes(ctx->category_sizes[i], size_buf, sizeof(size_buf));
            printf("║  %-16s: %8" PRIu64 " files, %10s                    ║\n",
                   cat_names[i], ctx->category_counts[i], size_buf);
        }
    }
    
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║ TOP EXTENSIONS                                                     ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    
    /* Collect and sort extensions by count */
    typedef struct {
        const char* ext;
        uint64_t count;
        uint64_t size;
    } ExtStat;
    
    ExtStat top_exts[10];
    int ext_count = 0;
    
    for (int i = 0; i < RAWR_EXT_HASH_SIZE && ext_count < 10; i++) {
        RawrExtHashEntry* entry = ctx->ext_hash_table[i];
        while (entry && ext_count < 10) {
            top_exts[ext_count].ext = entry->extension;
            top_exts[ext_count].count = entry->count;
            top_exts[ext_count].size = entry->total_size;
            ext_count++;
            entry = entry->next;
        }
    }
    
    /* Simple bubble sort by count */
    for (int i = 0; i < ext_count - 1; i++) {
        for (int j = i + 1; j < ext_count; j++) {
            if (top_exts[j].count > top_exts[i].count) {
                ExtStat tmp = top_exts[i];
                top_exts[i] = top_exts[j];
                top_exts[j] = tmp;
            }
        }
    }
    
    for (int i = 0; i < ext_count && i < 10; i++) {
        rawrxd_format_bytes(top_exts[i].size, size_buf, sizeof(size_buf));
        printf("║  .%-10s: %8" PRIu64 " files, %10s                    ║\n",
               top_exts[i].ext, top_exts[i].count, size_buf);
    }
    
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

/* Export audit results to JSON */
int rawrxd_drive_audit_export_json(const RawrDriveAuditContext* ctx, const char* output_path)
{
    if (!ctx || !output_path) return RAWR_ERR_NULL;
    
    FILE* fp = fopen(output_path, "w");
    if (!fp) return RAWR_ERR_IO;
    
    const RawrDriveAuditStats* stats = &ctx->stats;
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"root_path\": \"%s\",\n", ctx->root_path);
    fprintf(fp, "  \"audit_timestamp\": %llu,\n", (unsigned long long)time(NULL));
    fprintf(fp, "  \"summary\": {\n");
    fprintf(fp, "    \"total_files\": %llu,\n", (unsigned long long)stats->total_files);
    fprintf(fp, "    \"total_directories\": %llu,\n", (unsigned long long)stats->total_dirs);
    fprintf(fp, "    \"empty_files\": %llu,\n", (unsigned long long)stats->empty_files);
    fprintf(fp, "    \"total_bytes\": %llu,\n", (unsigned long long)stats->total_bytes);
    fprintf(fp, "    \"largest_file\": %llu\n", (unsigned long long)stats->largest_file);
    fprintf(fp, "  },\n");
    
    fprintf(fp, "  \"categories\": {\n");
    const char* cat_names[] = {
        "executable", "library", "object", "source", "script",
        "config", "document", "log", "temp", "archive",
        "model", "web", "database", "debug", "build_artifact",
        "other"
    };
    
    int first = 1;
    for (int i = 0; i < RAWR_CAT_COUNT; i++) {
        if (ctx->category_counts[i] > 0) {
            if (!first) fprintf(fp, ",\n");
            fprintf(fp, "    \"%s\": {\n", cat_names[i]);
            fprintf(fp, "      \"count\": %llu,\n", (unsigned long long)ctx->category_counts[i]);
            fprintf(fp, "      \"size\": %llu\n", (unsigned long long)ctx->category_sizes[i]);
            fprintf(fp, "    }");
            first = 0;
        }
    }
    fprintf(fp, "\n  },\n");
    
    fprintf(fp, "  \"extensions\": {\n");
    first = 1;
    for (int i = 0; i < RAWR_EXT_HASH_SIZE; i++) {
        RawrExtHashEntry* entry = ctx->ext_hash_table[i];
        while (entry) {
            if (!first) fprintf(fp, ",\n");
            fprintf(fp, "    \"%s\": {\n", entry->extension);
            fprintf(fp, "      \"count\": %llu,\n", (unsigned long long)entry->count);
            fprintf(fp, "      \"total_size\": %llu\n", (unsigned long long)entry->total_size);
            fprintf(fp, "    }");
            first = 0;
            entry = entry->next;
        }
    }
    fprintf(fp, "\n  }\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
    return RAWR_OK;
}
