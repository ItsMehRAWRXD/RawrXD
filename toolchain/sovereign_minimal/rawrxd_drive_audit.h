/* rawrxd_drive_audit.h — Comprehensive D drive audit API (Tier G) */

#ifndef RAWRXD_DRIVE_AUDIT_H
#define RAWRXD_DRIVE_AUDIT_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define RAWR_OK          0
#define RAWR_ERR_NULL   -1
#define RAWR_ERR_IO     -2
#define RAWR_ERR_RANGE  -3
#define RAWR_ERR_MEM    -4

/* File categories for classification */
typedef enum {
    RAWR_CAT_EXECUTABLE = 0,
    RAWR_CAT_LIBRARY,
    RAWR_CAT_OBJECT,
    RAWR_CAT_SOURCE,
    RAWR_CAT_SCRIPT,
    RAWR_CAT_CONFIG,
    RAWR_CAT_DOCUMENT,
    RAWR_CAT_LOG,
    RAWR_CAT_TEMP,
    RAWR_CAT_ARCHIVE,
    RAWR_CAT_MODEL,
    RAWR_CAT_WEB,
    RAWR_CAT_DATABASE,
    RAWR_CAT_DEBUG,
    RAWR_CAT_BUILD_ARTIFACT,
    RAWR_CAT_OTHER,
    RAWR_CAT_COUNT
} RawrFileCategory;

/* Audit statistics */
typedef struct {
    uint64_t total_files;
    uint64_t total_dirs;
    uint64_t total_bytes;
    uint64_t empty_files;
    uint64_t largest_file;
    time_t   start_time;
    time_t   end_time;
} RawrDriveAuditStats;

/* Extension hash table entry */
#define RAWR_EXT_HASH_SIZE 256

typedef struct RawrExtHashEntry {
    char* extension;
    uint64_t count;
    uint64_t total_size;
    struct RawrExtHashEntry* next;
} RawrExtHashEntry;

/* Audit context */
typedef struct {
    char* root_path;
    int max_depth;
    RawrDriveAuditStats stats;
    uint64_t category_counts[RAWR_CAT_COUNT];
    uint64_t category_sizes[RAWR_CAT_COUNT];
    RawrExtHashEntry* ext_hash_table[RAWR_EXT_HASH_SIZE];
} RawrDriveAuditContext;

/* === API Functions === */

/* Create audit context */
RawrDriveAuditContext* rawrxd_drive_audit_create(const char* root_path);

/* Destroy audit context */
void rawrxd_drive_audit_destroy(RawrDriveAuditContext* ctx);

/* Run full drive audit */
int rawrxd_drive_audit_run(RawrDriveAuditContext* ctx);

/* Get audit statistics */
const RawrDriveAuditStats* rawrxd_drive_audit_get_stats(const RawrDriveAuditContext* ctx);

/* Get category count */
uint64_t rawrxd_drive_audit_get_category_count(const RawrDriveAuditContext* ctx, RawrFileCategory cat);

/* Get category size */
uint64_t rawrxd_drive_audit_get_category_size(const RawrDriveAuditContext* ctx, RawrFileCategory cat);

/* Format bytes to human-readable string */
void rawrxd_format_bytes(uint64_t bytes, char* out, size_t out_size);

/* Print audit report to stdout */
void rawrxd_drive_audit_print_report(const RawrDriveAuditContext* ctx);

/* Export audit results to JSON */
int rawrxd_drive_audit_export_json(const RawrDriveAuditContext* ctx, const char* output_path);

#ifdef __cplusplus
}
#endif

#endif /* RAWRXD_DRIVE_AUDIT_H */
