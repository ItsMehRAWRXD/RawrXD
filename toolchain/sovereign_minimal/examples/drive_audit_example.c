/* drive_audit_example.c — Example usage of rawrxd_drive_audit */

#include "rawrxd/rawrxd_drive_audit.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    const char* target_path = (argc > 1) ? argv[1] : "D:\\";
    const char* output_json = (argc > 2) ? argv[2] : "d_drive_audit.json";
    
    printf("RawrXD Drive Audit Tool\n");
    printf("========================\n\n");
    printf("Target: %s\n", target_path);
    printf("Output: %s\n\n", output_json);
    
    /* Create audit context */
    RawrDriveAuditContext* ctx = rawrxd_drive_audit_create(target_path);
    if (!ctx) {
        fprintf(stderr, "Failed to create audit context\n");
        return 1;
    }
    
    printf("Running audit...\n");
    
    /* Run the audit */
    int result = rawrxd_drive_audit_run(ctx);
    if (result != RAWR_OK) {
        fprintf(stderr, "Audit failed with error code: %d\n", result);
        rawrxd_drive_audit_destroy(ctx);
        return 1;
    }
    
    /* Print report */
    rawrxd_drive_audit_print_report(ctx);
    
    /* Export to JSON */
    printf("Exporting to JSON...\n");
    result = rawrxd_drive_audit_export_json(ctx, output_json);
    if (result != RAWR_OK) {
        fprintf(stderr, "Failed to export JSON: %d\n", result);
    } else {
        printf("JSON export complete: %s\n", output_json);
    }
    
    /* Cleanup */
    rawrxd_drive_audit_destroy(ctx);
    
    printf("\nAudit complete.\n");
    return 0;
}
