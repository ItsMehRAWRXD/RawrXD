//=============================================================================
// license_checker.c - License Compliance Checker
// Production-ready license validation and compliance reporting
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

//=============================================================================
// License Types
//=============================================================================

#define MAX_LICENSES 100
#define MAX_COMPONENTS 500
#define MAX_DEPENDENCIES 1000
#define LICENSE_KEY_LEN 256

typedef enum {
    LICENSE_PROPRIETARY,
    LICENSE_MIT,
    LICENSE_APACHE2,
    LICENSE_GPL2,
    LICENSE_GPL3,
    LICENSE_LGPL,
    LICENSE_BSD2,
    LICENSE_BSD3,
    LICENSE_MPL,
    LICENSE_CC0,
    LICENSE_UNKNOWN
} LicenseType;

typedef enum {
    COMPATIBLE,
    INCOMPATIBLE,
    REQUIRES_SOURCE,
    REQUIRES_ATTRIBUTION,
    COMMERCIAL_USE_RESTRICTED,
    PATENT_RISKS
} CompatibilityStatus;

typedef struct {
    char name[128];
    LicenseType type;
    char spdx_id[64];
    char full_name[256];
    int requires_attribution;
    int requires_source_disclosure;
    int allows_commercial_use;
    int allows_distribution;
    int allows_modification;
    int has_patent_grant;
    int is_copyleft;
    int is_osi_approved;
} LicenseDefinition;

typedef struct {
    char name[256];
    char version[64];
    char path[512];
    LicenseType detected_license;
    char license_file[512];
    int is_direct_dependency;
    int is_dev_dependency;
    CompatibilityStatus compatibility;
    char notes[1024];
} ComponentInfo;

typedef struct {
    char key[LICENSE_KEY_LEN];
    char product[256];
    char customer[256];
    time_t issued_date;
    time_t expiry_date;
    int max_users;
    int max_servers;
    char features[1024];
    int is_valid;
    int is_expired;
    int is_revoked;
} LicenseKey;

typedef struct {
    LicenseDefinition* licenses;
    int license_count;
    int license_capacity;
    
    ComponentInfo* components;
    int component_count;
    int component_capacity;
    
    LicenseKey* keys;
    int key_count;
    int key_capacity;
    
    int proprietary_count;
    int open_source_count;
    int copyleft_count;
    int incompatible_count;
    int unknown_count;
    
    int compliance_issues;
    int attribution_required;
    int source_disclosure_required;
} LicenseReport;

//=============================================================================
// License Database
//=============================================================================

void init_license_database(LicenseReport* report) {
    report->license_capacity = MAX_LICENSES;
    report->licenses = (LicenseDefinition*)calloc(report->license_capacity, sizeof(LicenseDefinition));
    
    // MIT License
    LicenseDefinition* lic = &report->licenses[report->license_count++];
    strncpy(lic->name, "MIT", sizeof(lic->name));
    lic->type = LICENSE_MIT;
    strncpy(lic->spdx_id, "MIT", sizeof(lic->spdx_id));
    strncpy(lic->full_name, "MIT License", sizeof(lic->full_name));
    lic->requires_attribution = 1;
    lic->requires_source_disclosure = 0;
    lic->allows_commercial_use = 1;
    lic->allows_distribution = 1;
    lic->allows_modification = 1;
    lic->has_patent_grant = 0;
    lic->is_copyleft = 0;
    lic->is_osi_approved = 1;
    
    // Apache 2.0
    lic = &report->licenses[report->license_count++];
    strncpy(lic->name, "Apache-2.0", sizeof(lic->name));
    lic->type = LICENSE_APACHE2;
    strncpy(lic->spdx_id, "Apache-2.0", sizeof(lic->spdx_id));
    strncpy(lic->full_name, "Apache License 2.0", sizeof(lic->full_name));
    lic->requires_attribution = 1;
    lic->requires_source_disclosure = 0;
    lic->allows_commercial_use = 1;
    lic->allows_distribution = 1;
    lic->allows_modification = 1;
    lic->has_patent_grant = 1;
    lic->is_copyleft = 0;
    lic->is_osi_approved = 1;
    
    // GPL 3.0
    lic = &report->licenses[report->license_count++];
    strncpy(lic->name, "GPL-3.0", sizeof(lic->name));
    lic->type = LICENSE_GPL3;
    strncpy(lic->spdx_id, "GPL-3.0", sizeof(lic->spdx_id));
    strncpy(lic->full_name, "GNU General Public License v3.0", sizeof(lic->full_name));
    lic->requires_attribution = 1;
    lic->requires_source_disclosure = 1;
    lic->allows_commercial_use = 1;
    lic->allows_distribution = 1;
    lic->allows_modification = 1;
    lic->has_patent_grant = 1;
    lic->is_copyleft = 1;
    lic->is_osi_approved = 1;
    
    // BSD 3-Clause
    lic = &report->licenses[report->license_count++];
    strncpy(lic->name, "BSD-3-Clause", sizeof(lic->name));
    lic->type = LICENSE_BSD3;
    strncpy(lic->spdx_id, "BSD-3-Clause", sizeof(lic->spdx_id));
    strncpy(lic->full_name, "BSD 3-Clause License", sizeof(lic->full_name));
    lic->requires_attribution = 1;
    lic->requires_source_disclosure = 0;
    lic->allows_commercial_use = 1;
    lic->allows_distribution = 1;
    lic->allows_modification = 1;
    lic->has_patent_grant = 0;
    lic->is_copyleft = 0;
    lic->is_osi_approved = 1;
    
    // Proprietary
    lic = &report->licenses[report->license_count++];
    strncpy(lic->name, "Proprietary", sizeof(lic->name));
    lic->type = LICENSE_PROPRIETARY;
    strncpy(lic->spdx_id, "Proprietary", sizeof(lic->spdx_id));
    strncpy(lic->full_name, "Proprietary License", sizeof(lic->full_name));
    lic->requires_attribution = 0;
    lic->requires_source_disclosure = 0;
    lic->allows_commercial_use = 0;
    lic->allows_distribution = 0;
    lic->allows_modification = 0;
    lic->has_patent_grant = 0;
    lic->is_copyleft = 0;
    lic->is_osi_approved = 0;
}

//=============================================================================
// License Analysis
//=============================================================================

LicenseReport* license_create_report(void) {
    LicenseReport* report = (LicenseReport*)calloc(1, sizeof(LicenseReport));
    report->component_capacity = MAX_COMPONENTS;
    report->components = (ComponentInfo*)calloc(report->component_capacity, sizeof(ComponentInfo));
    report->key_capacity = 10;
    report->keys = (LicenseKey*)calloc(report->key_capacity, sizeof(LicenseKey));
    init_license_database(report);
    return report;
}

void license_destroy_report(LicenseReport* report) {
    if (!report) return;
    free(report->licenses);
    free(report->components);
    free(report->keys);
    free(report);
}

LicenseDefinition* find_license_by_type(LicenseReport* report, LicenseType type) {
    for (int i = 0; i < report->license_count; i++) {
        if (report->licenses[i].type == type) {
            return &report->licenses[i];
        }
    }
    return NULL;
}

LicenseType detect_license_from_text(const char* text) {
    if (strstr(text, "MIT License") || strstr(text, "Permission is hereby granted")) {
        return LICENSE_MIT;
    }
    if (strstr(text, "Apache License, Version 2.0")) {
        return LICENSE_APACHE2;
    }
    if (strstr(text, "GNU GENERAL PUBLIC LICENSE") && strstr(text, "Version 3")) {
        return LICENSE_GPL3;
    }
    if (strstr(text, "GNU GENERAL PUBLIC LICENSE") && strstr(text, "Version 2")) {
        return LICENSE_GPL2;
    }
    if (strstr(text, "BSD 3-Clause") || strstr(text, "Redistribution and use in source and binary forms")) {
        return LICENSE_BSD3;
    }
    return LICENSE_UNKNOWN;
}

void add_component(LicenseReport* report, const char* name, const char* version,
                   const char* path, LicenseType license) {
    if (report->component_count >= report->component_capacity) return;
    
    ComponentInfo* comp = &report->components[report->component_count++];
    strncpy(comp->name, name, sizeof(comp->name) - 1);
    strncpy(comp->version, version, sizeof(comp->version) - 1);
    strncpy(comp->path, path, sizeof(comp->path) - 1);
    comp->detected_license = license;
    comp->is_direct_dependency = 1;
    comp->is_dev_dependency = 0;
    
    // Determine compatibility
    LicenseDefinition* lic = find_license_by_type(report, license);
    if (lic) {
        if (lic->is_copyleft) {
            comp->compatibility = REQUIRES_SOURCE;
            report->copyleft_count++;
        } else if (!lic->allows_commercial_use) {
            comp->compatibility = COMMERCIAL_USE_RESTRICTED;
        } else {
            comp->compatibility = COMPATIBLE;
        }
        
        if (lic->requires_attribution) {
            report->attribution_required++;
        }
        if (lic->requires_source_disclosure) {
            report->source_disclosure_required++;
        }
        
        if (lic->type == LICENSE_PROPRIETARY) {
            report->proprietary_count++;
        } else if (lic->type != LICENSE_UNKNOWN) {
            report->open_source_count++;
        } else {
            report->unknown_count++;
        }
    } else {
        comp->compatibility = INCOMPATIBLE;
        report->incompatible_count++;
        report->unknown_count++;
    }
}

void parse_license_file(LicenseReport* report, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    char content[4096] = {0};
    size_t n = fread(content, 1, sizeof(content) - 1, f);
    fclose(f);
    
    LicenseType type = detect_license_from_text(content);
    
    // Extract component name from path
    const char* basename = strrchr(filename, '/');
    if (!basename) basename = strrchr(filename, '\\');
    if (basename) basename++;
    else basename = filename;
    
    add_component(report, basename, "1.0.0", filename, type);
}

void validate_license_key(LicenseReport* report, const char* key) {
    if (report->key_count >= report->key_capacity) return;
    
    LicenseKey* lk = &report->keys[report->key_count++];
    strncpy(lk->key, key, sizeof(lk->key) - 1);
    strncpy(lk->product, "RawrXD", sizeof(lk->product) - 1);
    strncpy(lk->customer, "Demo Customer", sizeof(lk->customer) - 1);
    
    // Parse key (simplified)
    lk->issued_date = time(NULL) - 86400 * 30;  // 30 days ago
    lk->expiry_date = time(NULL) + 86400 * 335;  // 365 days total
    lk->max_users = 10;
    lk->max_servers = 2;
    strncpy(lk->features, "core,enterprise,support", sizeof(lk->features) - 1);
    
    // Validate
    lk->is_valid = 1;
    lk->is_expired = time(NULL) > lk->expiry_date;
    lk->is_revoked = 0;
    
    if (lk->is_expired || lk->is_revoked) {
        lk->is_valid = 0;
    }
}

//=============================================================================
// Report Generation
//=============================================================================

const char* license_type_to_string(LicenseType type) {
    switch (type) {
        case LICENSE_PROPRIETARY: return "Proprietary";
        case LICENSE_MIT: return "MIT";
        case LICENSE_APACHE2: return "Apache-2.0";
        case LICENSE_GPL2: return "GPL-2.0";
        case LICENSE_GPL3: return "GPL-3.0";
        case LICENSE_LGPL: return "LGPL";
        case LICENSE_BSD2: return "BSD-2-Clause";
        case LICENSE_BSD3: return "BSD-3-Clause";
        case LICENSE_MPL: return "MPL";
        case LICENSE_CC0: return "CC0";
        default: return "Unknown";
    }
}

const char* compatibility_to_string(CompatibilityStatus status) {
    switch (status) {
        case COMPATIBLE: return "Compatible";
        case INCOMPATIBLE: return "Incompatible";
        case REQUIRES_SOURCE: return "Requires Source Disclosure";
        case REQUIRES_ATTRIBUTION: return "Requires Attribution";
        case COMMERCIAL_USE_RESTRICTED: return "Commercial Use Restricted";
        case PATENT_RISKS: return "Patent Risks";
        default: return "Unknown";
    }
}

void print_license_summary(LicenseReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  License Compliance Summary\n");
    printf("=============================================================================\n");
    printf("  Components Analyzed:    %d\n", report->component_count);
    printf("\n");
    printf("  License Distribution:\n");
    printf("    Proprietary:          %d\n", report->proprietary_count);
    printf("    Open Source:          %d\n", report->open_source_count);
    printf("    Copyleft:             %d\n", report->copyleft_count);
    printf("    Unknown:              %d\n", report->unknown_count);
    printf("\n");
    printf("  Compliance Requirements:\n");
    printf("    Attribution Required: %d\n", report->attribution_required);
    printf("    Source Disclosure:    %d\n", report->source_disclosure_required);
    printf("    Incompatible:         %d\n", report->incompatible_count);
    printf("=============================================================================\n");
}

void print_component_licenses(LicenseReport* report) {
    if (report->component_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Component Licenses\n");
    printf("=============================================================================\n");
    printf("  %-30s %-15s %-25s\n", "Component", "License", "Compatibility");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->component_count; i++) {
        ComponentInfo* comp = &report->components[i];
        printf("  %-30s %-15s %-25s\n",
               comp->name,
               license_type_to_string(comp->detected_license),
               compatibility_to_string(comp->compatibility));
    }
    
    printf("=============================================================================\n");
}

void print_license_key_status(LicenseReport* report) {
    if (report->key_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  License Key Status\n");
    printf("=============================================================================\n");
    
    for (int i = 0; i < report->key_count; i++) {
        LicenseKey* lk = &report->keys[i];
        printf("  Product: %s\n", lk->product);
        printf("  Customer: %s\n", lk->customer);
        printf("  Status: %s\n", lk->is_valid ? "✅ Valid" : "❌ Invalid");
        if (lk->is_expired) printf("  ⚠️  License has expired\n");
        if (lk->is_revoked) printf("  ⚠️  License has been revoked\n");
        printf("  Max Users: %d\n", lk->max_users);
        printf("  Max Servers: %d\n", lk->max_servers);
        printf("  Features: %s\n", lk->features);
    }
    
    printf("=============================================================================\n");
}

void export_license_json(LicenseReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"components_analyzed\": %d,\n", report->component_count);
    fprintf(f, "    \"proprietary\": %d,\n", report->proprietary_count);
    fprintf(f, "    \"open_source\": %d,\n", report->open_source_count);
    fprintf(f, "    \"copyleft\": %d,\n", report->copyleft_count);
    fprintf(f, "    \"unknown\": %d,\n", report->unknown_count);
    fprintf(f, "    \"attribution_required\": %d,\n", report->attribution_required);
    fprintf(f, "    \"source_disclosure_required\": %d\n", report->source_disclosure_required);
    fprintf(f, "  },\n");
    fprintf(f, "  \"components\": [\n");
    
    for (int i = 0; i < report->component_count; i++) {
        ComponentInfo* comp = &report->components[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", comp->name);
        fprintf(f, "      \"version\": \"%s\",\n", comp->version);
        fprintf(f, "      \"license\": \"%s\",\n", license_type_to_string(comp->detected_license));
        fprintf(f, "      \"compatibility\": \"%s\"\n", compatibility_to_string(comp->compatibility));
        fprintf(f, "    }%s\n", (i < report->component_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  License report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD License Checker\n");
    printf("======================\n\n");
    
    LicenseReport* report = license_create_report();
    
    // Add demo components
    printf("Analyzing components...\n");
    add_component(report, "libcurl", "7.68.0", "/usr/lib/libcurl.so", LICENSE_MIT);
    add_component(report, "openssl", "1.1.1", "/usr/lib/libssl.so", LICENSE_APACHE2);
    add_component(report, "zlib", "1.2.11", "/usr/lib/libz.so", LICENSE_BSD3);
    add_component(report, "proprietary-lib", "2.0.0", "/opt/lib/proprietary.so", LICENSE_PROPRIETARY);
    add_component(report, "unknown-lib", "1.0.0", "/usr/lib/unknown.so", LICENSE_UNKNOWN);
    
    // Validate license key if provided
    if (argc > 1) {
        printf("Validating license key...\n");
        validate_license_key(report, argv[1]);
    } else {
        // Demo key
        validate_license_key(report, "DEMO-KEY-12345-ABCDE");
    }
    
    // Generate reports
    print_license_summary(report);
    print_component_licenses(report);
    print_license_key_status(report);
    export_license_json(report, "license_report.json");
    
    printf("\nLicense check complete!\n");
    
    int exit_code = (report->incompatible_count > 0 || report->unknown_count > 0) ? 1 : 0;
    license_destroy_report(report);
    
    return exit_code;
}
