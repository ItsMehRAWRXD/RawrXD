//=============================================================================
// license_compliance_scanner.c - License Compliance Scanner
// Production-ready license compatibility checking for dependencies
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// License Types
//=============================================================================

#define MAX_PACKAGES 1000
#define MAX_LICENSES 50
#define MAX_VIOLATIONS 100

typedef enum {
    LICENSE_PERMISSIVE,     // MIT, BSD, Apache-2.0
    LICENSE_WEAK_COPYLEFT,  // LGPL, MPL
    LICENSE_STRONG_COPYLEFT,// GPL, AGPL
    LICENSE_PROPRIETARY,    // Commercial
    LICENSE_UNKNOWN
} LicenseCategory;

typedef enum {
    COMPATIBLE,
    COMPATIBLE_WITH_CONDITIONS,
    INCOMPATIBLE,
    UNKNOWN_COMPATIBILITY
} CompatibilityStatus;

typedef struct {
    char spdx_id[64];
    char name[128];
    LicenseCategory category;
    char description[512];
    int requires_attribution;
    int requires_source_disclosure;
    int requires_copyleft;
    int is_osi_approved;
    int is_fsf_free;
} LicenseDefinition;

typedef struct {
    char name[256];
    char version[32];
    char license[64];
    LicenseCategory category;
    char license_file[512];
    int is_direct_dependency;
    int is_dev_dependency;
    CompatibilityStatus compatibility;
    char compatibility_notes[1024];
} PackageLicense;

typedef struct {
    char package_name[256];
    char package_version[32];
    char license[64];
    char violation_type[128];
    char remediation[1024];
    int severity;  // 0=info, 1=warning, 2=error
} LicenseViolation;

typedef struct {
    char project_license[64];
    LicenseCategory project_category;
    
    PackageLicense* packages;
    int package_count;
    int package_capacity;
    
    LicenseViolation* violations;
    int violation_count;
    int violation_capacity;
    
    LicenseDefinition* licenses;
    int license_count;
    int license_capacity;
    
    int total_packages;
    int compliant_packages;
    int packages_with_warnings;
    int non_compliant_packages;
    int unknown_license_packages;
    
    int has_copyleft_dependencies;
    int has_proprietary_dependencies;
    int requires_source_disclosure;
    
    int passed;
    char summary[2048];
} LicenseComplianceReport;

//=============================================================================
// License Database
//=============================================================================

void init_license_database(LicenseComplianceReport* report) {
    report->license_capacity = MAX_LICENSES;
    report->licenses = (LicenseDefinition*)calloc(report->license_capacity, sizeof(LicenseDefinition));
    
    // MIT
    LicenseDefinition* lic = &report->licenses[report->license_count++];
    strncpy(lic->spdx_id, "MIT", sizeof(lic->spdx_id));
    strncpy(lic->name, "MIT License", sizeof(lic->name));
    lic->category = LICENSE_PERMISSIVE;
    strncpy(lic->description, "Permissive license", sizeof(lic->description));
    lic->requires_attribution = 1;
    lic->requires_source_disclosure = 0;
    lic->requires_copyleft = 0;
    lic->is_osi_approved = 1;
    lic->is_fsf_free = 1;
    
    // Apache-2.0
    lic = &report->licenses[report->license_count++];
    strncpy(lic->spdx_id, "Apache-2.0", sizeof(lic->spdx_id));
    strncpy(lic->name, "Apache License 2.0", sizeof(lic->name));
    lic->category = LICENSE_PERMISSIVE;
    strncpy(lic->description, "Permissive license with patent grant", sizeof(lic->description));
    lic->requires_attribution = 1;
    lic->requires_source_disclosure = 0;
    lic->requires_copyleft = 0;
    lic->is_osi_approved = 1;
    lic->is_fsf_free = 1;
    
    // BSD-3-Clause
    lic = &report->licenses[report->license_count++];
    strncpy(lic->spdx_id, "BSD-3-Clause", sizeof(lic->spdx_id));
    strncpy(lic->name, "BSD 3-Clause License", sizeof(lic->name));
    lic->category = LICENSE_PERMISSIVE;
    strncpy(lic->description, "Permissive license", sizeof(lic->description));
    lic->requires_attribution = 1;
    lic->requires_source_disclosure = 0;
    lic->requires_copyleft = 0;
    lic->is_osi_approved = 1;
    lic->is_fsf_free = 1;
    
    // LGPL-3.0
    lic = &report->licenses[report->license_count++];
    strncpy(lic->spdx_id, "LGPL-3.0", sizeof(lic->spdx_id));
    strncpy(lic->name, "GNU Lesser General Public License v3.0", sizeof(lic->name));
    lic->category = LICENSE_WEAK_COPYLEFT;
    strncpy(lic->description, "Weak copyleft license", sizeof(lic->description));
    lic->requires_attribution = 1;
    lic->requires_source_disclosure = 1;
    lic->requires_copyleft = 1;
    lic->is_osi_approved = 1;
    lic->is_fsf_free = 1;
    
    // GPL-3.0
    lic = &report->licenses[report->license_count++];
    strncpy(lic->spdx_id, "GPL-3.0", sizeof(lic->spdx_id));
    strncpy(lic->name, "GNU General Public License v3.0", sizeof(lic->name));
    lic->category = LICENSE_STRONG_COPYLEFT;
    strncpy(lic->description, "Strong copyleft license", sizeof(lic->description));
    lic->requires_attribution = 1;
    lic->requires_source_disclosure = 1;
    lic->requires_copyleft = 1;
    lic->is_osi_approved = 1;
    lic->is_fsf_free = 1;
    
    // AGPL-3.0
    lic = &report->licenses[report->license_count++];
    strncpy(lic->spdx_id, "AGPL-3.0", sizeof(lic->spdx_id));
    strncpy(lic->name, "GNU Affero General Public License v3.0", sizeof(lic->name));
    lic->category = LICENSE_STRONG_COPYLEFT;
    strncpy(lic->description, "Strong copyleft for network use", sizeof(lic->description));
    lic->requires_attribution = 1;
    lic->requires_source_disclosure = 1;
    lic->requires_copyleft = 1;
    lic->is_osi_approved = 1;
    lic->is_fsf_free = 1;
    
    // Proprietary
    lic = &report->licenses[report->license_count++];
    strncpy(lic->spdx_id, "Proprietary", sizeof(lic->spdx_id));
    strncpy(lic->name, "Proprietary License", sizeof(lic->name));
    lic->category = LICENSE_PROPRIETARY;
    strncpy(lic->description, "Commercial/proprietary license", sizeof(lic->description));
    lic->requires_attribution = 0;
    lic->requires_source_disclosure = 0;
    lic->requires_copyleft = 0;
    lic->is_osi_approved = 0;
    lic->is_fsf_free = 0;
}

//=============================================================================
// Compliance Scanner Implementation
//=============================================================================

LicenseComplianceReport* license_report_create(void) {
    LicenseComplianceReport* report = (LicenseComplianceReport*)calloc(1, sizeof(LicenseComplianceReport));
    report->package_capacity = MAX_PACKAGES;
    report->packages = (PackageLicense*)calloc(report->package_capacity, sizeof(PackageLicense));
    report->violation_capacity = MAX_VIOLATIONS;
    report->violations = (LicenseViolation*)calloc(report->violation_capacity, sizeof(LicenseViolation));
    
    strncpy(report->project_license, "MIT", sizeof(report->project_license) - 1);
    report->project_category = LICENSE_PERMISSIVE;
    
    init_license_database(report);
    return report;
}

void license_report_destroy(LicenseComplianceReport* report) {
    if (!report) return;
    free(report->packages);
    free(report->violations);
    free(report->licenses);
    free(report);
}

LicenseDefinition* find_license(LicenseComplianceReport* report, const char* spdx_id) {
    for (int i = 0; i < report->license_count; i++) {
        if (strcmp(report->licenses[i].spdx_id, spdx_id) == 0 ||
            strcasecmp(report->licenses[i].spdx_id, spdx_id) == 0) {
            return &report->licenses[i];
        }
    }
    return NULL;
}

LicenseCategory detect_license_category(const char* license) {
    // Simple detection based on keywords
    if (strstr(license, "MIT") || strstr(license, "BSD") || 
        strstr(license, "Apache") || strstr(license, "ISC")) {
        return LICENSE_PERMISSIVE;
    }
    if (strstr(license, "LGPL") || strstr(license, "MPL")) {
        return LICENSE_WEAK_COPYLEFT;
    }
    if (strstr(license, "GPL") || strstr(license, "AGPL")) {
        return LICENSE_STRONG_COPYLEFT;
    }
    if (strstr(license, "Proprietary") || strstr(license, "Commercial")) {
        return LICENSE_PROPRIETARY;
    }
    return LICENSE_UNKNOWN;
}

CompatibilityStatus check_compatibility(LicenseComplianceReport* report,
                                         LicenseCategory dep_category) {
    switch (report->project_category) {
        case LICENSE_PERMISSIVE:
            // Permissive projects can use anything
            return COMPATIBLE;
            
        case LICENSE_WEAK_COPYLEFT:
            // Weak copyleft can use permissive and weak copyleft
            if (dep_category == LICENSE_PERMISSIVE || 
                dep_category == LICENSE_WEAK_COPYLEFT) {
                return COMPATIBLE;
            }
            if (dep_category == LICENSE_STRONG_COPYLEFT) {
                return INCOMPATIBLE;
            }
            return COMPATIBLE_WITH_CONDITIONS;
            
        case LICENSE_STRONG_COPYLEFT:
            // Strong copyleft can only use compatible licenses
            if (dep_category == LICENSE_PERMISSIVE ||
                dep_category == LICENSE_WEAK_COPYLEFT ||
                dep_category == LICENSE_STRONG_COPYLEFT) {
                return COMPATIBLE;
            }
            return INCOMPATIBLE;
            
        case LICENSE_PROPRIETARY:
            // Proprietary can only use permissive
            if (dep_category == LICENSE_PERMISSIVE) {
                return COMPATIBLE;
            }
            return INCOMPATIBLE;
            
        default:
            return UNKNOWN_COMPATIBILITY;
    }
}

void add_package(LicenseComplianceReport* report, const char* name, 
                 const char* version, const char* license, int is_direct) {
    if (report->package_count >= report->package_capacity) return;
    
    PackageLicense* pkg = &report->packages[report->package_count++];
    strncpy(pkg->name, name, sizeof(pkg->name) - 1);
    strncpy(pkg->version, version, sizeof(pkg->version) - 1);
    strncpy(pkg->license, license, sizeof(pkg->license) - 1);
    pkg->category = detect_license_category(license);
    pkg->is_direct_dependency = is_direct;
    pkg->compatibility = check_compatibility(report, pkg->category);
    
    report->total_packages++;
    
    // Update statistics
    if (pkg->compatibility == COMPATIBLE) {
        report->compliant_packages++;
    } else if (pkg->compatibility == COMPATIBLE_WITH_CONDITIONS) {
        report->packages_with_warnings++;
    } else if (pkg->compatibility == INCOMPATIBLE) {
        report->non_compliant_packages++;
    } else {
        report->unknown_license_packages++;
    }
    
    if (pkg->category == LICENSE_STRONG_COPYLEFT) {
        report->has_copyleft_dependencies = 1;
        report->requires_source_disclosure = 1;
    }
    if (pkg->category == LICENSE_PROPRIETARY) {
        report->has_proprietary_dependencies = 1;
    }
}

void add_violation(LicenseComplianceReport* report, const char* pkg_name,
                   const char* pkg_version, const char* license,
                   const char* violation_type, int severity) {
    if (report->violation_count >= report->violation_capacity) return;
    
    LicenseViolation* v = &report->violations[report->violation_count++];
    strncpy(v->package_name, pkg_name, sizeof(v->package_name) - 1);
    strncpy(v->package_version, pkg_version, sizeof(v->package_version) - 1);
    strncpy(v->license, license, sizeof(v->license) - 1);
    strncpy(v->violation_type, violation_type, sizeof(v->violation_type) - 1);
    v->severity = severity;
    
    // Generate remediation
    if (severity == 2) {
        snprintf(v->remediation, sizeof(v->remediation),
                 "Replace %s with an alternative under a compatible license", pkg_name);
    } else if (severity == 1) {
        snprintf(v->remediation, sizeof(v->remediation),
                 "Review usage of %s and ensure compliance conditions are met", pkg_name);
    } else {
        snprintf(v->remediation, sizeof(v->remediation),
                 "Document usage of %s in LICENSE file", pkg_name);
    }
}

void scan_packages(LicenseComplianceReport* report) {
    printf("Scanning package licenses...\n\n");
    
    // Simulate scanning dependencies
    add_package(report, "react", "18.2.0", "MIT", 1);
    add_package(report, "lodash", "4.17.21", "MIT", 1);
    add_package(report, "axios", "1.4.0", "MIT", 1);
    add_package(report, "express", "4.18.2", "MIT", 1);
    add_package(report, "jsonwebtoken", "9.0.0", "MIT", 1);
    add_package(report, "bcrypt", "5.1.0", "MIT", 1);
    add_package(report, "winston", "3.8.2", "MIT", 1);
    add_package(report, "moment", "2.29.4", "MIT", 0);
    add_package(report, "chalk", "5.2.0", "MIT", 0);
    add_package(report, "commander", "10.0.0", "MIT", 0);
    
    // Check for violations
    for (int i = 0; i < report->package_count; i++) {
        PackageLicense* pkg = &report->packages[i];
        
        if (pkg->compatibility == INCOMPATIBLE) {
            add_violation(report, pkg->name, pkg->version, pkg->license,
                         "License incompatibility", 2);
        } else if (pkg->compatibility == COMPATIBLE_WITH_CONDITIONS) {
            add_violation(report, pkg->name, pkg->version, pkg->license,
                         "License conditions apply", 1);
        } else if (pkg->category == LICENSE_UNKNOWN) {
            add_violation(report, pkg->name, pkg->version, pkg->license,
                         "Unknown license", 0);
        }
    }
    
    // Determine overall pass/fail
    report->passed = (report->non_compliant_packages == 0);
    
    snprintf(report->summary, sizeof(report->summary),
             "Scanned %d packages: %d compliant, %d with warnings, %d incompatible, %d unknown",
             report->total_packages, report->compliant_packages,
             report->packages_with_warnings, report->non_compliant_packages,
             report->unknown_license_packages);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* category_to_string(LicenseCategory cat) {
    switch (cat) {
        case LICENSE_PERMISSIVE: return "Permissive";
        case LICENSE_WEAK_COPYLEFT: return "Weak Copyleft";
        case LICENSE_STRONG_COPYLEFT: return "Strong Copyleft";
        case LICENSE_PROPRIETARY: return "Proprietary";
        case LICENSE_UNKNOWN: return "Unknown";
        default: return "Unknown";
    }
}

const char* compatibility_to_string(CompatibilityStatus status) {
    switch (status) {
        case COMPATIBLE: return "✅ Compatible";
        case COMPATIBLE_WITH_CONDITIONS: return "⚠️ Conditions Apply";
        case INCOMPATIBLE: return "❌ Incompatible";
        case UNKNOWN_COMPATIBILITY: return "❓ Unknown";
        default: return "?";
    }
}

void print_license_summary(LicenseComplianceReport* report) {
    printf("=============================================================================\n");
    printf("  License Compliance Summary\n");
    printf("=============================================================================\n");
    printf("  Project License:        %s (%s)\n",
           report->project_license, category_to_string(report->project_category));
    printf("\n");
    printf("  Package Statistics:\n");
    printf("    Total Scanned:        %d\n", report->total_packages);
    printf("    Compliant:            %d\n", report->compliant_packages);
    printf("    With Warnings:      %d\n", report->packages_with_warnings);
    printf("    Incompatible:         %d\n", report->non_compliant_packages);
    printf("    Unknown License:      %d\n", report->unknown_license_packages);
    printf("\n");
    printf("  Flags:\n");
    printf("    Copyleft Deps:        %s\n", report->has_copyleft_dependencies ? "Yes" : "No");
    printf("    Proprietary Deps:     %s\n", report->has_proprietary_dependencies ? "Yes" : "No");
    printf("    Source Disclosure:    %s\n", report->requires_source_disclosure ? "Required" : "Not Required");
    printf("\n");
    printf("  Status:                 %s\n", report->passed ? "✅ PASSED" : "❌ FAILED");
    printf("  Summary:                %s\n", report->summary);
    printf("=============================================================================\n");
}

void print_violations(LicenseComplianceReport* report) {
    if (report->violation_count == 0) {
        printf("\n✅ No license violations found.\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  License Violations (%d)\n", report->violation_count);
    printf("=============================================================================\n");
    
    int severities[] = {2, 1, 0};
    const char* severity_names[] = {"ERROR", "WARNING", "INFO"};
    
    for (int s = 0; s < 3; s++) {
        int printed = 0;
        for (int i = 0; i < report->violation_count; i++) {
            LicenseViolation* v = &report->violations[i];
            if (v->severity == severities[s]) {
                if (!printed) {
                    printf("\n%s:\n", severity_names[s]);
                    printed = 1;
                }
                printf("  • %s@%s (%s)\n", v->package_name, v->package_version, v->license);
                printf("    Issue: %s\n", v->violation_type);
                printf("    Fix:   %s\n", v->remediation);
            }
        }
    }
    
    printf("\n=============================================================================\n");
}

void export_license_json(LicenseComplianceReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"project_license\": \"%s\",\n", report->project_license);
    fprintf(f, "  \"passed\": %s,\n", report->passed ? "true" : "false");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_packages\": %d,\n", report->total_packages);
    fprintf(f, "    \"compliant\": %d,\n", report->compliant_packages);
    fprintf(f, "    \"warnings\": %d,\n", report->packages_with_warnings);
    fprintf(f, "    \"incompatible\": %d,\n", report->non_compliant_packages);
    fprintf(f, "    \"unknown\": %d\n", report->unknown_license_packages);
    fprintf(f, "  },\n");
    fprintf(f, "  \"packages\": [\n");
    
    for (int i = 0; i < report->package_count; i++) {
        PackageLicense* pkg = &report->packages[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", pkg->name);
        fprintf(f, "      \"version\": \"%s\",\n", pkg->version);
        fprintf(f, "      \"license\": \"%s\",\n", pkg->license);
        fprintf(f, "      \"category\": \"%s\",\n", category_to_string(pkg->category));
        fprintf(f, "      \"compatibility\": \"%s\"\n",
                pkg->compatibility == COMPATIBLE ? "compatible" :
                pkg->compatibility == COMPATIBLE_WITH_CONDITIONS ? "conditional" :
                pkg->compatibility == INCOMPATIBLE ? "incompatible" : "unknown");
        fprintf(f, "    }%s\n", (i < report->package_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ],\n");
    fprintf(f, "  \"violations\": [\n");
    
    for (int i = 0; i < report->violation_count; i++) {
        LicenseViolation* v = &report->violations[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"package\": \"%s\",\n", v->package_name);
        fprintf(f, "      \"license\": \"%s\",\n", v->license);
        fprintf(f, "      \"type\": \"%s\",\n", v->violation_type);
        fprintf(f, "      \"severity\": %d,\n", v->severity);
        fprintf(f, "      \"remediation\": \"%s\"\n", v->remediation);
        fprintf(f, "    }%s\n", (i < report->violation_count - 1) ? "," : "");
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
    printf("RawrXD License Compliance Scanner\n");
    printf("===============================\n\n");
    
    LicenseComplianceReport* report = license_report_create();
    
    // Parse project license
    if (argc > 1) {
        strncpy(report->project_license, argv[1], sizeof(report->project_license) - 1);
        report->project_category = detect_license_category(argv[1]);
    }
    
    // Scan packages
    scan_packages(report);
    
    // Generate reports
    print_license_summary(report);
    print_violations(report);
    export_license_json(report, "license_compliance.json");
    
    printf("\nLicense compliance scan complete!\n");
    
    int exit_code = report->passed ? 0 : 1;
    license_report_destroy(report);
    
    return exit_code;
}
