//=============================================================================
// artifact_manager.c - Build Artifact Manager
// Production-ready artifact versioning, storage, and retrieval
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>

//=============================================================================
// Artifact Types
//=============================================================================

#define MAX_ARTIFACTS 1000
#define MAX_VERSIONS 100
#define MAX_TAGS 50

typedef enum {
    ARTIFACT_EXECUTABLE,
    ARTIFACT_LIBRARY,
    ARTIFACT_PACKAGE,
    ARTIFACT_DOCUMENTATION,
    ARTIFACT_SOURCE,
    ARTIFACT_CONTAINER
} ArtifactType;

typedef enum {
    STORAGE_LOCAL,
    STORAGE_S3,
    STORAGE_AZURE,
    STORAGE_GCS,
    STORAGE_NFS
} StorageType;

typedef struct {
    char version[32];
    char build_id[64];
    time_t timestamp;
    char checksum[65];
    size_t size;
    char path[512];
    int is_latest;
    int download_count;
} ArtifactVersion;

typedef struct {
    char name[256];
    char id[64];
    ArtifactType type;
    char project[128];
    char branch[128];
    
    ArtifactVersion* versions;
    int version_count;
    int version_capacity;
    
    char tags[MAX_TAGS][64];
    int tag_count;
    
    StorageType storage;
    char storage_config[512];
    
    int retention_days;
    int max_versions;
    char description[1024];
} Artifact;

typedef struct {
    Artifact* artifacts;
    int artifact_count;
    int artifact_capacity;
    
    StorageType default_storage;
    char storage_root[512];
    
    int total_artifacts;
    int total_versions;
    size_t total_size;
    size_t reclaimed_space;
} ArtifactManager;

//=============================================================================
// Artifact Manager Implementation
//=============================================================================

ArtifactManager* artifact_manager_create(void) {
    ArtifactManager* mgr = (ArtifactManager*)calloc(1, sizeof(ArtifactManager));
    mgr->artifact_capacity = MAX_ARTIFACTS;
    mgr->artifacts = (Artifact*)calloc(mgr->artifact_capacity, sizeof(Artifact));
    mgr->default_storage = STORAGE_LOCAL;
    strncpy(mgr->storage_root, "./artifacts", sizeof(mgr->storage_root));
    return mgr;
}

void artifact_manager_destroy(ArtifactManager* mgr) {
    if (!mgr) return;
    for (int i = 0; i < mgr->artifact_count; i++) {
        free(mgr->artifacts[i].versions);
    }
    free(mgr->artifacts);
    free(mgr);
}

Artifact* artifact_create(ArtifactManager* mgr, const char* name, ArtifactType type) {
    if (mgr->artifact_count >= mgr->artifact_capacity) return NULL;
    
    Artifact* art = &mgr->artifacts[mgr->artifact_count++];
    strncpy(art->name, name, sizeof(art->name) - 1);
    snprintf(art->id, sizeof(art->id), "ART-%ld", (long)time(NULL));
    art->type = type;
    art->version_capacity = MAX_VERSIONS;
    art->versions = (ArtifactVersion*)calloc(art->version_capacity, sizeof(ArtifactVersion));
    art->retention_days = 30;
    art->max_versions = 10;
    art->storage = mgr->default_storage;
    return art;
}

ArtifactVersion* artifact_add_version(Artifact* art, const char* version,
                                       const char* build_id, size_t size) {
    if (art->version_count >= art->version_capacity) return NULL;
    
    // Mark previous latest as not latest
    for (int i = 0; i < art->version_count; i++) {
        art->versions[i].is_latest = 0;
    }
    
    ArtifactVersion* ver = &art->versions[art->version_count++];
    strncpy(ver->version, version, sizeof(ver->version) - 1);
    strncpy(ver->build_id, build_id, sizeof(ver->build_id) - 1);
    ver->timestamp = time(NULL);
    ver->size = size;
    ver->is_latest = 1;
    
    // Generate checksum (simulated)
    snprintf(ver->checksum, sizeof(ver->checksum),
             "sha256:%08x%08x%08x%08x",
             rand(), rand(), rand(), rand());
    
    snprintf(ver->path, sizeof(ver->path),
             "%s/%s/%s/%s",
             art->project, art->name, version, build_id);
    
    return ver;
}

void artifact_add_tag(Artifact* art, const char* tag) {
    if (art->tag_count >= MAX_TAGS) return;
    strncpy(art->tags[art->tag_count++], tag, 63);
}

void artifact_cleanup_old_versions(Artifact* art, ArtifactManager* mgr) {
    time_t now = time(NULL);
    int removed = 0;
    
    for (int i = art->version_count - 1; i >= 0; i--) {
        ArtifactVersion* ver = &art->versions[i];
        double age_days = difftime(now, ver->timestamp) / (24 * 3600);
        
        // Remove if too old and not latest
        if (age_days > art->retention_days && !ver->is_latest) {
            mgr->reclaimed_space += ver->size;
            // Shift remaining versions
            for (int j = i; j < art->version_count - 1; j++) {
                art->versions[j] = art->versions[j + 1];
            }
            art->version_count--;
            removed++;
        }
    }
    
    // Enforce max versions
    while (art->version_count > art->max_versions) {
        // Remove oldest non-latest
        for (int i = 0; i < art->version_count; i++) {
            if (!art->versions[i].is_latest) {
                mgr->reclaimed_space += art->versions[i].size;
                for (int j = i; j < art->version_count - 1; j++) {
                    art->versions[j] = art->versions[j + 1];
                }
                art->version_count--;
                removed++;
                break;
            }
        }
    }
}

Artifact* artifact_find(ArtifactManager* mgr, const char* name) {
    for (int i = 0; i < mgr->artifact_count; i++) {
        if (strcmp(mgr->artifacts[i].name, name) == 0) {
            return &mgr->artifacts[i];
        }
    }
    return NULL;
}

ArtifactVersion* artifact_get_latest(Artifact* art) {
    for (int i = 0; i < art->version_count; i++) {
        if (art->versions[i].is_latest) {
            return &art->versions[i];
        }
    }
    return art->version_count > 0 ? &art->versions[art->version_count - 1] : NULL;
}

void artifact_download(Artifact* art, ArtifactVersion* ver) {
    if (!ver) return;
    ver->download_count++;
    printf("  Downloading %s v%s (%zu bytes)\n", art->name, ver->version, ver->size);
    printf("  Checksum: %s\n", ver->checksum);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* artifact_type_to_string(ArtifactType type) {
    switch (type) {
        case ARTIFACT_EXECUTABLE: return "Executable";
        case ARTIFACT_LIBRARY: return "Library";
        case ARTIFACT_PACKAGE: return "Package";
        case ARTIFACT_DOCUMENTATION: return "Documentation";
        case ARTIFACT_SOURCE: return "Source";
        case ARTIFACT_CONTAINER: return "Container";
        default: return "Unknown";
    }
}

const char* storage_type_to_string(StorageType type) {
    switch (type) {
        case STORAGE_LOCAL: return "Local";
        case STORAGE_S3: return "S3";
        case STORAGE_AZURE: return "Azure";
        case STORAGE_GCS: return "GCS";
        case STORAGE_NFS: return "NFS";
        default: return "Unknown";
    }
}

void print_artifact_summary(ArtifactManager* mgr) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Artifact Manager Summary\n");
    printf("=============================================================================\n");
    printf("  Total Artifacts:      %d\n", mgr->artifact_count);
    printf("  Total Versions:       %d\n", mgr->total_versions);
    printf("  Total Size:           %zu MB\n", mgr->total_size / (1024 * 1024));
    printf("  Reclaimed Space:      %zu MB\n", mgr->reclaimed_space / (1024 * 1024));
    printf("  Storage:              %s\n", storage_type_to_string(mgr->default_storage));
    printf("=============================================================================\n");
}

void print_artifact_details(ArtifactManager* mgr) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Artifact Details\n");
    printf("=============================================================================\n");
    
    for (int i = 0; i < mgr->artifact_count; i++) {
        Artifact* art = &mgr->artifacts[i];
        printf("\n  [%s] %s\n", art->id, art->name);
        printf("       Type: %s\n", artifact_type_to_string(art->type));
        printf("       Project: %s\n", art->project);
        printf("       Versions: %d (max: %d)\n", art->version_count, art->max_versions);
        printf("       Retention: %d days\n", art->retention_days);
        
        if (art->tag_count > 0) {
            printf("       Tags: ");
            for (int t = 0; t < art->tag_count; t++) {
                printf("%s ", art->tags[t]);
            }
            printf("\n");
        }
        
        printf("\n       Versions:\n");
        for (int v = 0; v < art->version_count; v++) {
            ArtifactVersion* ver = &art->versions[v];
            printf("         %s %s - %s - %zu bytes - %d downloads\n",
                   ver->is_latest ? "[LATEST]" : "        ",
                   ver->version, ver->build_id, ver->size, ver->download_count);
        }
    }
    
    printf("\n=============================================================================\n");
}

void export_artifacts_json(ArtifactManager* mgr, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"artifacts\": %d,\n", mgr->artifact_count);
    fprintf(f, "    \"versions\": %d,\n", mgr->total_versions);
    fprintf(f, "    \"total_size\": %zu,\n", mgr->total_size);
    fprintf(f, "    \"reclaimed_space\": %zu\n", mgr->reclaimed_space);
    fprintf(f, "  },\n");
    fprintf(f, "  \"artifacts\": [\n");
    
    for (int i = 0; i < mgr->artifact_count; i++) {
        Artifact* art = &mgr->artifacts[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": \"%s\",\n", art->id);
        fprintf(f, "      \"name\": \"%s\",\n", art->name);
        fprintf(f, "      \"type\": \"%s\",\n", artifact_type_to_string(art->type));
        fprintf(f, "      \"project\": \"%s\",\n", art->project);
        fprintf(f, "      \"version_count\": %d,\n", art->version_count);
        fprintf(f, "      \"versions\": [\n");
        
        for (int v = 0; v < art->version_count; v++) {
            ArtifactVersion* ver = &art->versions[v];
            fprintf(f, "        {\n");
            fprintf(f, "          \"version\": \"%s\",\n", ver->version);
            fprintf(f, "          \"build_id\": \"%s\",\n", ver->build_id);
            fprintf(f, "          \"size\": %zu,\n", ver->size);
            fprintf(f, "          \"checksum\": \"%s\",\n", ver->checksum);
            fprintf(f, "          \"is_latest\": %s,\n", ver->is_latest ? "true" : "false");
            fprintf(f, "          \"downloads\": %d\n", ver->download_count);
            fprintf(f, "        }%s\n", (v < art->version_count - 1) ? "," : "");
        }
        
        fprintf(f, "      ]\n");
        fprintf(f, "    }%s\n", (i < mgr->artifact_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Artifact report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Artifact Manager\n");
    printf("=====================\n\n");
    
    srand((unsigned int)time(NULL));
    
    ArtifactManager* mgr = artifact_manager_create();
    
    // Create sample artifacts
    Artifact* exe = artifact_create(mgr, "RawrXD.exe", ARTIFACT_EXECUTABLE);
    strncpy(exe->project, "RawrXD", sizeof(exe->project));
    artifact_add_tag(exe, "stable");
    artifact_add_tag(exe, "windows");
    
    artifact_add_version(exe, "3.0.0", "BUILD-20240708-001", 45 * 1024 * 1024);
    artifact_add_version(exe, "3.0.1", "BUILD-20240708-002", 46 * 1024 * 1024);
    artifact_add_version(exe, "3.1.0", "BUILD-20240708-003", 48 * 1024 * 1024);
    
    Artifact* lib = artifact_create(mgr, "RawrXD.lib", ARTIFACT_LIBRARY);
    strncpy(lib->project, "RawrXD", sizeof(lib->project));
    artifact_add_tag(lib, "dev");
    
    artifact_add_version(lib, "3.0.0", "BUILD-20240708-001", 12 * 1024 * 1024);
    artifact_add_version(lib, "3.1.0", "BUILD-20240708-003", 13 * 1024 * 1024);
    
    // Simulate downloads
    artifact_download(exe, artifact_get_latest(exe));
    
    // Cleanup old versions
    artifact_cleanup_old_versions(exe, mgr);
    artifact_cleanup_old_versions(lib, mgr);
    
    // Calculate totals
    for (int i = 0; i < mgr->artifact_count; i++) {
        mgr->total_versions += mgr->artifacts[i].version_count;
        for (int v = 0; v < mgr->artifacts[i].version_count; v++) {
            mgr->total_size += mgr->artifacts[i].versions[v].size;
        }
    }
    
    // Generate reports
    print_artifact_summary(mgr);
    print_artifact_details(mgr);
    export_artifacts_json(mgr, "artifact_report.json");
    
    printf("\nArtifact management complete!\n");
    
    artifact_manager_destroy(mgr);
    return 0;
}
