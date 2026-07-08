/*
 * RAWRXD NATIVE MANIFEST WRITER
 * Creates Windows application manifest files
 * No Microsoft MT.EXE dependency
 * Supports: x86 (32-bit), x64 (64-bit), x32 (ILP32)
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* Manifest types */
typedef enum {
    MANIFEST_DEFAULT,
    MANIFEST_UAC_ADMIN,
    MANIFEST_UAC_HIGHEST,
    MANIFEST_UAC_INVOKER,
    MANIFEST_DPI_AWARE,
    MANIFEST_DPI_UNAWARE,
    MANIFEST_COMPATIBILITY,
    MANIFEST_COMMON_CONTROLS_V6
} ManifestType;

/* Assembly info */
typedef struct {
    char Name[256];
    char Version[32];
    char ProcessorArchitecture[16];
    char PublicKeyToken[32];
    char Language[16];
    ManifestType Type;
    int UACLevel; /* 0=asInvoker, 1=highestAvailable, 2=requireAdministrator */
    int DPIAware; /* 0=unaware, 1=system, 2=per-monitor */
    int CompatibilityMode; /* Windows version compatibility */
} AssemblyInfo;

static AssemblyInfo g_asm;

/* ============================================================================
 * XML ESCAPING
 * ============================================================================ */

static void write_xml_string(FILE* fp, const char* str) {
    while (*str) {
        switch (*str) {
            case '&': fprintf(fp, "&amp;"); break;
            case '<': fprintf(fp, "&lt;"); break;
            case '>': fprintf(fp, "&gt;"); break;
            case '"': fprintf(fp, "&quot;"); break;
            case '\'': fprintf(fp, "&apos;"); break;
            default: fputc(*str, fp); break;
        }
        str++;
    }
}

/* ============================================================================
 * MANIFEST GENERATION
 * ============================================================================ */

static void write_manifest_header(FILE* fp) {
    fprintf(fp, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?\u003e\n");
}

static void write_assembly_start(FILE* fp) {
    fprintf(fp, "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" ");
    fprintf(fp, "manifestVersion=\"1.0\"\u003e\n");
}

static void write_assembly_identity(FILE* fp) {
    fprintf(fp, "  <assemblyIdentity\n");
    fprintf(fp, "    version=\"%s\"\n", g_asm.Version);
    fprintf(fp, "    name=\"");
    write_xml_string(fp, g_asm.Name);
    fprintf(fp, "\"\n");
    fprintf(fp, "    processorArchitecture=\"%s\"\n", g_asm.ProcessorArchitecture);
    fprintf(fp, "    type=\"win32\"\n");
    fprintf(fp, "    publicKeyToken=\"%s\"\n", g_asm.PublicKeyToken);
    fprintf(fp, "    language=\"%s\"\n", g_asm.Language);
    fprintf(fp, "  /\u003e\n");
}

static void write_compatibility_section(FILE* fp) {
    fprintf(fp, "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"\u003e\n");
    fprintf(fp, "    <application\u003e\n");
    
    /* Windows 10/11 */
    fprintf(fp, "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/\u003e\n");
    /* Windows 8.1 */
    fprintf(fp, "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/\u003e\n");
    /* Windows 8 */
    fprintf(fp, "      <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/\u003e\n");
    /* Windows 7 */
    fprintf(fp, "      <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/\u003e\n");
    /* Windows Vista */
    fprintf(fp, "      <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/\u003e\n");
    
    fprintf(fp, "    </application\u003e\n");
    fprintf(fp, "  </compatibility\u003e\n");
}

static void write_dependency_section(FILE* fp) {
    /* Common Controls v6 */
    fprintf(fp, "  <dependency\u003e\n");
    fprintf(fp, "    <dependentAssembly\u003e\n");
    fprintf(fp, "      <assemblyIdentity\n");
    fprintf(fp, "        type=\"win32\"\n");
    fprintf(fp, "        name=\"Microsoft.Windows.Common-Controls\"\n");
    fprintf(fp, "        version=\"6.0.0.0\"\n");
    fprintf(fp, "        processorArchitecture=\"%s\"\n", g_asm.ProcessorArchitecture);
    fprintf(fp, "        publicKeyToken=\"6595b64144ccf1df\"\n");
    fprintf(fp, "        language=\"*\"\n");
    fprintf(fp, "      /\u003e\n");
    fprintf(fp, "    </dependentAssembly\u003e\n");
    fprintf(fp, "  </dependency\u003e\n");
}

static void write_trust_info(FILE* fp) {
    fprintf(fp, "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"\u003e\n");
    fprintf(fp, "    <security\u003e\n");
    fprintf(fp, "      <requestedPrivileges\u003e\n");
    
    switch (g_asm.UACLevel) {
        case 0:
            fprintf(fp, "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /\u003e\n");
            break;
        case 1:
            fprintf(fp, "        <requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\" /\u003e\n");
            break;
        case 2:
            fprintf(fp, "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" /\u003e\n");
            break;
        default:
            fprintf(fp, "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /\u003e\n");
            break;
    }
    
    fprintf(fp, "      </requestedPrivileges\u003e\n");
    fprintf(fp, "    </security\u003e\n");
    fprintf(fp, "  </trustInfo\u003e\n");
}

static void write_dpi_awareness(FILE* fp) {
    fprintf(fp, "  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\"\u003e\n");
    fprintf(fp, "    <windowsSettings\u003e\n");
    
    if (g_asm.DPIAware == 2) {
        fprintf(fp, "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\u003e");
        fprintf(fp, "true/pm</dpiAware\u003e\n");
        fprintf(fp, "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\u003e");
        fprintf(fp, "permonitorv2,permonitor,system</dpiAwareness\u003e\n");
    } else if (g_asm.DPIAware == 1) {
        fprintf(fp, "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\u003e");
        fprintf(fp, "true</dpiAware\u003e\n");
    } else {
        fprintf(fp, "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\u003e");
        fprintf(fp, "false</dpiAware\u003e\n");
    }
    
    fprintf(fp, "    </windowsSettings\u003e\n");
    fprintf(fp, "  </application\u003e\n");
}

static void write_assembly_end(FILE* fp) {
    fprintf(fp, "</assembly\u003e\n");
}

static int generate_manifest(const char* output_file) {
    FILE* fp = fopen(output_file, "w");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create '%s'\n", output_file);
        return 0;
    }

    write_manifest_header(fp);
    write_assembly_start(fp);
    write_assembly_identity(fp);
    write_compatibility_section(fp);
    write_dependency_section(fp);
    write_trust_info(fp);
    write_dpi_awareness(fp);
    write_assembly_end(fp);

    fclose(fp);
    printf("Manifest created: %s\n", output_file);
    return 1;
}

/* ============================================================================
 * EMBEDDED RESOURCE GENERATION
 * ============================================================================ */

static int generate_embedded_manifest(const char* output_file, const char* input_manifest) {
    /* Read input manifest */
    FILE* in = fopen(input_manifest, "rb");
    if (!in) {
        fprintf(stderr, "Error: Cannot open input manifest '%s'\n", input_manifest);
        return 0;
    }

    fseek(in, 0, SEEK_END);
    long size = ftell(in);
    fseek(in, 0, SEEK_SET);

    char* manifest_data = (char*)malloc(size + 1);
    fread(manifest_data, size, 1, in);
    manifest_data[size] = '\0';
    fclose(in);

    /* Create .res file (binary resource) */
    FILE* out = fopen(output_file, "wb");
    if (!out) {
        fprintf(stderr, "Error: Cannot create '%s'\n", output_file);
        free(manifest_data);
        return 0;
    }

    /* Resource header */
    struct {
        uint32_t DataSize;
        uint32_t HeaderSize;
        uint16_t Type;
        uint16_t Name;
        uint32_t DataVersion;
        uint16_t MemoryFlags;
        uint16_t LanguageId;
        uint32_t Version;
        uint32_t Characteristics;
    } res_header;

    res_header.DataSize = size;
    res_header.HeaderSize = sizeof(res_header);
    res_header.Type = 24; /* RT_MANIFEST */
    res_header.Name = 1;  /* CREATEPROCESS_MANIFEST_RESOURCE_ID */
    res_header.DataVersion = 0;
    res_header.MemoryFlags = 0x0030; /* MOVEABLE | PURE */
    res_header.LanguageId = 0x0409;  /* LANG_ENGLISH | SUBLANG_ENGLISH_US */
    res_header.Version = 0;
    res_header.Characteristics = 0;

    fwrite(&res_header, sizeof(res_header), 1, out);
    fwrite(manifest_data, size, 1, out);

    fclose(out);
    free(manifest_data);

    printf("Embedded manifest resource created: %s\n", output_file);
    return 1;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] /out:output.manifest\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  /out:file           Output manifest file (required)\n");
    fprintf(stderr, "  /identity:name      Assembly identity name\n");
    fprintf(stderr, "  /version:ver        Assembly version (default: 1.0.0.0)\n");
    fprintf(stderr, "  /arch:arch          Processor architecture: x86, x64, ia64, arm, arm64\n");
    fprintf(stderr, "  /uac:level          UAC level: asInvoker, highest, admin\n");
    fprintf(stderr, "  /dpi:mode           DPI awareness: unaware, system, permonitor\n");
    fprintf(stderr, "  /embed:resfile      Create embedded resource from manifest\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s /out:app.manifest /identity:MyApp /uac:admin\n", prog);
    fprintf(stderr, "  %s /out:app.res /embed:app.manifest\n", prog);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* Defaults */
    strcpy(g_asm.Name, "MyApplication");
    strcpy(g_asm.Version, "1.0.0.0");
    strcpy(g_asm.ProcessorArchitecture, "amd64");
    strcpy(g_asm.PublicKeyToken, "0000000000000000");
    strcpy(g_asm.Language, "*");
    g_asm.UACLevel = 0;
    g_asm.DPIAware = 1;

    char output_file[256] = {0};
    char embed_output[256] = {0};
    char* input_manifest = NULL;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "/out:", 5) == 0 || strncmp(argv[i], "-out:", 5) == 0) {
            strncpy(output_file, argv[i] + 5, 255);
        } else if (strncmp(argv[i], "/identity:", 10) == 0) {
            strncpy(g_asm.Name, argv[i] + 10, 255);
        } else if (strncmp(argv[i], "/version:", 9) == 0) {
            strncpy(g_asm.Version, argv[i] + 9, 31);
        } else if (strncmp(argv[i], "/arch:", 6) == 0) {
            strncpy(g_asm.ProcessorArchitecture, argv[i] + 6, 15);
        } else if (strncmp(argv[i], "/uac:", 5) == 0) {
            const char* level = argv[i] + 5;
            if (strcmp(level, "admin") == 0 || strcmp(level, "requireAdministrator") == 0) {
                g_asm.UACLevel = 2;
            } else if (strcmp(level, "highest") == 0 || strcmp(level, "highestAvailable") == 0) {
                g_asm.UACLevel = 1;
            } else {
                g_asm.UACLevel = 0;
            }
        } else if (strncmp(argv[i], "/dpi:", 5) == 0) {
            const char* mode = argv[i] + 5;
            if (strcmp(mode, "permonitor") == 0 || strcmp(mode, "permonitorv2") == 0) {
                g_asm.DPIAware = 2;
            } else if (strcmp(mode, "system") == 0 || strcmp(mode, "true") == 0) {
                g_asm.DPIAware = 1;
            } else {
                g_asm.DPIAware = 0;
            }
        } else if (strncmp(argv[i], "/embed:", 7) == 0) {
            strncpy(embed_output, argv[i] + 7, 255);
        } else if (argv[i][0] != '/' && argv[i][0] != '-') {
            input_manifest = argv[i];
        }
    }

    /* Handle embedded resource generation */
    if (embed_output[0] && input_manifest) {
        if (!generate_embedded_manifest(embed_output, input_manifest)) {
            return 1;
        }
        printf("\nSuccess! Embedded manifest resource generated.\n");
        return 0;
    }

    if (!output_file[0]) {
        fprintf(stderr, "Error: No output file specified. Use /out:filename\n");
        return 1;
    }

    /* Generate manifest */
    if (!generate_manifest(output_file)) {
        return 1;
    }

    printf("\nSuccess! Manifest generated.\n");
    printf("  Name: %s\n", g_asm.Name);
    printf("  Version: %s\n", g_asm.Version);
    printf("  Architecture: %s\n", g_asm.ProcessorArchitecture);
    printf("  UAC Level: %s\n", g_asm.UACLevel == 2 ? "requireAdministrator" : 
           g_asm.UACLevel == 1 ? "highestAvailable" : "asInvoker");
    printf("  DPI Awareness: %s\n", g_asm.DPIAware == 2 ? "per-monitor" :
           g_asm.DPIAware == 1 ? "system" : "unaware");

    return 0;
}
