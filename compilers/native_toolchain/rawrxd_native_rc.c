/*
 * RAWRXD NATIVE RESOURCE COMPILER
 * Compiles .RC resource script files into COFF .RES or binary .RES files
 * No Microsoft RC.EXE dependency
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <wchar.h>

#pragma pack(push, 1)

/* Resource directory structures */
typedef struct {
    uint32_t DataSize;
    uint32_t HeaderSize;
    uint16_t Type;
    uint16_t Name;
    uint32_t DataVersion;
    uint16_t MemoryFlags;
    uint16_t LanguageId;
    uint32_t Version;
    uint32_t Characteristics;
} RESOURCE_HEADER;

/* Icon directory entry */
typedef struct {
    uint8_t Width;
    uint8_t Height;
    uint8_t ColorCount;
    uint8_t Reserved;
    uint16_t Planes;
    uint16_t BitCount;
    uint32_t BytesInRes;
    uint16_t Id;
} ICON_DIR_ENTRY;

/* Icon directory */
typedef struct {
    uint16_t Reserved;
    uint16_t Type;
    uint16_t Count;
} ICON_DIR;

#pragma pack(pop)

/* Resource types */
#define RT_CURSOR       1
#define RT_BITMAP       2
#define RT_ICON         3
#define RT_MENU         4
#define RT_DIALOG       5
#define RT_STRING       6
#define RT_FONTDIR      7
#define RT_FONT         8
#define RT_ACCELERATOR  9
#define RT_RCDATA       10
#define RT_MESSAGETABLE 11
#define RT_GROUP_CURSOR 12
#define RT_GROUP_ICON   14
#define RT_VERSION      16
#define RT_DLGINCLUDE   17
#define RT_PLUGPLAY     19
#define RT_VXD          20
#define RT_ANICURSOR    21
#define RT_ANIICON      22
#define RT_HTML         23
#define RT_MANIFEST     24

/* Resource memory flags */
#define MOVEABLE        0x0010
#define FIXED           0x0000
#define PURE            0x0020
#define IMPURE          0x0000
#define PRELOAD         0x0040
#define LOADONCALL      0x0000
#define DISCARDABLE     0x1000

/* Parser state */
typedef struct {
    char *input_file;
    char *output_file;
    int verbose;
    int line_number;
    FILE *out_fp;
} RC_State;

static RC_State g_state;

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */
static char *skip_whitespace(char *p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static char *parse_token(char *p, char *token, size_t token_size) {
    p = skip_whitespace(p);
    size_t i = 0;

    /* Handle quoted strings */
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && i < token_size - 1) {
            if (*p == '\\' && *(p+1)) {
                p++;
                switch (*p) {
                    case 'n': token[i++] = '\n'; break;
                    case 't': token[i++] = '\t'; break;
                    case 'r': token[i++] = '\r'; break;
                    case '\\': token[i++] = '\\'; break;
                    case '"': token[i++] = '"'; break;
                    default: token[i++] = *p; break;
                }
                p++;
            } else {
                token[i++] = *p++;
            }
        }
        if (*p == '"') p++;
        token[i] = '\0';
        return p;
    }

    /* Handle identifiers and numbers */
    if (isalpha((unsigned char)*p) || *p == '_') {
        while ((isalnum((unsigned char)*p) || *p == '_') && i < token_size - 1) {
            token[i++] = *p++;
        }
    } else if (isdigit((unsigned char)*p)) {
        while (isdigit((unsigned char)*p) && i < token_size - 1) {
            token[i++] = *p++;
        }
    } else {
        /* Single character token */
        token[i++] = *p++;
    }

    token[i] = '\0';
    return p;
}

static int get_resource_type(const char *name) {
    if (strcmp(name, "CURSOR") == 0) return RT_CURSOR;
    if (strcmp(name, "BITMAP") == 0) return RT_BITMAP;
    if (strcmp(name, "ICON") == 0) return RT_ICON;
    if (strcmp(name, "MENU") == 0) return RT_MENU;
    if (strcmp(name, "DIALOG") == 0) return RT_DIALOG;
    if (strcmp(name, "STRING") == 0) return RT_STRING;
    if (strcmp(name, "FONTDIR") == 0) return RT_FONTDIR;
    if (strcmp(name, "FONT") == 0) return RT_FONT;
    if (strcmp(name, "ACCELERATOR") == 0) return RT_ACCELERATOR;
    if (strcmp(name, "RCDATA") == 0) return RT_RCDATA;
    if (strcmp(name, "MESSAGETABLE") == 0) return RT_MESSAGETABLE;
    if (strcmp(name, "GROUP_CURSOR") == 0) return RT_GROUP_CURSOR;
    if (strcmp(name, "GROUP_ICON") == 0) return RT_GROUP_ICON;
    if (strcmp(name, "VERSIONINFO") == 0) return RT_VERSION;
    if (strcmp(name, "DLGINCLUDE") == 0) return RT_DLGINCLUDE;
    if (strcmp(name, "PLUGPLAY") == 0) return RT_PLUGPLAY;
    if (strcmp(name, "VXD") == 0) return RT_VXD;
    if (strcmp(name, "ANICURSOR") == 0) return RT_ANICURSOR;
    if (strcmp(name, "ANIICON") == 0) return RT_ANIICON;
    if (strcmp(name, "HTML") == 0) return RT_HTML;
    if (strcmp(name, "MANIFEST") == 0) return RT_MANIFEST;

    /* Numeric type */
    if (isdigit((unsigned char)name[0])) {
        return atoi(name);
    }

    return 0; /* Custom name */
}

/* ============================================================================
 * RESOURCE WRITING
 * ============================================================================ */
static void write_resource_header(int type, int name, uint32_t data_size, uint16_t lang) {
    RESOURCE_HEADER hdr;
    hdr.DataSize = data_size;
    hdr.HeaderSize = sizeof(RESOURCE_HEADER);
    hdr.Type = (uint16_t)type;
    hdr.Name = (uint16_t)name;
    hdr.DataVersion = 0;
    hdr.MemoryFlags = MOVEABLE | PURE | PRELOAD;
    hdr.LanguageId = lang;
    hdr.Version = 0;
    hdr.Characteristics = 0;

    fwrite(&hdr, sizeof(hdr), 1, g_state.out_fp);
}

static int compile_bitmap(const char *filename, int res_id, uint16_t lang) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open bitmap '%s'\n", filename);
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    uint32_t size = (uint32_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *data = (uint8_t *)malloc(size);
    fread(data, size, 1, fp);
    fclose(fp);

    write_resource_header(RT_BITMAP, res_id, size, lang);
    fwrite(data, size, 1, g_state.out_fp);

    free(data);
    return 1;
}

static int compile_icon(const char *filename, int res_id, uint16_t lang) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open icon '%s'\n", filename);
        return 0;
    }

    /* Read icon directory */
    ICON_DIR icon_dir;
    fread(&icon_dir, sizeof(icon_dir), 1, fp);

    if (icon_dir.Reserved != 0 || icon_dir.Type != 1) {
        fprintf(stderr, "Error: Invalid icon file '%s'\n", filename);
        fclose(fp);
        return 0;
    }

    /* Read icon entries */
    ICON_DIR_ENTRY *entries = (ICON_DIR_ENTRY *)malloc(icon_dir.Count * sizeof(ICON_DIR_ENTRY));
    fread(entries, sizeof(ICON_DIR_ENTRY), icon_dir.Count, fp);

    /* Create group icon resource */
    uint32_t group_size = sizeof(ICON_DIR) + icon_dir.Count * 14; /* sizeof(GRPICONDIRENTRY) */
    uint8_t *group_data = (uint8_t *)malloc(group_size);

    /* Copy icon directory */
    memcpy(group_data, &icon_dir, sizeof(ICON_DIR));

    /* Create group entries */
    for (int i = 0; i < icon_dir.Count; i++) {
        uint8_t *entry = group_data + sizeof(ICON_DIR) + i * 14;
        entry[0] = entries[i].Width;
        entry[1] = entries[i].Height;
        entry[2] = entries[i].ColorCount;
        entry[3] = entries[i].Reserved;
        *(uint16_t *)(entry + 4) = entries[i].Planes;
        *(uint16_t *)(entry + 6) = entries[i].BitCount;
        *(uint32_t *)(entry + 8) = entries[i].BytesInRes;
        *(uint16_t *)(entry + 12) = res_id + i + 1;
    }

    /* Write group icon resource */
    write_resource_header(RT_GROUP_ICON, res_id, group_size, lang);
    fwrite(group_data, group_size, 1, g_state.out_fp);

    /* Write individual icon images */
    for (int i = 0; i < icon_dir.Count; i++) {
        uint8_t *icon_data = (uint8_t *)malloc(entries[i].BytesInRes);
        fseek(fp, entries[i].Id, SEEK_SET); /* Id field contains offset in this context */
        fread(icon_data, entries[i].BytesInRes, 1, fp);

        write_resource_header(RT_ICON, res_id + i + 1, entries[i].BytesInRes, lang);
        fwrite(icon_data, entries[i].BytesInRes, 1, g_state.out_fp);

        free(icon_data);
    }

    free(entries);
    free(group_data);
    fclose(fp);

    return 1;
}

static int compile_rcdata(const char *filename, int res_id, uint16_t lang) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    uint32_t size = (uint32_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *data = (uint8_t *)malloc(size);
    fread(data, size, 1, fp);
    fclose(fp);

    write_resource_header(RT_RCDATA, res_id, size, lang);
    fwrite(data, size, 1, g_state.out_fp);

    free(data);
    return 1;
}

static int compile_string_table(int block_id, const char *strings, uint16_t lang) {
    /* String table block - 16 strings per block */
    /* Each string is: length (word) + characters (unicode) */

    /* For simplicity, convert to wide char and write */
    wchar_t *wstrings = (wchar_t *)malloc(4096 * sizeof(wchar_t));
    size_t len = mbstowcs(wstrings, strings, 4096);

    uint32_t size = (uint32_t)(len * sizeof(wchar_t));
    write_resource_header(RT_STRING, block_id + 1, size, lang);
    fwrite(wstrings, size, 1, g_state.out_fp);

    free(wstrings);
    return 1;
}

static int compile_version_info(int res_id, uint16_t lang) {
    /* VS_VERSION_INFO structure */
    /* This is a simplified version */

    uint8_t version_data[1024];
    memset(version_data, 0, sizeof(version_data));

    /* VS_VERSIONINFO header */
    uint16_t *p = (uint16_t *)version_data;
    *p++ = sizeof(version_data);  /* wLength */
    *p++ = sizeof(uint32_t) * 6;  /* wValueLength (VS_FIXEDFILEINFO) */
    *p++ = 0;                     /* wType (0 = binary) */
    /* szKey: "VS_VERSION_INFO\0" */
    wchar_t *key = (wchar_t *)p;
    const char *vs_key = "VS_VERSION_INFO";
    for (size_t i = 0; i <= strlen(vs_key); i++) {
        key[i] = (wchar_t)vs_key[i];
    }
    p = (uint16_t *)(key + strlen(vs_key) + 1);

    /* Align to 4 bytes */
    p = (uint16_t *)(((uintptr_t)p + 3) & ~3);

    /* VS_FIXEDFILEINFO */
    uint32_t *ffi = (uint32_t *)p;
    ffi[0] = 0xFEEF04BD;  /* dwSignature */
    ffi[1] = 0x00010000;  /* dwStrucVersion */
    ffi[2] = 0x00010000;  /* dwFileVersionMS */
    ffi[3] = 0x00000000;  /* dwFileVersionLS */
    ffi[4] = 0x00010000;  /* dwProductVersionMS */
    ffi[5] = 0x00000000;  /* dwProductVersionLS */
    ffi[6] = 0x0000003F;  /* dwFileFlagsMask */
    ffi[7] = 0x00000000;  /* dwFileFlags */
    ffi[8] = 0x00000004;  /* dwFileOS (VOS_NT_WINDOWS32) */
    ffi[9] = 0x00000001;  /* dwFileType (VFT_APP) */
    ffi[10] = 0x00000000; /* dwFileSubtype */
    ffi[11] = 0x00000000; /* dwFileDateMS */
    ffi[12] = 0x00000000; /* dwFileDateLS */

    uint32_t size = (uint32_t)((uint8_t *)(ffi + 13) - version_data);
    write_resource_header(RT_VERSION, res_id, size, lang);
    fwrite(version_data, size, 1, g_state.out_fp);

    return 1;
}

static int compile_manifest(const char *filename, int res_id, uint16_t lang) {
    return compile_rcdata(filename, res_id, lang);
}

/* ============================================================================
 * RC SCRIPT PARSING
 * ============================================================================ */
static int parse_rc_script(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open RC script '%s'\n", filename);
        return 0;
    }

    printf("Compiling: %s\n", filename);

    char line[4096];
    g_state.line_number = 0;

    while (fgets(line, sizeof(line), fp)) {
        g_state.line_number++;

        /* Remove comments */
        char *comment = strchr(line, '//');
        if (comment) *comment = '\0';

        /* Remove newline */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }

        char *p = skip_whitespace(line);
        if (!*p) continue;

        /* Parse resource definition */
        char token[256];
        p = parse_token(p, token, sizeof(token));

        /* Check for resource ID first */
        int res_id = 0;
        if (isdigit((unsigned char)token[0])) {
            res_id = atoi(token);
            p = parse_token(p, token, sizeof(token));
        } else if (token[0] == '"') {
            /* String ID */
            res_id = 1; /* Default */
        }

        /* Get resource type */
        int res_type = get_resource_type(token);

        if (res_type == 0) {
            /* Custom type or identifier */
            /* Try to parse as ID TYPE filename format */
            char type_name[256];
            strcpy(type_name, token);

            p = parse_token(p, token, sizeof(token));
            if (token[0] == '"') {
                /* filename */
                printf("  Resource: %s (type %s, id %d)\n", token, type_name, res_id);

                /* Determine type from extension or type name */
                if (strstr(token, ".bmp") || strstr(token, ".BMP")) {
                    compile_bitmap(token, res_id, 0x0409); /* English US */
                } else if (strstr(token, ".ico") || strstr(token, ".ICO")) {
                    compile_icon(token, res_id, 0x0409);
                } else if (strstr(token, ".manifest") || strstr(token, ".MANIFEST")) {
                    compile_manifest(token, res_id, 0x0409);
                } else {
                    compile_rcdata(token, res_id, 0x0409);
                }
            }
        } else {
            /* Predefined type */
            p = parse_token(p, token, sizeof(token));

            if (token[0] == '"') {
                printf("  Resource: %s (type %d, id %d)\n", token, res_type, res_id);

                switch (res_type) {
                    case RT_BITMAP:
                        compile_bitmap(token, res_id, 0x0409);
                        break;
                    case RT_ICON:
                        compile_icon(token, res_id, 0x0409);
                        break;
                    case RT_VERSION:
                        compile_version_info(res_id, 0x0409);
                        break;
                    case RT_MANIFEST:
                        compile_manifest(token, res_id, 0x0409);
                        break;
                    default:
                        compile_rcdata(token, res_id, 0x0409);
                        break;
                }
            }
        }
    }

    fclose(fp);
    return 1;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */
static void print_usage(const char *prog) {
    fprintf(stderr, "RAWRXD Native Resource Compiler\n");
    fprintf(stderr, "Usage: %s [options] script.rc [output.res]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  /fo file        Output file name\n");
    fprintf(stderr, "  /v              Verbose output\n");
    fprintf(stderr, "  /l lang         Language ID (default: 0x0409)\n");
    fprintf(stderr, "  /c codepage     Code page\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s resources.rc /fo output.res\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    memset(&g_state, 0, sizeof(g_state));

    char *input_file = NULL;
    char *output_file = NULL;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "/v") == 0 || strcmp(argv[i], "-v") == 0) {
            g_state.verbose = 1;
        } else if ((strcmp(argv[i], "/fo") == 0 || strcmp(argv[i], "-fo") == 0) && i + 1 < argc) {
            output_file = argv[++i];
        } else if ((strcmp(argv[i], "/l") == 0 || strcmp(argv[i], "-l") == 0) && i + 1 < argc) {
            /* Language ID - skip for now */
            i++;
        } else if (argv[i][0] != '/' && argv[i][0] != '-') {
            if (!input_file) {
                input_file = argv[i];
            } else if (!output_file) {
                output_file = argv[i];
            }
        }
    }

    if (!input_file) {
        fprintf(stderr, "Error: No input file specified\n");
        return 1;
    }

    /* Generate output filename if not specified */
    if (!output_file) {
        static char out_buf[256];
        strncpy(out_buf, input_file, 250);
        out_buf[250] = '\0';
        char *dot = strrchr(out_buf, '.');
        if (dot) {
            strcpy(dot, ".res");
        } else {
            strcat(out_buf, ".res");
        }
        output_file = out_buf;
    }

    g_state.input_file = input_file;
    g_state.output_file = output_file;

    /* Open output file */
    g_state.out_fp = fopen(output_file, "wb");
    if (!g_state.out_fp) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
        return 1;
    }

    /* Parse and compile */
    if (!parse_rc_script(input_file)) {
        fclose(g_state.out_fp);
        return 1;
    }

    fclose(g_state.out_fp);

    printf("\nSuccess! Output: %s\n", output_file);
    return 0;
}
