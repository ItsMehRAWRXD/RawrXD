/*
 * RAWRXD NATIVE LIBRARIAN - Static library manager
 * Creates and manages .LIB files (COFF format)
 * No Microsoft LIB.EXE dependency
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#pragma pack(push, 1)

/* COFF Archive format */
#define IMAGE_ARCHIVE_START_SIZE 8
#define IMAGE_ARCHIVE_START "!\u003carch\u003e\n"

#define IMAGE_ARCHIVE_END "\x60\x0A"
#define IMAGE_ARCHIVE_PAD "\n"
#define IMAGE_ARCHIVE_PAD_SIZE 1

typedef struct {
    char Name[16];
    char Date[12];
    char UserID[6];
    char GroupID[6];
    char Mode[8];
    char Size[10];
    char EndHeader[2];
} IMAGE_ARCHIVE_MEMBER_HEADER;

typedef struct {
    uint32_t Sig1;
    uint32_t Sig2;
    uint16_t Version;
    uint32_t Machine;
    uint32_t TimeDateStamp;
    uint32_t SizeOfData;
    uint16_t Ordinal;
    uint16_t Type;
} IMPORT_OBJECT_HEADER;

#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_I386  0x014C

#define IMPORT_NAME_NOPREFIX    1
#define IMPORT_NAME_UNDECORATE  2

#pragma pack(pop)

/* Archive member types */
typedef enum {
    MEMBER_NORMAL,
    MEMBER_IMPORT,
    MEMBER_LINKER
} MemberType;

typedef struct ArchiveMember {
    char Name[256];
    uint8_t *Data;
    uint32_t Size;
    uint32_t TimeStamp;
    MemberType Type;
    struct ArchiveMember *next;
} ArchiveMember;

/* Archive state */
typedef struct {
    ArchiveMember *members;
    ArchiveMember *last;
    int member_count;
    char output_name[256];
    int verbose;
} ArchiveState;

static ArchiveState g_state;

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */
static uint32_t align_up(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static void write_decimal(char *buf, size_t size, uint32_t value) {
    snprintf(buf, size, "%-*lu", (int)size - 1, (unsigned long)value);
    buf[size - 1] = ' ';
}

static void write_octal(char *buf, size_t size, uint32_t value) {
    snprintf(buf, size, "%-*o", (int)size - 1, (unsigned)value);
    buf[size - 1] = ' ';
}

/* ============================================================================
 * ARCHIVE OPERATIONS
 * ============================================================================ */
static ArchiveMember* create_member(const char *name, const uint8_t *data, uint32_t size) {
    ArchiveMember *member = (ArchiveMember *)calloc(1, sizeof(ArchiveMember));
    strncpy(member->Name, name, 255);
    member->Name[255] = '\0';
    member->Size = size;
    member->TimeStamp = (uint32_t)time(NULL);
    member->Type = MEMBER_NORMAL;

    if (size > 0) {
        member->Data = (uint8_t *)malloc(size);
        memcpy(member->Data, data, size);
    }

    return member;
}

static void add_member(ArchiveMember *member) {
    if (g_state.last) {
        g_state.last->next = member;
    } else {
        g_state.members = member;
    }
    g_state.last = member;
    g_state.member_count++;
}

static int read_object_file(const char *filename, uint8_t **data, uint32_t *size) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open '%s'\n", filename);
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    *size = (uint32_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    *data = (uint8_t *)malloc(*size);
    if (fread(*data, *size, 1, fp) != 1) {
        fprintf(stderr, "Error: Cannot read '%s'\n", filename);
        free(*data);
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return 1;
}

static int load_archive(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        /* Archive doesn't exist yet - that's OK */
        return 1;
    }

    /* Read signature */
    char sig[IMAGE_ARCHIVE_START_SIZE];
    if (fread(sig, IMAGE_ARCHIVE_START_SIZE, 1, fp) != 1) {
        fprintf(stderr, "Error: Cannot read archive signature\n");
        fclose(fp);
        return 0;
    }

    if (memcmp(sig, IMAGE_ARCHIVE_START, IMAGE_ARCHIVE_START_SIZE) != 0) {
        fprintf(stderr, "Error: Invalid archive format\n");
        fclose(fp);
        return 0;
    }

    /* Read members */
    while (!feof(fp)) {
        IMAGE_ARCHIVE_MEMBER_HEADER header;
        if (fread(&header, sizeof(header), 1, fp) != 1) {
            break;
        }

        /* Parse header */
        char name[17];
        char size_str[11];
        memcpy(name, header.Name, 16);
        name[16] = '\0';

        /* Trim trailing spaces */
        for (int i = 15; i >= 0 && name[i] == ' '; i--) {
            name[i] = '\0';
        }

        memcpy(size_str, header.Size, 10);
        size_str[10] = '\0';
        uint32_t size = (uint32_t)strtoul(size_str, NULL, 10);

        /* Read member data */
        uint8_t *data = (uint8_t *)malloc(size);
        if (fread(data, size, 1, fp) != 1) {
            fprintf(stderr, "Error: Cannot read member data\n");
            free(data);
            break;
        }

        /* Create member */
        ArchiveMember *member = create_member(name, data, size);
        member->TimeStamp = (uint32_t)strtoul(header.Date, NULL, 10);
        add_member(member);

        free(data);

        /* Align to even boundary */
        if (size % 2 != 0) {
            fgetc(fp);
        }
    }

    fclose(fp);
    return 1;
}

static int write_archive(const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create '%s'\n", filename);
        return 0;
    }

    /* Write signature */
    fwrite(IMAGE_ARCHIVE_START, IMAGE_ARCHIVE_START_SIZE, 1, fp);

    /* Write linker member (first and second members) */
    /* For simplicity, we'll skip the linker members for now */

    /* Write regular members */
    ArchiveMember *member = g_state.members;
    while (member) {
        IMAGE_ARCHIVE_MEMBER_HEADER header;
        memset(&header, ' ', sizeof(header));

        /* Name */
        size_t name_len = strlen(member->Name);
        if (name_len <= 15) {
            memcpy(header.Name, member->Name, name_len);
        } else {
            /* Long name - use offset format */
            header.Name[0] = '/';
            /* Would need long name string table for full support */
        }

        /* Date */
        write_decimal(header.Date, sizeof(header.Date), member->TimeStamp);

        /* User ID */
        memcpy(header.UserID, "0     ", 6);

        /* Group ID */
        memcpy(header.GroupID, "0     ", 6);

        /* Mode */
        memcpy(header.Mode, "100644  ", 8);

        /* Size */
        write_decimal(header.Size, sizeof(header.Size), member->Size);

        /* End header marker */
        memcpy(header.EndHeader, IMAGE_ARCHIVE_END, 2);

        /* Write header and data */
        fwrite(&header, sizeof(header), 1, fp);
        fwrite(member->Data, member->Size, 1, fp);

        /* Align to even boundary */
        if (member->Size % 2 != 0) {
            fwrite(IMAGE_ARCHIVE_PAD, IMAGE_ARCHIVE_PAD_SIZE, 1, fp);
        }

        member = member->next;
    }

    fclose(fp);
    return 1;
}

/* ============================================================================
 * COMMANDS
 * ============================================================================ */
static int cmd_create(int argc, char *argv[], int *idx) {
    printf("Creating library: %s\n", g_state.output_name);

    while (*idx < argc) {
        const char *arg = argv[*idx];

        if (arg[0] == '/' || arg[0] == '-') {
            /* Option */
            break;
        }

        printf("  Adding: %s\n", arg);

        uint8_t *data;
        uint32_t size;
        if (!read_object_file(arg, &data, &size)) {
            return 0;
        }

        /* Extract base name */
        const char *base = arg;
        const char *slash = strrchr(arg, '\\');
        const char *slash2 = strrchr(arg, '/');
        if (slash2 && (!slash || slash2 > slash)) slash = slash2;
        if (slash) base = slash + 1;

        ArchiveMember *member = create_member(base, data, size);
        add_member(member);

        free(data);
        (*idx)++;
    }

    return write_archive(g_state.output_name);
}

static int cmd_add(int argc, char *argv[], int *idx) {
    printf("Adding to library: %s\n", g_state.output_name);

    /* Load existing archive */
    if (!load_archive(g_state.output_name)) {
        return 0;
    }

    while (*idx < argc) {
        const char *arg = argv[*idx];

        if (arg[0] == '/' || arg[0] == '-') {
            break;
        }

        printf("  Adding: %s\n", arg);

        uint8_t *data;
        uint32_t size;
        if (!read_object_file(arg, &data, &size)) {
            return 0;
        }

        const char *base = arg;
        const char *slash = strrchr(arg, '\\');
        const char *slash2 = strrchr(arg, '/');
        if (slash2 && (!slash || slash2 > slash)) slash = slash2;
        if (slash) base = slash + 1;

        ArchiveMember *member = create_member(base, data, size);
        add_member(member);

        free(data);
        (*idx)++;
    }

    return write_archive(g_state.output_name);
}

static int cmd_remove(int argc, char *argv[], int *idx) {
    printf("Removing from library: %s\n", g_state.output_name);

    if (!load_archive(g_state.output_name)) {
        return 0;
    }

    while (*idx < argc) {
        const char *arg = argv[*idx];

        if (arg[0] == '/' || arg[0] == '-') {
            break;
        }

        printf("  Removing: %s\n", arg);

        /* Find and remove member */
        ArchiveMember **current = &g_state.members;
        while (*current) {
            if (strcmp((*current)->Name, arg) == 0) {
                ArchiveMember *to_remove = *current;
                *current = to_remove->next;
                if (to_remove == g_state.last) {
                    g_state.last = NULL;
                }
                free(to_remove->Data);
                free(to_remove);
                g_state.member_count--;
                break;
            }
            current = &(*current)->next;
        }

        (*idx)++;
    }

    return write_archive(g_state.output_name);
}

static int cmd_list(int argc, char *argv[], int *idx) {
    (void)argc;
    (void)argv;
    (void)idx;

    printf("Library: %s\n", g_state.output_name);

    if (!load_archive(g_state.output_name)) {
        return 0;
    }

    printf("\nMembers:\n");
    ArchiveMember *member = g_state.members;
    int count = 0;
    while (member) {
        printf("  %s (%u bytes)\n", member->Name, member->Size);
        member = member->next;
        count++;
    }
    printf("\nTotal: %d members\n", count);

    return 1;
}

static int cmd_extract(int argc, char *argv[], int *idx) {
    printf("Extracting from library: %s\n", g_state.output_name);

    if (!load_archive(g_state.output_name)) {
        return 0;
    }

    while (*idx < argc) {
        const char *arg = argv[*idx];

        if (arg[0] == '/' || arg[0] == '-') {
            break;
        }

        /* Find member */
        ArchiveMember *member = g_state.members;
        while (member) {
            if (strcmp(member->Name, arg) == 0) {
                printf("  Extracting: %s\n", arg);

                FILE *fp = fopen(arg, "wb");
                if (!fp) {
                    fprintf(stderr, "Error: Cannot create '%s'\n", arg);
                    return 0;
                }

                fwrite(member->Data, member->Size, 1, fp);
                fclose(fp);
                break;
            }
            member = member->next;
        }

        if (!member) {
            fprintf(stderr, "Warning: Member '%s' not found\n", arg);
        }

        (*idx)++;
    }

    return 1;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */
static void print_usage(const char *prog) {
    fprintf(stderr, "RAWRXD Native Librarian - Static Library Manager\n");
    fprintf(stderr, "Usage: %s [options] [commands] [files...]\n\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  /out:file       Specify output library name\n");
    fprintf(stderr, "  files...        Object files to add (create mode)\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  /list           List library contents\n");
    fprintf(stderr, "  /extract:name   Extract member from library\n");
    fprintf(stderr, "  /remove:name    Remove member from library\n");
    fprintf(stderr, "  /verbose        Verbose output\n");
    fprintf(stderr, "  /machine:type   Target machine: x86, x64\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s /out:mylib.lib obj1.obj obj2.obj\n", prog);
    fprintf(stderr, "  %s /out:mylib.lib /list\n", prog);
    fprintf(stderr, "  %s /out:mylib.lib /extract:obj1.obj\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    memset(&g_state, 0, sizeof(g_state));
    strcpy(g_state.output_name, "a.lib");

    int i = 1;
    int mode = 0; /* 0 = create, 1 = list, 2 = extract, 3 = remove */

    /* Parse options */
    while (i < argc) {
        const char *arg = argv[i];

        if (strncmp(arg, "/out:", 5) == 0 ||
            strncmp(arg, "-out:", 5) == 0) {
            strncpy(g_state.output_name, arg + 5, 255);
            g_state.output_name[255] = '\0';
            i++;
        } else if (strcmp(arg, "/list") == 0 ||
                   strcmp(arg, "-list") == 0 ||
                   strcmp(arg, "/t") == 0) {
            mode = 1;
            i++;
        } else if (strncmp(arg, "/extract:", 9) == 0 ||
                   strncmp(arg, "-extract:", 9) == 0) {
            mode = 2;
            i++;
        } else if (strncmp(arg, "/remove:", 8) == 0 ||
                   strncmp(arg, "-remove:", 8) == 0) {
            mode = 3;
            i++;
        } else if (strcmp(arg, "/verbose") == 0 ||
                   strcmp(arg, "-verbose") == 0) {
            g_state.verbose = 1;
            i++;
        } else if (arg[0] != '/' && arg[0] != '-') {
            break;
        } else {
            i++;
        }
    }

    /* Execute command */
    int result = 0;
    switch (mode) {
        case 0:
            result = cmd_create(argc, argv, &i);
            break;
        case 1:
            result = cmd_list(argc, argv, &i);
            break;
        case 2:
            result = cmd_extract(argc, argv, &i);
            break;
        case 3:
            result = cmd_remove(argc, argv, &i);
            break;
    }

    if (result) {
        printf("\nSuccess!\n");
        return 0;
    } else {
        printf("\nFailed!\n");
        return 1;
    }
}
