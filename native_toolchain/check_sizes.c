#include <stdio.h>
#include <stddef.h>

#pragma pack(push, 1)
typedef struct {
    unsigned short e_magic;
    unsigned short e_cblp;
    unsigned short e_cp;
    unsigned short e_crlc;
    unsigned short e_cparhdr;
    unsigned short e_minalloc;
    unsigned short e_maxalloc;
    unsigned short e_ss;
    unsigned short e_sp;
    unsigned short e_csum;
    unsigned short e_ip;
    unsigned short e_cs;
    unsigned short e_lfarlc;
    unsigned short e_ovno;
    unsigned short e_res[4];
    unsigned short e_oemid;
    unsigned short e_oeminfo;
    unsigned short e_res2[10];
    unsigned int e_lfanew;
} DOS_HEADER;
#pragma pack(pop)

int main() {
    printf("sizeof(DOS_HEADER) = %zu\n", sizeof(DOS_HEADER));
    printf("offsetof(e_lfanew) = %zu\n", offsetof(DOS_HEADER, e_lfanew));
    return 0;
}
