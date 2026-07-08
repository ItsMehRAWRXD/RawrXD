#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#pragma pack(push, 1)
typedef struct {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } LongName;
    } Name;
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} COFF_SYMBOL;
#pragma pack(pop)

int main() {
    printf("sizeof(COFF_SYMBOL) = %zu\n", sizeof(COFF_SYMBOL));
    return 0;
}
