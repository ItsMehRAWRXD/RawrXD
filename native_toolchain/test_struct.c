#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

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

int main() {
    printf("sizeof(COFF_SYMBOL) = %zu\n", sizeof(COFF_SYMBOL));
    printf("offsetof(Name) = %zu\n", offsetof(COFF_SYMBOL, Name));
    printf("offsetof(Value) = %zu\n", offsetof(COFF_SYMBOL, Value));
    printf("offsetof(SectionNumber) = %zu\n", offsetof(COFF_SYMBOL, SectionNumber));
    printf("offsetof(Type) = %zu\n", offsetof(COFF_SYMBOL, Type));
    printf("offsetof(StorageClass) = %zu\n", offsetof(COFF_SYMBOL, StorageClass));
    printf("offsetof(NumberOfAuxSymbols) = %zu\n", offsetof(COFF_SYMBOL, NumberOfAuxSymbols));
    return 0;
}
