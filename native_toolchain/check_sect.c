#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SECTION_HEADER;
#pragma pack(pop)

int main() {
    printf("sizeof(SECTION_HEADER) = %zu\n", sizeof(SECTION_HEADER));
    return 0;
}
