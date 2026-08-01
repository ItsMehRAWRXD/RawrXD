#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
} TestHeader;
#pragma pack(pop)

int main() {
    printf("sizeof(TestHeader) = %zu\n", sizeof(TestHeader));
    printf("offsetof(ImageBase) = %zu\n", offsetof(TestHeader, ImageBase));
    printf("offsetof(SectionAlignment) = %zu\n", offsetof(TestHeader, SectionAlignment));
    return 0;
}
