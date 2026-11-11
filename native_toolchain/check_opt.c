#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} OPTIONAL_HEADER_64;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} DATA_DIRECTORY;
#pragma pack(pop)

int main() {
    printf("sizeof(OPTIONAL_HEADER_64) = %zu\n", sizeof(OPTIONAL_HEADER_64));
    printf("sizeof(DATA_DIRECTORY) = %zu\n", sizeof(DATA_DIRECTORY));
    printf("sizeof(DATA_DIRECTORY) * 16 = %zu\n", sizeof(DATA_DIRECTORY) * 16);
    printf("Total optional header size = %zu\n", sizeof(OPTIONAL_HEADER_64) + sizeof(DATA_DIRECTORY) * 16);
    printf("offsetof(Magic) = %zu\n", offsetof(OPTIONAL_HEADER_64, Magic));
    printf("offsetof(ImageBase) = %zu\n", offsetof(OPTIONAL_HEADER_64, ImageBase));
    printf("offsetof(Subsystem) = %zu\n", offsetof(OPTIONAL_HEADER_64, Subsystem));
    return 0;
}
