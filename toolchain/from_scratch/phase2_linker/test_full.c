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
    struct { uint32_t VirtualAddress; uint32_t Size; } DataDirectory[16];
} PeOptionalHeader64;
#pragma pack(pop)

int main() {
    printf("sizeof(PeOptionalHeader64) = %zu\n", sizeof(PeOptionalHeader64));
    printf("offsetof(Magic) = %zu (0x%zX)\n", offsetof(PeOptionalHeader64, Magic), offsetof(PeOptionalHeader64, Magic));
    printf("offsetof(AddressOfEntryPoint) = %zu (0x%zX)\n", offsetof(PeOptionalHeader64, AddressOfEntryPoint), offsetof(PeOptionalHeader64, AddressOfEntryPoint));
    printf("offsetof(BaseOfCode) = %zu (0x%zX)\n", offsetof(PeOptionalHeader64, BaseOfCode), offsetof(PeOptionalHeader64, BaseOfCode));
    printf("offsetof(ImageBase) = %zu (0x%zX)\n", offsetof(PeOptionalHeader64, ImageBase), offsetof(PeOptionalHeader64, ImageBase));
    printf("offsetof(SectionAlignment) = %zu (0x%zX)\n", offsetof(PeOptionalHeader64, SectionAlignment), offsetof(PeOptionalHeader64, SectionAlignment));
    printf("offsetof(FileAlignment) = %zu (0x%zX)\n", offsetof(PeOptionalHeader64, FileAlignment), offsetof(PeOptionalHeader64, FileAlignment));
    printf("offsetof(Subsystem) = %zu (0x%zX)\n", offsetof(PeOptionalHeader64, Subsystem), offsetof(PeOptionalHeader64, Subsystem));
    printf("offsetof(DataDirectory) = %zu (0x%zX)\n", offsetof(PeOptionalHeader64, DataDirectory), offsetof(PeOptionalHeader64, DataDirectory));
    return 0;
}
