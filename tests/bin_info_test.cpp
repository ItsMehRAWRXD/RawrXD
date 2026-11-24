// =============================================================================
// bin_info_test.cpp — R1 certification: ELF64/Mach-O/PE headers parse.
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "reverse_engineering/binary_loaders.h"

static void WriteFile(const std::string& path, const std::vector<uint8_t>& b) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(b.data()), b.size());
}

int main() {
    int failures = 0;
    const std::string tmp = getenv("TEMP") ? getenv("TEMP") : ".";
    rawrxd::re::BinaryLoader loader;
    rawrxd::re::BinaryInfo info;

    // Minimal ELF64: magic, class 2, little-endian, machine x86-64, entry.
    {
        std::vector<uint8_t> b(64, 0);
        b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
        b[4] = 2; b[5] = 1;
        b[18] = 0x3e;  // EM_X86_64
        const uint64_t entry = 0x401000;
        std::memcpy(b.data() + 24, &entry, 8);
        const std::string p = tmp + "/bin_info_test.elf";
        WriteFile(p, b);
        if (!loader.Load(p, info) || info.format != rawrxd::re::BinaryFormat::Elf64 ||
            info.arch != "x86-64" || info.entry != 0x401000) {
            std::printf("[FAIL] ELF64 parse\n");
            ++failures;
        }
    }
    // Minimal Mach-O 64: magic feedfacf, cputype x86-64, entry, ncmds=0.
    {
        std::vector<uint8_t> b(32, 0);
        b[0] = 0xcf; b[1] = 0xfa; b[2] = 0xed; b[3] = 0xfe;
        const uint32_t cpu = 0x01000007;
        std::memcpy(b.data() + 4, &cpu, 4);
        const uint64_t entry = 0x100000000ull;
        std::memcpy(b.data() + 8, &entry, 8);
        const std::string p = tmp + "/bin_info_test.macho";
        WriteFile(p, b);
        if (!loader.Load(p, info) || info.format != rawrxd::re::BinaryFormat::MachO64 ||
            info.arch != "x86-64" || info.entry != 0x100000000ull) {
            std::printf("[FAIL] Mach-O parse\n");
            ++failures;
        }
    }
    // Minimal PE: MZ + e_lfanew 0x80 + machine 0x8664.
    {
        std::vector<uint8_t> b(0x100, 0);
        b[0] = 'M'; b[1] = 'Z';
        b[0x3c] = 0x80;
        b[0x80 + 4] = 0x64; b[0x80 + 5] = 0x86;  // IMAGE_FILE_MACHINE_AMD64
        const std::string p = tmp + "/bin_info_test.exe";
        WriteFile(p, b);
        if (!loader.Load(p, info) || info.format != rawrxd::re::BinaryFormat::Pe ||
            info.arch != "x86-64") {
            std::printf("[FAIL] PE parse\n");
            ++failures;
        }
    }
    std::printf("bin_info_test: failures=%d\n", failures);
    std::printf("BIN_INFO_TEST %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}