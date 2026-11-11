#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>

static void dump_bytes(const char* label, const uint8_t* data, size_t count)
{
    std::cout << label << " (" << count << " bytes):\n";

    std::cout << "Hex:\n";
    for (size_t i = 0; i < count; ++i) {
        if (i % 16 == 0) {
            if (i != 0) std::cout << '\n';
            std::cout << "  ";
        }
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (unsigned)data[i] << ' ';
    }
    std::cout << '\n';

    std::cout << std::dec << "Float32 values:\n";
    size_t floats = count / sizeof(float);
    for (size_t i = 0; i < floats; ++i) {
        float f;
        std::memcpy(&f, data + i * sizeof(float), sizeof(float));
        std::cout << "  [" << i << "] = " << std::setprecision(9) << f << '\n';
    }

    std::cout << '\n';
}

int main()
{
    const char* path = "G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open " << path << '\n';
        return 1;
    }

    constexpr size_t BUF = 64;
    uint8_t buf[BUF];

    // Offset 1: 289996800 (decimal)
    constexpr std::uintmax_t offset1 = 289996800;
    file.clear();
    file.seekg(static_cast<std::streamoff>(offset1), std::ios::beg);
    file.read(reinterpret_cast<char*>(buf), BUF);
    std::streamsize n = file.gcount();
    if (n > 0) {
        std::cout << "Offset 0x" << std::hex << offset1 << " (decimal "
                  << std::dec << offset1 << ")\n";
        dump_bytes("Data", buf, static_cast<size_t>(n));
    } else {
        std::cerr << "No data read at offset 0x" << std::hex << offset1 << '\n';
    }

    // Offset 2: 0 (start of file, output.weight Q6_K)
    file.clear();
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buf), BUF);
    n = file.gcount();
    if (n > 0) {
        std::cout << "Offset 0 (start of file)\n";
        dump_bytes("Data", buf, static_cast<size_t>(n));
    } else {
        std::cerr << "No data read at offset 0\n";
    }

    return 0;
}
