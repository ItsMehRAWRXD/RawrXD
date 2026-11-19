#pragma once
#include <string>
#include <vector>
#include <cstdint>

// ELF writer stub
namespace MASM {
class ElfWriter {
public:
    bool Write(const std::string& path, const std::vector<uint8_t>& data) {
        return false;
    }
};
}