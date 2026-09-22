#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <string>
#include "RGUFFormat.hpp"

namespace rguf {

struct WriterConfig {
    bool encrypt = false;
    uint8_t key[32] = {};
};

class Writer {
public:
    bool pack(const std::string& ggufPath,
              const std::string& rgufPath,
              const WriterConfig& cfg,
              std::string& err);
private:
    bool writeHeader(std::ostream& out, const Header& h, std::string& err);
};

} // namespace rguf
