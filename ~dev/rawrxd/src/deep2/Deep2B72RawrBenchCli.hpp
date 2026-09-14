#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {

struct B72BenchOptions {
    bool valid = false;
    bool showHelp = false;
    bool useContract = false;
    bool json = false;
    bool quiet = false;
    std::string model;
    std::string contractName;
    std::string prompt = "Introduce yourself in under 99 words.";
    std::string evidenceDir = "evidence";
    uint32_t tokens = 384;
    uint32_t warmupTokens = 32;
};

class B72RawrBenchCli {
public:
    static B72BenchOptions parse(const std::vector<std::string>&) noexcept;
    static std::string usage();
};

} // namespace Deep2
