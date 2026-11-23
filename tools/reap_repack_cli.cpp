#include "../src/reap/NativeGGUFPublisher.hpp"
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>

int main(int argc, char** argv) {
    if (argc != 3 && argc != 5) {
        std::cerr << "Usage: rawrxd-reap-repack INPUT.gguf OUTPUT.gguf"
                     " [--max-bytes POSITIVE_INTEGER]\n";
        return 2;
    }
    uint64_t budget = UINT64_MAX;
    if (argc == 5) {
        if (std::string(argv[3]) != "--max-bytes" || !argv[4] ||
            !argv[4][0] || argv[4][0] == '-') {
            std::cerr << "Invalid budget option\n";
            return 2;
        }
        errno = 0;
        char* end = nullptr;
        const unsigned long long value = std::strtoull(argv[4], &end, 10);
        if (errno || !end || *end || !value) {
            std::cerr << "Invalid positive integer budget\n";
            return 2;
        }
        budget = static_cast<uint64_t>(value);
    }
    const auto result = RawrXD::REAP::PublishRepackedGGUF(argv[1], argv[2], budget);
    if (result.error != RawrXD::REAP::PublishError::None) {
        std::cerr << "REAP_REPACK_RESULT=FAIL error="
                  << static_cast<int>(result.error) << " repack_error=" << static_cast<int>(result.repack_error) << "\n";
        return 1;
    }
    std::cout << "REAP_REPACK_RESULT=PASS output=" << argv[2] << "\n";
    return 0;
}
