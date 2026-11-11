#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static bool load(const char* path, std::vector<int64_t>& out) {
    std::ifstream f(path);
    if (!f) return false;
    int64_t v = 0;
    while (f >> v) out.push_back(v);
    return !out.empty();
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: token_sequence_parity deep2_ids.txt reference_ids.txt\n";
        return 64;
    }
    std::vector<int64_t> a, b;
    if (!load(argv[1], a) || !load(argv[2], b)) {
        std::cerr << "TOKEN_FILE_READ=FAIL\n";
        return 65;
    }

    const size_t n = a.size() < b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) {
            std::cout << "FIRST_TOKEN_DIFF=" << i
                      << " deep2=" << a[i]
                      << " ref=" << b[i] << "\n";
            std::cout << "MULTITOKEN_PARITY=FAIL\n";
            return 1;
        }
    }
    if (a.size() != b.size()) {
        std::cout << "FIRST_TOKEN_DIFF=" << n << " length_mismatch=1"
                  << " deep2_count=" << a.size()
                  << " ref_count=" << b.size() << "\n";
        std::cout << "MULTITOKEN_PARITY=FAIL\n";
        return 1;
    }

    std::cout << "TOKEN_COUNT=" << a.size() << "\n";
    std::cout << "MULTITOKEN_PARITY=PASS\n";
    return 0;
}
