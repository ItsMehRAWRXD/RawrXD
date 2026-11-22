#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>

int main(int argc, char ** argv) {
    if (argc != 2) {
        std::cerr << "usage: reap-zero-prune-manifest <output.json>\n";
        return 2;
    }
    std::ofstream out(argv[1], std::ios::binary | std::ios::trunc);
    if (!out) return 3;
    out << "{\"schema\":\"RAWRXD_REAP_EXPERT_SELECTION_001\","
           "\"experimental_offline\":true,\"rewrite_authorized\":false,"
           "\"reference_parity_pass\":false,\"zero_prune\":true,"
           "\"layers\":[";
    for (uint32_t layer = 1; layer <= 46; ++layer) {
        if (layer != 1) out << ',';
        out << "{\"layer\":" << layer << ",\"selected\":[";
        for (uint32_t expert = 0; expert < 59; ++expert) {
            if (expert) out << ',';
            out << "{\"expert\":" << expert << "}";
        }
        out << "]}";
    }
    out << "]}\n";
    if (!out.good()) return 4;
    std::cout << "ZERO_PRUNE_MANIFEST layers=46 experts_per_layer=59 private=1\n";
    return 0;
}
