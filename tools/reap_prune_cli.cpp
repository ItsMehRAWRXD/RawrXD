// R04 real-model CLI: native expert pruning over a real MoE GGUF.
// Usage: reap_prune_cli <input.gguf> <output.gguf> <keep_ratio>
// Streams; loads only router rows. Reports selection, savings, and error.
#include "reap/NativeExpertPruner.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace RawrXD::REAP;

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: %s <input.gguf> <output.gguf> <keep_ratio>\n", argv[0]);
        return 2;
    }
    const std::string input = argv[1];
    const std::string output = argv[2];
    const double keep = std::atof(argv[3]);
    PruneRequest req;
    req.keep_ratio = keep;
    PruneReport rep;
    const PruneError err = PruneGGUF(input, output, req, rep);
    static const char* kName[] = {"None","Input","Format","Unsupported","Overflow","Output","NoExperts"};
    std::printf("R04_REAL err=%d (%s) layers=%zu input=%llu output=%llu saved=%llu removed=%llu\n",
                (int)err, kName[(int)err], rep.layers.size(),
                (unsigned long long)rep.input_bytes, (unsigned long long)rep.output_bytes,
                (unsigned long long)rep.bytes_saved, (unsigned long long)rep.experts_removed);
    for (const auto& l : rep.layers) {
        std::printf("  %-40s experts=%u->%u kept=", l.tensor.c_str(), l.experts_before, l.experts_after);
        for (size_t i = 0; i < l.kept.size(); ++i) std::printf("%s%u", i ? "," : "", l.kept[i]);
        std::printf("  bytes=%llu->%llu\n",
                    (unsigned long long)l.bytes_before, (unsigned long long)l.bytes_after);
    }
    std::fflush(stdout);
    return err == PruneError::None ? 0 : 1;
}