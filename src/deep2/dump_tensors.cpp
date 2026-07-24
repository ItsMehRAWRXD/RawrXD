// Dump tensor names from a GGUF file
#include "MoEWeightsLoader.hpp"
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <gguf> [filter]\n", argv[0]);
        return 1;
    }
    Deep2::MoEWeightsLoader loader;
    if (!loader.Open(argv[1])) {
        fprintf(stderr, "Failed to open\n");
        return 1;
    }
    const char* filter = (argc > 2) ? argv[2] : nullptr;
    int count = 0;
    int printed = 0;
    for (const auto& t : loader.GetAllTensors()) {
        count++;
        if (filter && t.name.find(filter) == std::string::npos) continue;
        if (printed < 200) {
            fprintf(stderr, "[%4d] %-60s dims=[", count, t.name.c_str());
            for (size_t i = 0; i < t.dimensions.size(); i++) {
                fprintf(stderr, "%llu%s", (unsigned long long)t.dimensions[i],
                         (i + 1 < t.dimensions.size()) ? "," : "");
            }
            fprintf(stderr, "] type=%u\n", (unsigned int)t.type);
            printed++;
        }
    }
    fprintf(stderr, "Total tensors: %d (printed %d)\n", count, printed);
    fprintf(stderr, "Architecture: %s\n", loader.GetArchitecture().c_str());
    loader.Close();
    return 0;
}