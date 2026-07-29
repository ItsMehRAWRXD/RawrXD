// src/direct_io/burstc_main.cpp
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <cstdint>

<<<<<<< HEAD
// burstc (metadata JSON parser excluded for zero-dep simplicity)
=======
// Simplified burstc (metadata JSON parser excluded for zero-dep simplicity)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
// Appends rawrxd.burst.plan to GGUF

int main(int argc, char** argv) {
    if (argc < 3) {
        
        return 1;
    }

    const char* gguf_path = argv[1];
    const char* profile_path = argv[2];

    std::ifstream profile_in(profile_path);
    std::vector<uint32_t> ids;
    uint32_t id;
    while (profile_in >> id) ids.push_back(id);

    std::ofstream out(gguf_path, std::ios::binary | std::ios::app);
    if (!out) {
        
        return 1;
    }

    std::string key = "rawrxd.burst.plan";
    uint32_t type = 0x10000004; // GGUF_ARRAY | UINT32
    uint32_t count = (uint32_t)ids.size();

    out.write(key.c_str(), key.size() + 1);
    out.write(reinterpret_cast<const char*>(&type), 4);
    out.write(reinterpret_cast<const char*>(&count), 4);
    for (uint32_t val : ids) {
        out.write(reinterpret_cast<const char*>(&val), 4);
    }


    return 0;
}
