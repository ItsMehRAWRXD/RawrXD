#pragma once
#include <string>

namespace RawrXD {
    class RawrXDInference {
    public:
        RawrXDInference();
        ~RawrXDInference();

        bool LoadGGUF(const std::string& path);
        std::string Generate(const std::string& prompt, size_t max_tokens = 4096);
        
        bool IsLoaded() const;

    private:
        void* impl; // Pointer to internal Model
        bool loaded;
    };
}
