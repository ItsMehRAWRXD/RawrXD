#pragma once
#include <cstdint>
#include <string>

// GGUF metadata probe - reads the real GGUF container header.
//
// This authority parses the file. It reports what the bytes say. A file that
// is not GGUF yields valid == false and no fabricated fields.

namespace rawrxd::models
{
    // Everything the header walk can actually recover.
    struct GgufInfo {
        bool        valid          = false;
        uint32_t    version        = 0;
        uint64_t    tensorCount    = 0;
        uint64_t    metadataKvCount= 0;
        std::string architecture;    // general.architecture
        std::string name;           // general.name
        std::string quantization;   // general.file_type (ggml ftype enum), or
                                    // file_type.{arch}.quantization_type
        uint32_t    fileType        = 0;      // raw general.file_type value
        uint64_t    fileSizeBytes   = 0;
        std::string error;          // why parsing stopped, when it did
    };

    // Read the header of a GGUF file. Reads only the header region, so this
    // is cheap regardless of model size.
    GgufInfo probeGgufFile(const std::string& path);

    // Probe and remember the result for the legacy accessors below.
    void probeGgufMetadata(const std::string& modelPath);
    void probeAllGgufMetadata();

    int         getGgufVersion();
    std::string getGgufArch();
    std::string getGgufName();
    std::string getQuantization();
    uint64_t    getFileSizeBytes();

    void writeGgufMetadataProbeReceipt();
}
