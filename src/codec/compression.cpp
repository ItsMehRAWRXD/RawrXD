#include "codec/compression.h"
<<<<<<< HEAD
#include "codec/brutal_gzip.h"
#include <vector>
=======
#include <zlib.h>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

namespace codec {

std::vector<uint8_t> deflate(const std::vector<uint8_t>& data, bool* success) {
    if (data.empty()) {
        if (success) *success = true;
<<<<<<< HEAD
        return {};
    }
    
    auto result = brutal::compress(data);
    if (success) *success = true;
    return result;
=======
        return std::vector<uint8_t>();
    }
    
    // Use zlib for basic deflate compression
    uLongf compressedSize = compressBound(data.size());
    std::vector<uint8_t> compressed(compressedSize, //Uninitialized);
    
    int result = compress2(reinterpret_cast<Bytef*>(compressed.data()), &compressedSize,
                          reinterpret_cast<const Bytef*>(data.constData()), data.size(),
                          Z_DEFAULT_COMPRESSION);
    
    if (result == Z_OK) {
        compressed.resize(compressedSize);
        if (success) *success = true;
        return compressed;
    } else {
        if (success) *success = false;
        return std::vector<uint8_t>();
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

std::vector<uint8_t> inflate(const std::vector<uint8_t>& data, bool* success) {
    if (data.empty()) {
        if (success) *success = true;
<<<<<<< HEAD
        return {};
    }
    
    auto result = brutal::decompress(data);
    if (success) *success = true;
    return result;
}

}
=======
        return std::vector<uint8_t>();
    }
    
    // Estimate decompressed size (4x compression ratio)
    uLongf decompressedSize = data.size() * 4;
    std::vector<uint8_t> decompressed(decompressedSize, //Uninitialized);
    
    int result = uncompress(reinterpret_cast<Bytef*>(decompressed.data()), &decompressedSize,
                           reinterpret_cast<const Bytef*>(data.constData()), data.size());
    
    if (result == Z_OK) {
        decompressed.resize(decompressedSize);
        if (success) *success = true;
        return decompressed;
    } else {
        // Try with larger buffer if first attempt failed
        decompressedSize = data.size() * 10;
        decompressed.resize(decompressedSize);
        
        result = uncompress(reinterpret_cast<Bytef*>(decompressed.data()), &decompressedSize,
                           reinterpret_cast<const Bytef*>(data.constData()), data.size());
        
        if (result == Z_OK) {
            decompressed.resize(decompressedSize);
            if (success) *success = true;
            return decompressed;
        } else {
            if (success) *success = false;
            return std::vector<uint8_t>();
        }
    }
}

std::vector<uint8_t> deflate_brutal_masm(const std::vector<uint8_t>& data, bool* success) {
    if (data.empty()) {
        if (success) *success = true;
        return std::vector<uint8_t>();
    }
    
    // Maximum compression with zlib (\"brutal\" mode)
    uLongf compressedSize = compressBound(data.size());
    std::vector<uint8_t> compressed(compressedSize, //Uninitialized);
    
    int result = compress2(reinterpret_cast<Bytef*>(compressed.data()), &compressedSize,
                          reinterpret_cast<const Bytef*>(data.constData()), data.size(),
                          Z_BEST_COMPRESSION);  // Level 9
    
    if (result == Z_OK) {
        compressed.resize(compressedSize);
        if (success) *success = true;
    } else {
        if (success) *success = false;
        return std::vector<uint8_t>();
    }
}

} // namespace codec

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
