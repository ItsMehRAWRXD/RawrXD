//=============================================================================
// RawrXD_Compression.hpp - C++ Interface for MASM Compression
// Zero-dependency checkpoint compression
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

// Extern "C" linkage for MASM functions
extern "C" {

    //=============================================================================
    // Compression Functions
    //=============================================================================
    
    /// Compress data using fast LZ4-style algorithm
    /// @param src Source buffer
    /// @param srcLen Source length in bytes
    /// @param dst Destination buffer
    /// @param dstMaxLen Maximum destination length
    /// @return Compressed size, or 0 if compression failed
    size_t RawrXD_Compress(
        const void* src,
        size_t srcLen,
        void* dst,
        size_t dstMaxLen
    );
    
    /// Decompress data
    /// @param src Source buffer (compressed)
    /// @param srcLen Source length in bytes
    /// @param dst Destination buffer
    /// @param dstMaxLen Maximum destination length
    /// @return Decompressed size, or 0 if decompression failed
    size_t RawrXD_Decompress(
        const void* src,
        size_t srcLen,
        void* dst,
        size_t dstMaxLen
    );
    
    /// Calculate maximum compressed size for given input
    /// @param inputSize Input size in bytes
    /// @return Maximum possible compressed size
    size_t RawrXD_Compression_GetMaxSize(size_t inputSize);
    
    /// Initialize compression library
    /// @param level Compression level (1-9, currently ignored)
    /// @return 0 on success
    int RawrXD_Compression_Init(int level);
    
    /// Get compression library version
    /// @return Version number (major << 24 | minor << 16 | patch << 8 | build)
    uint32_t RawrXD_Compression_Version();

} // extern "C"

namespace RawrXD {
namespace Compression {

    //=============================================================================
    // C++ Wrapper Class
    //=============================================================================
    
    class Compressor {
    public:
        Compressor() = default;
        ~Compressor() = default;
        
        // Disable copy/move
        Compressor(const Compressor&) = delete;
        Compressor& operator=(const Compressor&) = delete;
        Compressor(Compressor&&) = delete;
        Compressor& operator=(Compressor&&) = delete;
        
        /// Compress data
        /// @return Compressed size, or 0 on failure
        static size_t Compress(
            const void* src,
            size_t srcLen,
            void* dst,
            size_t dstMaxLen
        ) {
            return RawrXD_Compress(src, srcLen, dst, dstMaxLen);
        }
        
        /// Decompress data
        /// @return Decompressed size, or 0 on failure
        static size_t Decompress(
            const void* src,
            size_t srcLen,
            void* dst,
            size_t dstMaxLen
        ) {
            return RawrXD_Decompress(src, srcLen, dst, dstMaxLen);
        }
        
        /// Get maximum compressed size for input
        static size_t GetMaxCompressedSize(size_t inputSize) {
            return RawrXD_Compression_GetMaxSize(inputSize);
        }
        
        /// Initialize compression
        static bool Initialize(int level = 1) {
            return RawrXD_Compression_Init(level) == 0;
        }
        
        /// Get version
        static uint32_t GetVersion() {
            return RawrXD_Compression_Version();
        }
    };
    
    //=============================================================================
    // Helper Functions
    //=============================================================================
    
    /// Compress with automatic buffer allocation
    /// @param src Source data
    /// @param srcLen Source length
    /// @param compressedSize Output: compressed size
    /// @return Allocated buffer containing compressed data (caller must free with delete[])
    inline uint8_t* CompressBuffer(
        const void* src,
        size_t srcLen,
        size_t& compressedSize
    ) {
        size_t maxSize = Compressor::GetMaxCompressedSize(srcLen);
        uint8_t* dst = new uint8_t[maxSize];
        
        compressedSize = Compressor::Compress(src, srcLen, dst, maxSize);
        if (compressedSize == 0) {
            delete[] dst;
            return nullptr;
        }
        
        return dst;
    }
    
    /// Decompress with automatic buffer allocation
    /// @param src Compressed data
    /// @param srcLen Compressed length
    /// @param decompressedSize Output: decompressed size
    /// @return Allocated buffer containing decompressed data (caller must free with delete[])
    inline uint8_t* DecompressBuffer(
        const void* src,
        size_t srcLen,
        size_t& decompressedSize
    ) {
        // Read header to get original size
        if (srcLen < 16) return nullptr;
        
        const uint8_t* header = static_cast<const uint8_t*>(src);
        size_t originalSize = *reinterpret_cast<const size_t*>(header);
        
        uint8_t* dst = new uint8_t[originalSize];
        
        decompressedSize = Compressor::Decompress(src, srcLen, dst, originalSize);
        if (decompressedSize == 0) {
            delete[] dst;
            return nullptr;
        }
        
        return dst;
    }

} // namespace Compression
} // namespace RawrXD
