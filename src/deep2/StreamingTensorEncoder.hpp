#pragma once
// Bounded-memory RWT1 encoder: reads a source tensor by file offset and
// writes each independently compressed block without materializing the tensor.
// C++17, existing zlib only. Output is compatible with StreamingTensorFile.
#include "TensorAwareLossless.hpp"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace rawrxd::weights {
namespace streaming_detail {
inline void write32(std::ostream& out, uint32_t v) {
    char b[4];
    for (int i=0;i<4;++i) b[i]=static_cast<char>((v>>(8*i))&255u);
    if (!out.write(b,4)) throw std::runtime_error("RWT1 write failed");
}
inline void write64(std::ostream& out, uint64_t v) {
    write32(out,static_cast<uint32_t>(v));
    write32(out,static_cast<uint32_t>(v>>32));
}
} // namespace streaming_detail

struct StreamingEncodeStats {
    uint64_t plain_bytes=0;
    uint64_t encoded_bytes=0;
    uint64_t blocks=0;
    uint64_t raw_blocks=0;
    uint64_t zlib_blocks=0;
    uint64_t shuffle_blocks=0;
    uint64_t delta_shuffle_blocks=0;
};

// Input source is a seekable raw tensor region, e.g. a validated GGUF tensor
// offset. The caller owns GGUF parsing, alignment and tensor type metadata.
// Do not write directly over source_path: use a distinct output file.
inline StreamingEncodeStats encode_file_region(
    const std::string& source_path, uint64_t source_offset, uint64_t plain_bytes,
    const std::string& output_path, uint8_t element_bytes=1,
    uint32_t block_size=65536) {
    if (!block_size || block_size>(1u<<24) ||
        (element_bytes!=1 && element_bytes!=2 &&
         element_bytes!=4 && element_bytes!=8))
        throw std::invalid_argument("invalid streaming encoder geometry");
    if (source_path==output_path)
        throw std::invalid_argument("source and output must differ");
    const uint64_t count=plain_bytes/block_size+(plain_bytes%block_size!=0);
    if (count>std::numeric_limits<uint32_t>::max() ||
        source_offset>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
        plain_bytes>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max())-source_offset)
        throw std::length_error("streaming tensor exceeds supported bounds");
    std::ifstream input(source_path,std::ios::binary|std::ios::ate);
    if (!input) throw std::runtime_error("cannot open source tensor");
    const auto end=input.tellg();
    if (end<0 || uint64_t(end)<source_offset ||
        plain_bytes>uint64_t(end)-source_offset)
        throw std::out_of_range("source tensor region outside file");
    input.seekg(static_cast<std::streamoff>(source_offset));
    std::ofstream output(output_path,std::ios::binary|std::ios::trunc);
    if (!output) throw std::runtime_error("cannot create RWT1 output");
    using namespace streaming_detail;
    write32(output,0x31545752u);
    write32(output,1);
    write64(output,plain_bytes);
    write32(output,block_size);
    write32(output,element_bytes);
    write32(output,static_cast<uint32_t>(count));
    std::vector<uint8_t> buffer(block_size);
    StreamingEncodeStats stats;
    stats.plain_bytes=plain_bytes;
    for (uint64_t remaining=plain_bytes;remaining;) {
        const size_t n=static_cast<size_t>(std::min<uint64_t>(remaining,block_size));
        if (!input.read(reinterpret_cast<char*>(buffer.data()),
                        static_cast<std::streamsize>(n)))
            throw std::runtime_error("short source tensor read");
        Tensor t=encode(buffer.data(),n,element_bytes,block_size);
        if (t.blocks.size()!=1) throw std::logic_error("invalid streaming block");
        const Block& b=t.blocks.front();
        if (b.payload.size()>std::numeric_limits<uint32_t>::max())
            throw std::length_error("compressed block too large");
        write32(output,static_cast<uint32_t>(b.codec));
        write32(output,b.plain_size);
        write32(output,b.crc32_plain);
        write32(output,static_cast<uint32_t>(b.payload.size()));
        if (!output.write(reinterpret_cast<const char*>(b.payload.data()),
                          static_cast<std::streamsize>(b.payload.size())))
            throw std::runtime_error("short RWT1 payload write");
        ++stats.blocks;
        switch (b.codec) {
            case BlockCodec::Raw: ++stats.raw_blocks; break;
            case BlockCodec::Zlib: ++stats.zlib_blocks; break;
            case BlockCodec::ByteShuffleZlib: ++stats.shuffle_blocks; break;
            case BlockCodec::DeltaShuffleZlib: ++stats.delta_shuffle_blocks; break;
        }
        remaining-=n;
    }
    output.flush();
    if (!output) throw std::runtime_error("RWT1 flush failed");
    const auto pos=output.tellp();
    if (pos<0) throw std::runtime_error("cannot size RWT1 output");
    stats.encoded_bytes=static_cast<uint64_t>(pos);
    return stats;
}
} // namespace rawrxd::weights
