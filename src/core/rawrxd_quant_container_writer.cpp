#include "rawrxd_quant_container_writer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace RawrXD {
namespace Core {
namespace {

static uint64_t fnv1a64(const std::string& s) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

static bool range_writeable(uint64_t off, uint64_t size, uint64_t total) {
    return off <= total && size <= (total - off);
}

} // namespace

PatchResult WriteRawrXDQuantContainer(const std::string& output_path,
                                      const std::vector<RawrXDQuantTensorWriteSpec>& tensors,
                                      const RawrXDQuantWriteOptions& options) {
    if (tensors.empty()) {
        return PatchResult::error("RXQF writer: no tensors provided", -1);
    }
    if (!RawrXDQuantIsPowerOfTwo(options.global_alignment) || options.global_alignment < 8) {
        return PatchResult::error("RXQF writer: global_alignment must be power-of-two >= 8", -2);
    }

    RawrXDQuantFileHeader hdr{};
    hdr.magic = RAWRXD_QUANT_MAGIC;
    hdr.version = RAWRXD_QUANT_VERSION_1;
    hdr.endianness = 0;
    hdr.header_bytes = static_cast<uint32_t>(sizeof(RawrXDQuantFileHeader));
    hdr.descriptor_bytes = static_cast<uint32_t>(sizeof(RawrXDQuantTensorDescriptor));
    hdr.tensor_count = static_cast<uint64_t>(tensors.size());
    hdr.chunk_count = hdr.tensor_count;
    hdr.global_alignment = options.global_alignment;
    hdr.model_crc64 = options.model_crc64;

    std::vector<RawrXDQuantTensorDescriptor> descs(tensors.size());
    std::vector<RawrXDQuantShapeRecord> shapes(tensors.size());

    uint64_t cursor = RawrXDQuantAlignUp(sizeof(RawrXDQuantFileHeader), options.global_alignment);
    hdr.descriptor_table_offset = cursor;

    cursor += static_cast<uint64_t>(descs.size()) * sizeof(RawrXDQuantTensorDescriptor);
    cursor = RawrXDQuantAlignUp(cursor, options.global_alignment);

    hdr.shape_table_offset = cursor;
    hdr.shape_bytes = static_cast<uint32_t>(shapes.size() * sizeof(RawrXDQuantShapeRecord));

    cursor += hdr.shape_bytes;
    cursor = RawrXDQuantAlignUp(cursor, options.global_alignment);

    uint64_t names_offset = 0;
    uint64_t names_bytes = 0;
    if (options.emit_name_table) {
        names_offset = cursor;
        names_bytes = sizeof(RawrXDQuantNameTableHeader);
        for (const auto& t : tensors) {
            if (t.name.empty()) {
                return PatchResult::error("RXQF writer: tensor name empty while emit_name_table is enabled", -3);
            }
            if (t.name.size() > 255) {
                return PatchResult::error("RXQF writer: tensor name exceeds 255 bytes", -4);
            }
            names_bytes += sizeof(uint16_t) + static_cast<uint64_t>(t.name.size());
        }
        cursor += names_bytes;
        cursor = RawrXDQuantAlignUp(cursor, options.global_alignment);
    }

    hdr.payload_offset = cursor;

    uint64_t payload_cursor = hdr.payload_offset;

    for (size_t i = 0; i < tensors.size(); ++i) {
        const auto& in = tensors[i];
        auto& out = descs[i];
        auto& sh = shapes[i];

        if (in.quant_mode < RAWRXD_QUANT_FILE_FP16 || in.quant_mode > RAWRXD_QUANT_FILE_INT4_NF) {
            return PatchResult::error("RXQF writer: invalid quant_mode", -5);
        }
        if (!RawrXDQuantIsPowerOfTwo(in.alignment) || in.alignment == 0 || in.alignment > options.global_alignment) {
            return PatchResult::error("RXQF writer: invalid per-tensor alignment", -6);
        }
        if ((in.flags & RAWRXD_QUANT_FLAG_BLOCK_BASED) && in.block_size == 0) {
            return PatchResult::error("RXQF writer: BLOCK_BASED set but block_size is 0", -7);
        }

        out.name_hash = (in.name_hash != 0) ? in.name_hash : fnv1a64(in.name);
        out.tensor_kind = in.tensor_kind;
        out.quant_mode = in.quant_mode;
        out.block_size = in.block_size;
        out.flags = in.flags;
        out.element_count = in.element_count;
        out.alignment = in.alignment;

        sh.rank = static_cast<uint32_t>(std::min<size_t>(in.dims.size(), 8));
        sh.reserved0 = 0;
        for (uint32_t d = 0; d < sh.rank; ++d) {
            sh.dims[d] = in.dims[d];
        }

        out.shape_offset = static_cast<uint32_t>(i * sizeof(RawrXDQuantShapeRecord));
        out.shape_bytes = static_cast<uint32_t>(sizeof(RawrXDQuantShapeRecord));

        payload_cursor = RawrXDQuantAlignUp(payload_cursor, in.alignment);
        out.payload_offset = payload_cursor;
        out.payload_bytes = static_cast<uint64_t>(in.payload.size());
        payload_cursor += out.payload_bytes;

        if (!in.scales.empty()) {
            out.flags |= RAWRXD_QUANT_FLAG_HAS_SCALE;
            payload_cursor = RawrXDQuantAlignUp(payload_cursor, in.alignment);
            out.scale_offset = payload_cursor;
            out.scale_bytes = static_cast<uint64_t>(in.scales.size());
            payload_cursor += out.scale_bytes;
        }

        if (!in.zero_points.empty()) {
            out.flags |= RAWRXD_QUANT_FLAG_HAS_ZEROPOINT;
            payload_cursor = RawrXDQuantAlignUp(payload_cursor, in.alignment);
            out.zero_point_offset = payload_cursor;
            out.zero_point_bytes = static_cast<uint64_t>(in.zero_points.size());
            payload_cursor += out.zero_point_bytes;
        }
    }

    hdr.payload_bytes = payload_cursor - hdr.payload_offset;
    hdr.reserved0 = names_offset;

    const uint64_t total_size = payload_cursor;
    std::vector<uint8_t> blob(static_cast<size_t>(total_size), 0u);

    if (!range_writeable(0, sizeof(hdr), total_size)) {
        return PatchResult::error("RXQF writer: header range invalid", -8);
    }
    std::memcpy(blob.data(), &hdr, sizeof(hdr));

    if (!range_writeable(hdr.descriptor_table_offset,
                         static_cast<uint64_t>(descs.size()) * sizeof(RawrXDQuantTensorDescriptor),
                         total_size)) {
        return PatchResult::error("RXQF writer: descriptor table range invalid", -9);
    }
    std::memcpy(blob.data() + hdr.descriptor_table_offset, descs.data(),
                descs.size() * sizeof(RawrXDQuantTensorDescriptor));

    if (!range_writeable(hdr.shape_table_offset, hdr.shape_bytes, total_size)) {
        return PatchResult::error("RXQF writer: shape table range invalid", -10);
    }
    std::memcpy(blob.data() + hdr.shape_table_offset, shapes.data(),
                shapes.size() * sizeof(RawrXDQuantShapeRecord));

    if (options.emit_name_table) {
        RawrXDQuantNameTableHeader nh{};
        nh.magic = RAWRXD_QUANT_NAMES_MAGIC;
        nh.version = RAWRXD_QUANT_NAMES_VERSION_1;
        nh.tensor_count = hdr.tensor_count;

        if (!range_writeable(names_offset, sizeof(nh), total_size)) {
            return PatchResult::error("RXQF writer: name table header range invalid", -11);
        }
        std::memcpy(blob.data() + names_offset, &nh, sizeof(nh));

        uint64_t nc = names_offset + sizeof(nh);
        for (const auto& t : tensors) {
            const uint16_t n = static_cast<uint16_t>(t.name.size());
            if (!range_writeable(nc, sizeof(n), total_size)) {
                return PatchResult::error("RXQF writer: name length range invalid", -12);
            }
            std::memcpy(blob.data() + nc, &n, sizeof(n));
            nc += sizeof(n);
            if (!range_writeable(nc, n, total_size)) {
                return PatchResult::error("RXQF writer: name bytes range invalid", -13);
            }
            std::memcpy(blob.data() + nc, t.name.data(), n);
            nc += n;
        }
    }

    for (size_t i = 0; i < tensors.size(); ++i) {
        const auto& in = tensors[i];
        const auto& d = descs[i];

        if (!in.payload.empty()) {
            if (!range_writeable(d.payload_offset, d.payload_bytes, total_size)) {
                return PatchResult::error("RXQF writer: payload range invalid", -14);
            }
            std::memcpy(blob.data() + d.payload_offset, in.payload.data(), in.payload.size());
        }
        if (!in.scales.empty()) {
            if (!range_writeable(d.scale_offset, d.scale_bytes, total_size)) {
                return PatchResult::error("RXQF writer: scale range invalid", -15);
            }
            std::memcpy(blob.data() + d.scale_offset, in.scales.data(), in.scales.size());
        }
        if (!in.zero_points.empty()) {
            if (!range_writeable(d.zero_point_offset, d.zero_point_bytes, total_size)) {
                return PatchResult::error("RXQF writer: zero-point range invalid", -16);
            }
            std::memcpy(blob.data() + d.zero_point_offset, in.zero_points.data(), in.zero_points.size());
        }
    }

    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return PatchResult::error("RXQF writer: failed to open output file", -17);
    }

    out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    if (!out.good()) {
        return PatchResult::error("RXQF writer: failed while writing output", -18);
    }

    return PatchResult::ok("RXQF container written");
}

} // namespace Core
} // namespace RawrXD
