#ifndef RAWRXD_QUANT_CONTAINER_H
#define RAWRXD_QUANT_CONTAINER_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ==========================================================================
// RawrXD Quantized Tensor Container
// Flat inside each chunk, chunked at file level.
// ==========================================================================

enum RawrXDQuantFileType : uint32_t
{
    RAWRXD_QUANT_FILE_FP16 = 1,
    RAWRXD_QUANT_FILE_INT8 = 2,
    RAWRXD_QUANT_FILE_INT4 = 3,
    RAWRXD_QUANT_FILE_INT4_NF = 4,
};

enum RawrXDQuantFlags : uint32_t
{
    RAWRXD_QUANT_FLAG_NONE          = 0,
    RAWRXD_QUANT_FLAG_HAS_SCALE     = 1u << 0,
    RAWRXD_QUANT_FLAG_HAS_ZEROPOINT  = 1u << 1,
    RAWRXD_QUANT_FLAG_BLOCK_BASED    = 1u << 2,
    RAWRXD_QUANT_FLAG_SHAPE_INLINE   = 1u << 3,
    RAWRXD_QUANT_FLAG_NAME_HASHED    = 1u << 4,
};

enum RawrXDQuantConstants : uint32_t
{
    RAWRXD_QUANT_MAGIC = 0x46515852u, // 'RXQF' little-endian
    RAWRXD_QUANT_VERSION_1 = 1u,
    RAWRXD_QUANT_NAMES_MAGIC = 0x4D4E5152u, // 'RQNM' little-endian
    RAWRXD_QUANT_NAMES_VERSION_1 = 1u,
};

#pragma pack(push, 1)

struct RawrXDQuantFileHeader
{
    uint32_t magic;             // 'RXQF'
    uint32_t version;           // format version
    uint32_t endianness;        // 0 = little, 1 = big
    uint32_t header_bytes;      // sizeof(RawrXDQuantFileHeader)
    uint32_t descriptor_bytes;   // sizeof(RawrXDQuantTensorDescriptor)
    uint32_t shape_bytes;       // total bytes in shape table
    uint64_t tensor_count;
    uint64_t chunk_count;
    uint64_t global_alignment;
    uint64_t descriptor_table_offset;
    uint64_t shape_table_offset;
    uint64_t payload_offset;
    uint64_t payload_bytes;
    uint64_t model_crc64;
    uint64_t reserved0;         // optional name-table offset (0 = absent)
};

struct RawrXDQuantTensorDescriptor
{
    uint64_t name_hash;
    uint32_t tensor_kind;       // semantic tensor type / layer role
    uint32_t quant_mode;        // RawrXDQuantFileType
    uint32_t block_size;        // elements per quant block, 0 for dense FP16/FP32
    uint32_t flags;             // RawrXDQuantFlags
    uint64_t element_count;
    uint64_t payload_offset;
    uint64_t payload_bytes;
    uint64_t scale_offset;
    uint64_t scale_bytes;
    uint64_t zero_point_offset;
    uint64_t zero_point_bytes;
    uint32_t alignment;
    uint32_t shape_offset;      // offset into shape table
    uint32_t shape_bytes;       // bytes consumed by shape record
    uint32_t reserved0;
};

struct RawrXDQuantShapeRecord
{
    uint32_t rank;
    uint32_t reserved0;
    uint64_t dims[8];
};

struct RawrXDQuantNameTableHeader
{
    uint32_t magic;             // RAWRXD_QUANT_NAMES_MAGIC
    uint32_t version;           // RAWRXD_QUANT_NAMES_VERSION_1
    uint64_t tensor_count;      // must match file header tensor_count
};

#pragma pack(pop)

static inline uint64_t RawrXDQuantAlignUp(uint64_t value, uint64_t alignment)
{
    return (alignment == 0) ? value : ((value + alignment - 1) & ~(alignment - 1));
}

static inline int RawrXDQuantIsPowerOfTwo(uint64_t value)
{
    return value && ((value & (value - 1)) == 0);
}

static inline int RawrXDQuantRangeValid(uint64_t start, uint64_t size, uint64_t file_size)
{
    if (start > file_size)
    {
        return 0;
    }
    if (size > (file_size - start))
    {
        return 0;
    }
    return 1;
}

static inline uint64_t RawrXDQuantElements(const RawrXDQuantShapeRecord* shape)
{
    if (!shape || shape->rank == 0 || shape->rank > 8)
    {
        return 0;
    }

    uint64_t total = 1;
    for (uint32_t i = 0; i < shape->rank; ++i)
    {
        total *= shape->dims[i];
    }
    return total;
}

static inline int RawrXDQuantValidateHeader(const RawrXDQuantFileHeader* h, uint64_t file_size)
{
    if (!h)
    {
        return 0;
    }
    if (h->magic != RAWRXD_QUANT_MAGIC)
    {
        return 0;
    }
    if (h->version != RAWRXD_QUANT_VERSION_1)
    {
        return 0;
    }
    if (h->endianness != 0u)
    {
        return 0;
    }
    if (h->header_bytes != sizeof(RawrXDQuantFileHeader))
    {
        return 0;
    }
    if (h->descriptor_bytes != sizeof(RawrXDQuantTensorDescriptor))
    {
        return 0;
    }
    if (!RawrXDQuantIsPowerOfTwo(h->global_alignment))
    {
        return 0;
    }
    if ((h->descriptor_table_offset % h->global_alignment) != 0)
    {
        return 0;
    }
    if ((h->shape_table_offset % h->global_alignment) != 0)
    {
        return 0;
    }
    if ((h->payload_offset % h->global_alignment) != 0)
    {
        return 0;
    }
    if (!RawrXDQuantRangeValid(h->descriptor_table_offset,
                               h->tensor_count * h->descriptor_bytes,
                               file_size))
    {
        return 0;
    }
    if (!RawrXDQuantRangeValid(h->shape_table_offset, h->shape_bytes, file_size))
    {
        return 0;
    }
    if (!RawrXDQuantRangeValid(h->payload_offset, h->payload_bytes, file_size))
    {
        return 0;
    }

    // Optional name table lives between shape table and payload.
    if (h->reserved0 != 0)
    {
        const uint64_t shapeEnd = h->shape_table_offset + h->shape_bytes;
        if (h->reserved0 < shapeEnd || h->reserved0 >= h->payload_offset)
        {
            return 0;
        }
    }
    return 1;
}

static inline int RawrXDQuantValidateNameTableHeader(const RawrXDQuantFileHeader* h,
                                                     const RawrXDQuantNameTableHeader* nh,
                                                     uint64_t file_size)
{
    if (!h || !nh)
    {
        return 0;
    }
    if (nh->magic != RAWRXD_QUANT_NAMES_MAGIC)
    {
        return 0;
    }
    if (nh->version != RAWRXD_QUANT_NAMES_VERSION_1)
    {
        return 0;
    }
    if (nh->tensor_count != h->tensor_count)
    {
        return 0;
    }
    if (!RawrXDQuantRangeValid(h->reserved0, sizeof(RawrXDQuantNameTableHeader), file_size))
    {
        return 0;
    }
    return 1;
}

static inline int RawrXDQuantValidateDescriptor(const RawrXDQuantFileHeader* h,
                                                const RawrXDQuantTensorDescriptor* d,
                                                uint64_t file_size)
{
    if (!h || !d)
    {
        return 0;
    }
    if (d->quant_mode < RAWRXD_QUANT_FILE_FP16 || d->quant_mode > RAWRXD_QUANT_FILE_INT4_NF)
    {
        return 0;
    }
    if (!RawrXDQuantIsPowerOfTwo(d->alignment))
    {
        return 0;
    }
    if (d->alignment > h->global_alignment)
    {
        return 0;
    }
    if ((d->payload_offset % d->alignment) != 0)
    {
        return 0;
    }
    if (!RawrXDQuantRangeValid(d->payload_offset, d->payload_bytes, file_size))
    {
        return 0;
    }
    if ((d->flags & RAWRXD_QUANT_FLAG_HAS_SCALE) != 0u)
    {
        if (!RawrXDQuantRangeValid(d->scale_offset, d->scale_bytes, file_size))
        {
            return 0;
        }
    }
    if ((d->flags & RAWRXD_QUANT_FLAG_HAS_ZEROPOINT) != 0u)
    {
        if (!RawrXDQuantRangeValid(d->zero_point_offset, d->zero_point_bytes, file_size))
        {
            return 0;
        }
    }
    if ((d->shape_offset + d->shape_bytes) > h->shape_bytes)
    {
        return 0;
    }
    if ((d->flags & RAWRXD_QUANT_FLAG_BLOCK_BASED) != 0u)
    {
        if (d->block_size == 0u)
        {
            return 0;
        }
    }
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif /* RAWRXD_QUANT_CONTAINER_H */
