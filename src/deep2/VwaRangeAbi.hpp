#pragma once
#include <stddef.h>

// VWA range ABI.
// Deliberately does NOT mirror VirtualTensorDesc's binary layout.
// Populate this only from an already-audited RMV mount.
//
// No STL. No CRT dependency. Fixed offsets for x64 MASM.
//
// dataAbsOffset:
//   absolute file offset of the first byte of this tensor's data.
//
// tensorByteSize:
//   exact physical tensor payload bytes.
//
// blockBytes:
//   physical bytes per quant block, obtained from the existing certified
//   quant implementation. Do not invent a second GGML type table.
//
// shardId:
//   existing RMV/shard identity.
//
// mountGeneration:
//   existing RMV generation/epoch if available. Zero is permitted when the
//   current mount implementation does not expose one.

extern "C" {

struct VwaMountedPhysical {
    unsigned __int64 dataAbsOffset;      // +00
    unsigned __int64 tensorByteSize;     // +08
    unsigned long    blockBytes;         // +16
    unsigned long    flags;              // +20
    unsigned long    shardId;            // +24
    unsigned long    reserved0;          // +28
    unsigned __int64 mountGeneration;    // +32
};

struct VwaBlockRange {
    unsigned __int64 firstBlock;         // +00
    unsigned __int64 blockCount;         // +08
};

struct VwaPhysicalRange {
    unsigned __int64 absoluteFileOffset; // +00
    unsigned __int64 byteCount;          // +08
    unsigned __int64 tensorRelOffset;    // +16
    unsigned __int64 firstBlock;         // +24
    unsigned __int64 blockCount;         // +32
    unsigned __int64 mountGeneration;    // +40
    unsigned long    shardId;            // +48
    unsigned long    flags;              // +52
};

struct VwaIoBuffer {
    void*            data;               // +00
    unsigned __int64 capacity;           // +08
    unsigned __int64 bytesWritten;       // +16
    unsigned long    win32Error;         // +24
    unsigned long    reserved0;          // +28
};

enum : unsigned long {
    VWA_OK                 = 0,
    VWA_E_NULL             = 1,
    VWA_E_NOT_FILE_BACKED  = 2,
    VWA_E_BAD_GEOMETRY     = 3,
    VWA_E_EMPTY_REQUEST    = 4,
    VWA_E_INTEGER_OVERFLOW = 5,
    VWA_E_OUT_OF_RANGE     = 6,
    VWA_E_BUFFER_TOO_SMALL = 7,
    VWA_E_SEEK_FAILED      = 8,
    VWA_E_READ_FAILED      = 9,
    VWA_E_SHORT_READ       = 10,
    VWA_E_BAD_HANDLE       = 11,
    VWA_E_NOT_OVERLAPPED   = 12,
    VWA_E_TIMEOUT          = 13,
    VWA_E_MISMATCH         = 14
};

enum : unsigned long {
    VWA_PHYS_FILE_BACKED = 0x00000001u
};

// Pure resolver. No I/O. No residency. No tensor lookup.
unsigned long VwaResolveBlocks(
    const VwaMountedPhysical* mounted,
    const VwaBlockRange* requested,
    VwaPhysicalRange* resolved);

// POC/direct fulfillment.
// Uses SetFilePointerEx + synchronous ReadFile on an ALREADY OPEN handle.
// The handle must be dedicated to this request or externally serialized.
unsigned long VwaFulfillExactSync(
    void* shardHandle,
    const VwaPhysicalRange* range,
    VwaIoBuffer* destination);

} // extern "C"

// ABI drift is fatal: MASM uses these exact offsets.
static_assert(sizeof(VwaMountedPhysical) == 40, "VwaMountedPhysical ABI drift");
static_assert(sizeof(VwaBlockRange)      == 16, "VwaBlockRange ABI drift");
static_assert(sizeof(VwaPhysicalRange)   == 56, "VwaPhysicalRange ABI drift");
static_assert(sizeof(VwaIoBuffer)        == 32, "VwaIoBuffer ABI drift");

static_assert(offsetof(VwaMountedPhysical, dataAbsOffset)   == 0);
static_assert(offsetof(VwaMountedPhysical, tensorByteSize)  == 8);
static_assert(offsetof(VwaMountedPhysical, blockBytes)      == 16);
static_assert(offsetof(VwaMountedPhysical, flags)           == 20);
static_assert(offsetof(VwaMountedPhysical, shardId)         == 24);
static_assert(offsetof(VwaMountedPhysical, mountGeneration) == 32);

static_assert(offsetof(VwaPhysicalRange, absoluteFileOffset) == 0);
static_assert(offsetof(VwaPhysicalRange, byteCount)          == 8);
static_assert(offsetof(VwaPhysicalRange, tensorRelOffset)    == 16);
static_assert(offsetof(VwaPhysicalRange, firstBlock)         == 24);
static_assert(offsetof(VwaPhysicalRange, blockCount)         == 32);
static_assert(offsetof(VwaPhysicalRange, mountGeneration)    == 40);
static_assert(offsetof(VwaPhysicalRange, shardId)            == 48);
static_assert(offsetof(VwaPhysicalRange, flags)              == 52);
