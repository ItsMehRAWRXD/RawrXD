// ============================================================================
// pdb_gsi_hash.h — Phase 29.2: GSI Hash Table + TPI Type Parser
// ============================================================================
// Recovered declaration header for src/core/pdb_gsi_hash.cpp (the original
// header was lost; CMake excluded the TU with "missing pdb_gsi_hash.h").
// Declarations are reconstructed 1:1 from the definitions in
// pdb_gsi_hash.cpp and the consumption sites in pdb_native.cpp
// (parsePublicSymbolStream / unload / findSymbolByRVA paths).
//
// Layout facts encoded here (Microsoft MSF/PDB public formats):
//   GSIHashHeader  = 16 bytes: verHdr(4) verSignature(4) hrSize(4) verAux(4)
//   GSIHashRecord  = 8 bytes (symOffset:4, cref:4) — only symOffset used
//   TPIStreamHeader= 56 bytes (version 20040203, typeIndexMin/Max,
//                    typeRecordBytes, headerSize...)
//   IPHR_HASH      = 4096 buckets, GSI_BUCKET_BITMAP_WORDS = 128
//   GSI_HASH_RECORD_SIZE = 8
// ============================================================================

#pragma once

#include "pdb_native.h"

#include <cstdint>

namespace RawrXD {
namespace PDB {

// ============================================================================
// GSI constants (Microsoft public symbol hash stream)
// ============================================================================

// Bucket count: 4096 (Microsoft IPHR hash table size).
constexpr uint32_t IPHR_HASH = 4096;

// Size of one GSIHashRecord in the hash record array.
constexpr uint32_t GSI_HASH_RECORD_SIZE = 8;

// Bitmap words covering the 4096 buckets (4096 / 32).
constexpr uint32_t GSI_BUCKET_BITMAP_WORDS = 128;

// GSI hash header signature ('GSIF' family) and v7.00 version tag.
// The header carries verSignature = 0xFFFFFFFF and verHdr = 0x0700 for
// the v7.00 layout; legacy streams without the new-style header are
// rejected by parse() (fail-closed) rather than misparsed.
constexpr uint32_t GSI_HASH_SIGNATURE = 0xFFFFFFFF;
constexpr uint32_t GSI_HASH_V70       = 0x0700;

// ============================================================================
// Raw stream structures
// ============================================================================

#pragma pack(push, 1)

// 16-byte GSI hash stream header.
struct GSIHashHeader {
    uint32_t verHdr;        // GSI_HASH_V70 for the new-style header
    uint32_t verSignature;  // GSI_HASH_SIGNATURE for the new-style header
    uint32_t hrSize;        // Byte size of the hash record array
    uint32_t verAux;        // Secondary signature / aux version
};
static_assert(sizeof(GSIHashHeader) == 16, "GSIHashHeader must be 16 bytes");

// 8-byte hash record (fixed size, GSI_HASH_RECORD_SIZE).
struct GSIHashRecord {
    uint32_t symbolOffset;  // Byte offset of the CV record in the symbol stream
    uint32_t cref;          // Reference count (unused by this parser)
};
static_assert(sizeof(GSIHashRecord) == GSI_HASH_RECORD_SIZE,
              "GSIHashRecord must be 8 bytes");

// 56-byte TPI stream header (MSF stream 2).
struct TPIStreamHeader {
    // Fields as consumed by parse() in pdb_gsi_hash.cpp. headerSize (u16) is
    // promoted to 32-bit when used as the data start offset.
    uint16_t  headerSize;       // 56
    uint16_t  reserved;
    uint32_t  version;          // 20040203 for VC7
    uint32_t  headerSize32;     // duplicate 32-bit size field (on-disk layout)
    uint32_t  typeIndexMin;     // First type index (inclusive)
    uint32_t  typeIndexMax;     // End type index (exclusive)
    uint32_t  typeRecordBytes;  // Bytes of the record block (gprec)
    uint32_t  reserved2;
    uint8_t   tail[56 - 28];    // Pad the header to exactly 56 bytes
};
static_assert(sizeof(TPIStreamHeader) == 56, "TPIStreamHeader must be 56 bytes");
// CV calling-convention constants used by callConvName().
enum CVCallConvention : uint8_t {
    CV_CALL_NEAR_C     = 0x00,
    CV_CALL_NEAR_PASCAL= 0x01,
    CV_CALL_NEAR_FAST  = 0x02,
    CV_CALL_NEAR_SYS   = 0x03,
    CV_CALL_NEAR_STD   = 0x04,
    CV_CALL_NEAR_FAR   = 0x05,
    CV_CALL_FAR_C      = 0x09,
    CV_CALL_THISCALL   = 0x0B,
    CV_CALL_CLRCALL    = 0x10,
};

// CV leaf constants used by the TPI parser.
constexpr uint16_t LF_PROCEDURE = 0x1008;
constexpr uint16_t LF_MFUNCTION = 0x1009;
constexpr uint16_t LF_ARGLIST   = 0x1201;

// LF_PROCEDURE record layout (subset consumed by formatProcedureType).
struct CVTypeProcedure {
    uint16_t recLen;        // Size of data after this field
    uint16_t leafKind;      // LF_PROCEDURE
    uint32_t returnType;    // Type index of the return type
    uint8_t  callConv;      // CV calling convention
    uint8_t  reserved;
    uint16_t paramCount;    // Number of parameters
    uint32_t argListType;   // Type index of the LF_ARGLIST record
};

// LF_ARGLIST record layout (subset consumed by formatProcedureType).
struct CVTypeArgList {
    uint16_t recLen;        // Size of data after this field
    uint16_t leafKind;      // LF_ARGLIST
    uint32_t count;         // Number of argument type indices
    // uint32_t types[count]; — variable tail, not needed here
};

// ============================================================================
// GSIHashTable — O(1) public symbol lookup via Microsoft's GSI hash
// ============================================================================

// Visitor for walkBucket: (symbolOffset, indexInBucket, userData) -> continue?
using BucketVisitor = bool(*)(uint32_t symbolOffset, uint32_t index, void* userData);

class GSIHashTable {
public:
    GSIHashTable();
    ~GSIHashTable();

    // Parse the GSI hash stream. symbolStream/symbolStreamSize back the
    // name-verification reads (records only carry offsets).
    PDBResult parse(const uint8_t* streamData, uint32_t streamSize,
                    const uint8_t* symbolStream, uint32_t symbolStreamSize);

    // Microsoft PDB name hash (bucket index, case-insensitive).
    uint32_t hashName(const char* name, uint32_t nameLen);

    // O(1) amortized lookup: returns the symbol-stream offset of the CV
    // record for `name`, or UINT32_MAX when not present.
    uint32_t findSymbolOffset(const char* name, uint32_t nameLen) const;

    // Verify the name stored at a symbol offset matches (case-insensitive).
    bool verifySymbolName(uint32_t symbolOffset, const char* name,
                          uint32_t nameLen) const;

    // Bucket enumeration for diagnostics.
    void walkBucket(uint32_t bucketIndex, BucketVisitor visitor,
                    void* userData) const;

    // Population diagnostics.
    float getLoadFactor() const;
    uint32_t getRecordCount() const { return m_numRecords; }
    uint32_t getUsedBuckets() const { return m_usedBuckets; }

private:
    static uint32_t popcount32(uint32_t v);

    struct Bucket {
        uint32_t startIndex = 0;
        uint32_t count      = 0;
    };

    GSIHashRecord* m_records = nullptr;
    uint32_t       m_numRecords = 0;
    uint32_t       m_usedBuckets = 0;
    Bucket         m_buckets[IPHR_HASH];
    const uint8_t* m_symbolStream = nullptr;
    uint32_t       m_symbolStreamSize = 0;
    bool           m_valid = false;


};

// ============================================================================
// TPIStreamParser — Type record resolver for function signatures
// ============================================================================

class TPIStreamParser {
public:
    TPIStreamParser();
    ~TPIStreamParser();

    // Parse the TPI stream (stream 2 in the standard MSF layout).
    PDBResult parse(const uint8_t* streamData, uint32_t streamSize);

    // O(1) type record access by type index. Returns the leaf data pointer
    // (after recLen/leafKind), or nullptr for unknown/invalid indices.
    const uint8_t* getTypeRecord(uint32_t typeIndex, uint16_t* leafKindOut,
                                 uint32_t* recordSizeOut) const;

    // Human-readable calling convention name.
    const char* callConvName(uint8_t cc) const;

    // Build a human-readable signature for an LF_PROCEDURE index.
    PDBResult formatProcedureType(uint32_t typeIndex, char* out,
                                  uint32_t maxLen) const;

    // Diagnostics getters (consumed by pdb_native.cpp log lines).
    uint32_t getTypeCount() const { return m_valid ? (m_tiMax - m_tiMin) : 0; }
    uint32_t getTypeIndexMin() const { return m_tiMin; }
    uint32_t getTypeIndexMax() const { return m_tiMax; }
    bool isValid() const { return m_valid; }

private:
    uint32_t*     m_offsets = nullptr;   // Offset of each type record in m_data
    uint8_t*      m_data = nullptr;      // Type record bytes
    uint32_t      m_dataSize = 0;
    uint32_t      m_tiMin = 0;
    uint32_t      m_tiMax = 0;
    bool          m_valid = false;
};

} // namespace PDB
} // namespace RawrXD
