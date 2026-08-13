#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <cmath>

// ============================================================================
// RawrXD Slingshot Braid Container Format (.sbraid)
// ============================================================================
// Design goals:
//   - Tile-local sparse residuals (no 256× dense plane allocation)
//   - GPU-native consumption without CPU reconstruction
//   - Preserve Pinball telemetry (bounce_pass, earned_bits, scale)
//   - One contiguous file per tensor
//
// Memory model:
//   O(tile_size × residual_count) per tile, not O(tensor_size × 256)
//   For 926M-element tensor @ 64-weight tiles: ~14.5M tiles
//   Base payload: ~14.5M bytes (1 bit per weight)
//   Residuals: sparse, typically <5% density → ~0.7M × 4 bytes = ~2.8 MB
//   Total: ~17.3 MB vs 29.7 GB dense planes = 1700× reduction
// ============================================================================

#pragma pack(push, 1)

// Magic: "SRBD" = Slingshot Residual Braid Descriptor
constexpr char SBRAID_MAGIC[4] = {'S', 'R', 'B', 'D'};
constexpr uint32_t SBRAID_VERSION = 0x00010000;

struct SBraidHeader {
    char     magic[4];           // "SRBD"
    uint32_t version;          // 0x00010000
    uint32_t header_size;        // sizeof(SBraidHeader)
    uint32_t flags;              // Format flags (compression, encryption, etc.)

    uint64_t element_count;     // Total elements in tensor
    uint32_t tile_size;         // Elements per tile (typically 64 for RDNA3 Wave32)
    uint32_t tile_count;        // ceil(element_count / tile_size)

    uint64_t directory_offset;  // Offset to tile directory
    uint64_t payload_offset;    // Offset to first tile payload
    uint64_t payload_size;      // Total payload bytes

    // Pinball telemetry summary
    float    global_scale;      // Global quantization scale
    float    earned_bits;       // Pinball earned precision
    uint16_t max_bounce_pass;   // Maximum bounce pass across all tiles
    uint16_t reserved;
};

struct SBraidTile {
    uint32_t tile_id;          // Sequential tile index

    uint16_t element_count;     // Actual elements in this tile (last tile may be partial)
    uint8_t  base_bits;         // Base plane bit depth (typically 1)
    uint8_t  residual_count;   // Number of residual passes stored (0-255)

    uint16_t bounce_pass;      // Pinball convergence boundary for this tile
    uint16_t flags;             // TILE_FLAG_ATTENTION, TILE_FLAG_SACRED, etc.

    float    scale;             // Tile-local quantization scale
    float    residual_scale;    // Scale for residual deltas

    uint64_t payload_offset;    // File offset to tile payload
    uint32_t payload_size;      // Bytes for this tile's payload
    uint32_t reserved;
};

// Per-element sparse residual descriptor
// Only emitted when residual magnitude exceeds threshold
struct SBraidResidual {
    uint16_t element_index;     // Index within tile (0..tile_size-1)
    uint8_t  pass;              // Which residual pass this belongs to
    uint8_t  flags;             // Sign, magnitude class, etc.
};

#pragma pack(pop)

static_assert(sizeof(SBraidHeader) == 68, "SBraidHeader must be 68 bytes");
static_assert(sizeof(SBraidTile) == 36, "SBraidTile must be 36 bytes");
static_assert(sizeof(SBraidResidual) == 4, "SBraidResidual must be 4 bytes");

// Tile flags
constexpr uint16_t TILE_FLAG_ATTENTION = 0x0001;  // Attention tensor (higher precision floor)
constexpr uint16_t TILE_FLAG_SACRED    = 0x0002;  // Sacred tensor (no bounce until pass N)
constexpr uint16_t TILE_FLAG_BOUNCED   = 0x0004;  // Tile hit convergence boundary
constexpr uint16_t TILE_FLAG_SPARSE    = 0x0008;  // Residuals are sparse (not dense)

// ============================================================================
// Slingshot Braid Emitter
// ============================================================================
class SlingshotBraidEmitter {
public:
    // Emit a complete .sbraid file from a source tensor
    //
    // Parameters:
    //   filename      - Output .sbraid file path
    //   tensor_name   - Human-readable tensor name (for attention detection)
    //   src           - Source FP32 weights
    //   num_elements  - Number of elements
    //   max_passes    - Maximum Pinball passes (typically 256)
    //
    // Returns true on success, false on I/O or parameter error
    static bool EmitSBraidTensor(
        const std::string& filename,
        const std::string& tensor_name,
        const float* src,
        int64_t num_elements,
        int max_passes);

    // Read back a .sbraid file for verification/inspection
    static bool InspectSBraidTensor(
        const std::string& filename,
        SBraidHeader& out_header,
        std::vector<SBraidTile>& out_directory);

private:
    static constexpr int TILE_SIZE = 64;  // Match RDNA3 Wave32
    static constexpr float RESIDUAL_THRESHOLD = 0.125f;

    // Determine tile-local scale from max absolute value
    static float DetermineTileScale(const float* src, uint16_t count);

    // Emit base plane (1-bit sign per element)
    static std::vector<uint8_t> EmitBasePlane(
        const float* src, uint16_t count, float scale);

    // Emit sparse residuals for a tile
    // Returns only elements where |normalized - base| > threshold
    static std::vector<SBraidResidual> EmitSparseResiduals(
        const float* src, uint16_t count, float scale, uint16_t bounce_pass);

    // Detect if tensor is attention-related (affects precision floor)
    static bool IsAttentionTensor(const std::string& name);

    // Determine bounce pass from Pinball telemetry (simulated for now)
    static uint16_t DetermineBouncePass(
        const std::string& name, uint32_t tile_id, uint16_t element_count);
};
