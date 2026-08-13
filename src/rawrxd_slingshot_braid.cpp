#include "rawrxd_slingshot_braid.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <cmath>

// ============================================================================
// Slingshot Braid Emitter Implementation
// ============================================================================

bool SlingshotBraidEmitter::EmitSBraidTensor(
    const std::string& filename,
    const std::string& tensor_name,
    const float* src,
    int64_t num_elements,
    int max_passes)
{
    if (!src || num_elements <= 0 || max_passes <= 0) {
        std::fprintf(stderr, "[SBraid] Invalid parameters: src=%p num_elements=%lld max_passes=%d\n",
                     static_cast<const void*>(src), static_cast<long long>(num_elements), max_passes);
        return false;
    }

    // Calculate tile count
    const int64_t tile_count = (num_elements + TILE_SIZE - 1) / TILE_SIZE;
    if (tile_count > UINT32_MAX) {
        std::fprintf(stderr, "[SBraid] Tensor too large: %lld tiles exceeds uint32_t\n",
                     static_cast<long long>(tile_count));
        return false;
    }

    std::FILE* fp = std::fopen(filename.c_str(), "wb");
    if (!fp) {
        std::fprintf(stderr, "[SBraid] Failed to open '%s' for writing\n", filename.c_str());
        return false;
    }

    // ========================================================================
    // 1. Write placeholder header
    // ========================================================================
    SBraidHeader header{};
    std::memcpy(header.magic, SBRAID_MAGIC, 4);
    header.version = SBRAID_VERSION;
    header.header_size = sizeof(SBraidHeader);
    header.flags = 0;
    header.element_count = static_cast<uint64_t>(num_elements);
    header.tile_size = TILE_SIZE;
    header.tile_count = static_cast<uint32_t>(tile_count);
    header.directory_offset = sizeof(SBraidHeader);
    header.payload_offset = header.directory_offset + tile_count * sizeof(SBraidTile);
    header.payload_size = 0;  // Will be finalized
    header.global_scale = 1.0f;
    header.earned_bits = 0.0f;
    header.max_bounce_pass = 0;
    header.reserved = 0;

    if (std::fwrite(&header, sizeof(header), 1, fp) != 1) {
        std::fclose(fp);
        std::remove(filename.c_str());
        return false;
    }

    // ========================================================================
    // 2. Reserve space for tile directory
    // ========================================================================
    std::vector<SBraidTile> directory(tile_count);
    if (std::fwrite(directory.data(), sizeof(SBraidTile), tile_count, fp) != static_cast<size_t>(tile_count)) {
        std::fclose(fp);
        std::remove(filename.c_str());
        return false;
    }

    // ========================================================================
    // 3. Process each tile and emit payloads
    // ========================================================================
    uint64_t payload_cursor = header.payload_offset;
    float global_max_scale = 0.0f;
    uint16_t global_max_bounce = 0;
    double total_earned_bits = 0.0;

    const bool is_attention = IsAttentionTensor(tensor_name);

    for (int64_t tile_id = 0; tile_id < tile_count; ++tile_id) {
        const int64_t start_idx = tile_id * TILE_SIZE;
        const uint16_t count = static_cast<uint16_t>(
            std::min<int64_t>(TILE_SIZE, num_elements - start_idx));

        SBraidTile& tile = directory[tile_id];
        tile.tile_id = static_cast<uint32_t>(tile_id);
        tile.element_count = count;
        tile.base_bits = 1;  // Base plane: 1 bit per weight
        tile.flags = 0;

        // Attention tensors get sacred treatment (higher precision floor)
        if (is_attention) {
            tile.flags |= TILE_FLAG_ATTENTION | TILE_FLAG_SACRED;
        }

        // Determine tile-local scale
        tile.scale = DetermineTileScale(src + start_idx, count);
        if (tile.scale > global_max_scale) {
            global_max_scale = tile.scale;
        }

        // Determine bounce pass from Pinball telemetry
        tile.bounce_pass = DetermineBouncePass(tensor_name, static_cast<uint32_t>(tile_id), count);
        if (tile.bounce_pass > global_max_bounce) {
            global_max_bounce = tile.bounce_pass;
        }

        // Calculate earned bits for this tile
        // Base: 1 bit + residual contributions
        const float residual_density = static_cast<float>(tile.bounce_pass) / static_cast<float>(max_passes);
        const float tile_earned = 1.0f + (residual_density * 2.0f);  // Approximation
        total_earned_bits += tile_earned * count;

        // Emit base plane
        std::vector<uint8_t> base_plane = EmitBasePlane(src + start_idx, count, tile.scale);

        // Emit sparse residuals
        std::vector<SBraidResidual> residuals = EmitSparseResiduals(
            src + start_idx, count, tile.scale, tile.bounce_pass);

        tile.residual_count = static_cast<uint8_t>(
            std::min<size_t>(residuals.size(), 255));

        if (!residuals.empty()) {
            tile.flags |= TILE_FLAG_SPARSE;
        }

        // Set payload location
        tile.payload_offset = payload_cursor;
        tile.payload_size = static_cast<uint32_t>(
            base_plane.size() + residuals.size() * sizeof(SBraidResidual));

        // Write payload
        if (std::fwrite(base_plane.data(), 1, base_plane.size(), fp) != base_plane.size()) {
            std::fclose(fp);
            std::remove(filename.c_str());
            return false;
        }

        if (!residuals.empty()) {
            if (std::fwrite(residuals.data(), sizeof(SBraidResidual), residuals.size(), fp) != residuals.size()) {
                std::fclose(fp);
                std::remove(filename.c_str());
                return false;
            }
        }

        payload_cursor += tile.payload_size;
    }

    // ========================================================================
    // 4. Finalize header
    // ========================================================================
    header.payload_size = payload_cursor - header.payload_offset;
    header.global_scale = global_max_scale;
    header.earned_bits = static_cast<float>(total_earned_bits / num_elements);
    header.max_bounce_pass = global_max_bounce;

    // Rewrite header at start of file
    std::fseek(fp, 0, SEEK_SET);
    if (std::fwrite(&header, sizeof(header), 1, fp) != 1) {
        std::fclose(fp);
        std::remove(filename.c_str());
        return false;
    }

    // Rewrite directory after header
    std::fseek(fp, static_cast<long>(header.directory_offset), SEEK_SET);
    if (std::fwrite(directory.data(), sizeof(SBraidTile), tile_count, fp) != static_cast<size_t>(tile_count)) {
        std::fclose(fp);
        std::remove(filename.c_str());
        return false;
    }

    std::fclose(fp);

    std::printf("[SBraid] Emitted '%s': %lld elements, %d tiles, %.2f earned bits, %llu payload bytes\n",
                filename.c_str(),
                static_cast<long long>(num_elements),
                static_cast<int>(tile_count),
                header.earned_bits,
                static_cast<unsigned long long>(header.payload_size));

    return true;
}

// ============================================================================
// Inspection / Verification
// ============================================================================

bool SlingshotBraidEmitter::InspectSBraidTensor(
    const std::string& filename,
    SBraidHeader& out_header,
    std::vector<SBraidTile>& out_directory)
{
    std::FILE* fp = std::fopen(filename.c_str(), "rb");
    if (!fp) {
        std::fprintf(stderr, "[SBraid] Failed to open '%s' for reading\n", filename.c_str());
        return false;
    }

    // Read header
    if (std::fread(&out_header, sizeof(out_header), 1, fp) != 1) {
        std::fclose(fp);
        return false;
    }

    // Validate magic
    if (std::memcmp(out_header.magic, SBRAID_MAGIC, 4) != 0) {
        std::fprintf(stderr, "[SBraid] Invalid magic in '%s'\n", filename.c_str());
        std::fclose(fp);
        return false;
    }

    // Read directory
    out_directory.resize(out_header.tile_count);
    std::fseek(fp, static_cast<long>(out_header.directory_offset), SEEK_SET);
    if (std::fread(out_directory.data(), sizeof(SBraidTile), out_header.tile_count, fp) != out_header.tile_count) {
        std::fclose(fp);
        return false;
    }

    std::fclose(fp);
    return true;
}

// ============================================================================
// Private helpers
// ============================================================================

float SlingshotBraidEmitter::DetermineTileScale(const float* src, uint16_t count)
{
    float max_abs = 0.0f;
    for (uint16_t i = 0; i < count; ++i) {
        float abs_val = std::fabs(src[i]);
        if (abs_val > max_abs) {
            max_abs = abs_val;
        }
    }
    return max_abs > 0.0f ? max_abs : 1.0f;
}

std::vector<uint8_t> SlingshotBraidEmitter::EmitBasePlane(
    const float* src, uint16_t count, float scale)
{
    const size_t bytes = (count + 7) / 8;
    std::vector<uint8_t> result(bytes, 0);

    for (uint16_t i = 0; i < count; ++i) {
        const float normalized = src[i] / scale;
        if (normalized >= 0.0f) {
            result[i >> 3] |= static_cast<uint8_t>(1u << (i & 7));
        }
    }

    return result;
}

std::vector<SBraidResidual> SlingshotBraidEmitter::EmitSparseResiduals(
    const float* src, uint16_t count, float scale, uint16_t bounce_pass)
{
    std::vector<SBraidResidual> result;
    result.reserve(count / 20);  // Heuristic: ~5% density

    for (uint16_t i = 0; i < count; ++i) {
        const float normalized = src[i] / scale;
        const float base = normalized >= 0.0f ? 1.0f : -1.0f;
        const float error = std::fabs(normalized - base);

        if (error > RESIDUAL_THRESHOLD) {
            SBraidResidual r{};
            r.element_index = i;
            r.pass = static_cast<uint8_t>(std::min<uint16_t>(bounce_pass, 255));
            r.flags = (normalized > base) ? 0x01 : 0x00;  // 0x01 = positive residual
            result.push_back(r);
        }
    }

    return result;
}

bool SlingshotBraidEmitter::IsAttentionTensor(const std::string& name)
{
    // Attention-related tensor names that need higher precision floor
    static const char* attention_patterns[] = {
        "attn_q", "attn_k", "attn_v", "attn_output",
        "query", "key", "value", "attention"
    };

    for (const char* pattern : attention_patterns) {
        if (name.find(pattern) != std::string::npos) {
            return true;
        }
    }

    // Sacred tensors: embeddings and output projections
    if (name.find("token_embd") != std::string::npos ||
        name.find("output.weight") != std::string::npos) {
        return true;
    }

    return false;
}

uint16_t SlingshotBraidEmitter::DetermineBouncePass(
    const std::string& name, uint32_t tile_id, uint16_t element_count)
{
    (void)element_count;  // Unused for now, reserved for adaptive logic

    // Attention tensors: higher precision floor, later bounce
    if (IsAttentionTensor(name)) {
        // Sacred attention: allow up to full 256 passes
        // Add some tile-local variation to simulate adaptive convergence
        return static_cast<uint16_t>(200 + (tile_id % 56));
    }

    // FFN tensors: aggressive quantization, early bounce
    // Simulate the Pinball convergence pattern from telemetry:
    //   Bounce ~68 for ordinary tensors, with some variation
    return static_cast<uint16_t>(68 + (tile_id % 32));
}
