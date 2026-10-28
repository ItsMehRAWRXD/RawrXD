// ============================================================================
// Block.hpp — the block types of the world and how they are drawn.
//
// Every block in the world is one byte. The byte is the type, and the type
// decides three things: whether the block is solid, whether it is opaque
// (and therefore hides the faces of its neighbours), and what colour it
// is drawn in.
//
// The palette is deliberately small and deliberately ours. A voxel world
// with a handful of materials reads better than one with twenty, and the
// vertex format carries the block type, so the shader can tint per face
// without a texture atlas.
// ============================================================================

#pragma once

#include <cstdint>

namespace sunshine {

enum class BlockType : uint8_t {
    Air = 0,
    Bedrock = 1,
    Stone = 2,
    Dirt = 3,
    Grass = 4,
    Sand = 5,
    Water = 6,
    Wood = 7,
    Leaves = 8,
    CoalOre = 9,
    IronOre = 10,
    Snow = 11,
    Gravel = 12,
};

constexpr uint8_t kBlockAir = 0;

// How a block behaves in the mesher.
//
//   Solid    — the block occupies its cell. A solid block has faces.
//   Opaque   — the block hides the faces of the cells it touches. A solid
//              opaque block next to a solid opaque block shows no shared
//              face, which is what keeps the triangle count down.
//   Liquid   — the block is not solid for culling purposes, so a liquid
//              still draws its top face, but it does not hide the faces of
//              the blocks it touches.
enum class BlockRender : uint8_t {
    Air,
    Solid,
    Liquid,
};

// A colour, in 0..255 per channel.
struct BlockColor {
    uint8_t r = 0;
    uint8_t g = 0;
    uint8_t b = 0;
};

// Whether the block occupies its cell.
constexpr bool isSolid(BlockType t) {
    return t != BlockType::Air && t != BlockType::Water;
}

// Whether the block hides the faces of its neighbours.
constexpr bool isOpaque(BlockType t) {
    switch (t) {
        case BlockType::Air:
        case BlockType::Water:
        case BlockType::Leaves:
            return false;
        default:
            return true;
    }
}

constexpr BlockRender renderKind(BlockType t) {
    if (t == BlockType::Air) return BlockRender::Air;
    if (t == BlockType::Water) return BlockRender::Liquid;
    return BlockRender::Solid;
}

// The top face of a block. A grass block is green on top and brown on the
// sides, so the colour depends on the face.
constexpr BlockColor blockTopColor(BlockType t) {
    switch (t) {
        case BlockType::Bedrock: return {40, 40, 46};
        case BlockType::Stone:   return {104, 106, 116};
        case BlockType::Dirt:    return {86, 68, 55};
        case BlockType::Grass:   return {72, 94, 60};
        case BlockType::Sand:    return {172, 160, 134};
        case BlockType::Water:   return {44, 60, 86};
        case BlockType::Wood:    return {64, 52, 44};
        case BlockType::Leaves:  return {46, 64, 48};
        case BlockType::CoalOre: return {54, 54, 60};
        case BlockType::IronOre: return {146, 112, 96};
        case BlockType::Snow:    return {206, 206, 214};
        case BlockType::Gravel:  return {110, 108, 108};
        default:                 return {0, 0, 0};
    }
}

// The side faces of a block. Grass and snow are brown and grey on the
// side, so the world reads as stratified rather than as a flat sheet.
constexpr BlockColor blockSideColor(BlockType t) {
    switch (t) {
        case BlockType::Grass: return {92, 74, 56};
        case BlockType::Snow:  return {176, 178, 186};
        default:              return blockTopColor(t);
    }
}

// The block type carried in the vertex attributes.
constexpr uint8_t blockId(BlockType t) { return static_cast<uint8_t>(t); }

} // namespace sunshine
