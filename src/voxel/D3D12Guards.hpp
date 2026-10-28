// ============================================================================
// D3D12Guards.hpp — the parts of Direct3D that are easy to get wrong,
// written down once.
//
// Every rule in here was found by a failure, and every one of them is
// checkable by the compiler or by a test. The point of this file is that
// the next person does not have to find them again.
//
// The nine of them are:
//
//  1. The input layout of a pipeline must carry the number of its
//     elements, and a count that disagrees with the array is not a
//     mistake the runtime will tell you about: it reads past the end of
//     the array and takes the next thing in memory for a semantic name.
//     The InputLayout function below makes that mistake impossible to
//     write.
//
//  2. The transition barrier puts the subresource in the second place,
//     not the last. The order is the resource, the subresource, the
//     state before and the state after.
//
//  3. The compiler in this tree falls over on a table with an initial
//     value in it. Work the values out instead.
//
//  4. The format R8G8B8A8 stores the red, the green, the blue and the
//     alpha in that order, and reading it as blue first swaps the red
//     and the blue.
//
//  5. A colour target needs the flag that allows a render target.
//
//  6. The size of a constant buffer that is bound with a root
//     descriptor comes from the shader, and it has to be a whole number
//     of 256 byte blocks, which means every member of the block has to
//     be read by the shader.
//
//  7. The shader visibility is an enumeration and not a set of flags.
//     The vertex stage is 1 and the pixel stage is 5, and 1 or 5 is 5,
//     which is the pixel stage and nothing else. A root signature that
//     says "the vertex stage or the pixel stage" therefore covers the
//     pixel stage and leaves the vertex stage out, and a shader that
//     reads a constant buffer in the vertex stage is looking at a
//     buffer the root signature never bound. The value that covers
//     every stage is the one to use.
//
//  8. The footprints of a copy take eight arguments, and the rows of a
//     texture are padded to a 256 byte boundary, so the buffer a copy
//     reads into is bigger than the picture.
//
//  9. A vertex of a float3 and a float is sixteen bytes, and the extra
//     float is at the twelve byte mark. A vertex that is laid out as
//     three floats and two more is twenty bytes, and the hardware does
//     not mind, but the twenty byte layout and the three element layout
//     have to agree with each other or the shader reads a vertex from
//     the wrong place.
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>

#include <d3d12.h>

namespace sunshine {

// The input layout of a pipeline, with the number of its elements taken
// from the array itself.
//
// A pipeline that is given a count that was written by hand is one
// mistake away from reading past the end of the array, and the runtime
// will not say so: it will take the next thing in memory for the name
// of a semantic, and the pipeline will be refused, or the vertices will
// be read from the wrong place.
template <size_t N>
constexpr D3D12_INPUT_LAYOUT_DESC InputLayout(const D3D12_INPUT_ELEMENT_DESC (&elements)[N]) {
    return {elements, static_cast<UINT>(N)};
}

// The vertex of the voxel renderer.
//
// Three floats of position and one float that holds the block, the face
// and the occlusion. The extra float is at the twelve byte mark, which
// leaves the vertex at sixteen bytes.
struct GpuVertex {
    float x;
    float y;
    float z;
    float packed;
};

static_assert(sizeof(GpuVertex) == 16, "the vertex of the renderer is sixteen bytes");
static_assert(offsetof(GpuVertex, x) == 0, "the position starts at the front");
static_assert(offsetof(GpuVertex, packed) == 12, "the packed value is at the twelve byte mark");

// The number of bytes a copy of a picture needs.
//
// The rows of a texture are padded out to a 256 byte boundary, so the
// copy is bigger than the picture and a readback buffer that is sized
// from the width and the height alone is too small for any width that
// is not a whole number of sixty four pixels.
inline uint64_t paddedRowBytes(uint32_t widthBytes) {
    constexpr uint64_t kRowAlignment = 256;
    return ((static_cast<uint64_t>(widthBytes) + kRowAlignment - 1) / kRowAlignment) * kRowAlignment;
}

inline uint64_t readbackBytes(uint32_t width, uint32_t height, uint32_t bytesPerPixel) {
    return paddedRowBytes(width * bytesPerPixel) * height;
}

// The size of a constant buffer that is bound with a root descriptor
// has to be a whole number of 256 byte blocks.
inline constexpr bool isRootConstantBufferSize(uint64_t bytes) {
    return (bytes % 256) == 0;
}

// The shader visibility of a stage that is named with an enumeration and
// not with flags.
//
// The vertex stage is 1 and the pixel stage is 5, and there is no way to
// say both of them with an enumeration, so the enumeration that covers
// every stage is the only one that works.
inline constexpr bool isAllStages(D3D12_SHADER_VISIBILITY visibility) {
    return visibility == D3D12_SHADER_VISIBILITY_ALL;
}

} // namespace sunshine
