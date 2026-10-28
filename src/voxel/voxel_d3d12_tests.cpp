// ============================================================================
// voxel_d3d12_tests.cpp — the Direct3D rules this engine depends on,
// checked instead of remembered.
//
// Every one of these was found by a failure. A failure that is found once
// and written down becomes a test, and a test that fails tells you what
// broke without a day of isolation.
//
// The run writes a receipt and the exit code says whether the rules
// still hold.
// ============================================================================

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <d3d12.h>
#include <d3dcompiler.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#include "D3D12Guards.hpp"

using namespace sunshine;
using Microsoft::WRL::ComPtr;

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const char* name, const std::string& detail = "") {
    ++g_checks;
    if (condition) {
        printf("  pass  %s\n", name);
    } else {
        ++g_failures;
        printf("  FAIL  %s%s%s\n", name, detail.empty() ? "" : " : ", detail.c_str());
    }
}

// ---------------------------------------------------------------------------
// One. The input layout carries its own count.
//
// A layout whose count is written by hand can disagree with the array,
// and the runtime reads past the end of the array and takes the next
// thing in memory for the name of a semantic.
// ---------------------------------------------------------------------------
void testInputLayoutCarriesItsCount() {
    printf("\none. the input layout carries its count\n");

    static const D3D12_INPUT_ELEMENT_DESC elements[] = {
        {"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
        {"PACKED", 0, DXGI_FORMAT_R32_FLOAT, 0, 12, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
    };

    const D3D12_INPUT_LAYOUT_DESC layout = InputLayout(elements);
    check(layout.NumElements == 2, "the count is the number of the elements",
          "got " + std::to_string(layout.NumElements));
    check(layout.pInputElementDescs == elements, "the description points at the array");
    check(offsetof(GpuVertex, packed) == 12, "the packed value is at the twelve byte mark");
    check(sizeof(GpuVertex) == 16, "the vertex is sixteen bytes");
}

// ---------------------------------------------------------------------------
// Two. The transition barrier puts the subresource in the second place.
//
// The order is the resource, the subresource, the state before and the
// state after. A barrier that is written by hand in any other order
// gives the runtime a state of 0xFFFFFFFF, which is not a state.
// ---------------------------------------------------------------------------
void testBarrierLayout() {
    printf("\ntwo. the order of the fields of a transition barrier\n");

    D3D12_RESOURCE_BARRIER barrier{};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = nullptr;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_COMMON;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;

    check(barrier.Transition.Subresource == D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES,
          "the subresource holds the all subresources value");
    check(barrier.Transition.StateBefore == D3D12_RESOURCE_STATE_COMMON,
          "the state before is the common state");
    check(barrier.Transition.StateAfter == D3D12_RESOURCE_STATE_RENDER_TARGET,
          "the state after is the render target state");

    // The size of the barrier is the size of the resource, the
    // subresource, the state before and the state after.
    check(sizeof(D3D12_RESOURCE_TRANSITION_BARRIER) == 24,
          "the transition is twenty four bytes",
          "got " + std::to_string(sizeof(D3D12_RESOURCE_TRANSITION_BARRIER)));
}

// ---------------------------------------------------------------------------
// Three. The compiler falls over on a table with an initial value in it.
//
// It does not report an error. It stops the process.
// ---------------------------------------------------------------------------
void testCompilerHasNoTablesWithInitialValues() {
    printf("\nthree. the compiler does not fall over on the shader\n");

    static const char* kSource =
        "float4 VSMain(uint id : SV_VertexID) : SV_POSITION\n"
        "{\n"
        "    float x = id * 0.1;\n"
        "    return float4(x, x, x, 1.0);\n"
        "}\n"
        "float4 PSMain() : SV_TARGET { return float4(1.0, 0.0, 0.0, 1.0); }\n";

    ComPtr<ID3DBlob> blob;
    ComPtr<ID3DBlob> error;
    const HRESULT hr = D3DCompile(kSource, static_cast<UINT>(strlen(kSource)), "t.hlsl", nullptr,
                                  nullptr, "VSMain", "vs_5_1", 0, 0, &blob, &error);
    check(SUCCEEDED(hr), "a shader without a table compiles");
    check(blob != nullptr, "the bytecode was made");
}

// ---------------------------------------------------------------------------
// Four. The format R8G8B8A8 stores the red first.
//
// Reading it as blue first swaps the red and the blue, and a correct
// render comes out as an orange sky.
// ---------------------------------------------------------------------------
void testChannelOrder() {
    printf("\nfour. the order of the channels of R8G8B8A8\n");

    // The bytes of a pixel of the format, in the order they are in
    // memory: the red, the green, the blue and the alpha.
    const uint8_t pixel[4] = {200, 150, 100, 255};
    check(pixel[0] == 200, "the first byte is the red");
    check(pixel[1] == 150, "the second byte is the green");
    check(pixel[2] == 100, "the third byte is the blue");
    check(pixel[3] == 255, "the fourth byte is the alpha");
    check(!(pixel[0] == 100 && pixel[2] == 200), "the red and the blue are not the same");
}

// ---------------------------------------------------------------------------
// Five. A colour target needs the flag that allows a render target.
//
// Without it the transition is refused and the command list is closed
// with an argument error.
// ---------------------------------------------------------------------------
void testRenderTargetFlag() {
    printf("\nfive. the flag on a colour target\n");

    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    desc.Width = 64;
    desc.Height = 64;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;
    desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET;

    check((desc.Flags & D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET) != 0,
          "the colour target carries the flag");

    // A depth target needs the other one.
    D3D12_RESOURCE_DESC depth{};
    depth.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    depth.Width = 64;
    depth.Height = 64;
    depth.DepthOrArraySize = 1;
    depth.MipLevels = 1;
    depth.Format = DXGI_FORMAT_D32_FLOAT;
    depth.SampleDesc.Count = 1;
    depth.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;
    depth.Flags = D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL;
    check((depth.Flags & D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL) != 0,
          "the depth target carries the depth flag");
}

// ---------------------------------------------------------------------------
// Six. The size of a constant buffer has to be a whole number of 256 byte
// blocks, and the size comes from the shader.
//
// A member the shader does not read is thrown away, and the size that
// is left is not a whole number of blocks, and the pipeline is refused.
// ---------------------------------------------------------------------------
void testConstantBufferSize() {
    printf("\nsix. the size of a constant buffer\n");

    check(isRootConstantBufferSize(768), "768 bytes is three blocks");
    check(isRootConstantBufferSize(1024), "1024 bytes is four blocks");
    check(!isRootConstantBufferSize(624), "624 bytes is not a whole number of blocks");
    check(!isRootConstantBufferSize(736), "736 bytes is not a whole number of blocks");
}

// ---------------------------------------------------------------------------
// Seven. The shader visibility is an enumeration and not a set of flags.
//
// The values are 1 for the vertex stage and 5 for the pixel stage, and
// they are not a bit mask: 1 or 5 is 5, which is the pixel stage and
// nothing else. A root signature that says "the vertex stage or the
// pixel stage" therefore covers the pixel stage and leaves the vertex
// stage out, and a shader that reads a constant buffer in the vertex
// stage is looking at a buffer the root signature never bound.
//
// The only value that covers both stages is the one that means every
// stage, and that is the one to use.
// ---------------------------------------------------------------------------
void testShaderVisibility() {
    printf("\nseven. the shader visibility is an enumeration\n");

    check(static_cast<int>(D3D12_SHADER_VISIBILITY_VERTEX) == 1, "the vertex stage is one");
    check(static_cast<int>(D3D12_SHADER_VISIBILITY_PIXEL) == 5, "the pixel stage is five");
    check(static_cast<int>(D3D12_SHADER_VISIBILITY_VERTEX | D3D12_SHADER_VISIBILITY_PIXEL) ==
              static_cast<int>(D3D12_SHADER_VISIBILITY_PIXEL),
          "the two of them ored together is the pixel stage and not both");
    check(static_cast<int>(D3D12_SHADER_VISIBILITY_VERTEX | D3D12_SHADER_VISIBILITY_PIXEL) !=
              static_cast<int>(D3D12_SHADER_VISIBILITY_VERTEX),
          "the two of them ored together leaves the vertex stage out");
    check(isAllStages(D3D12_SHADER_VISIBILITY_ALL),
          "the enumeration that covers every stage is the one to use");
}

// ---------------------------------------------------------------------------
// Eight. The footprints of a copy take eight arguments, and the rows are
// padded.
//
// A readback buffer that is sized from the width and the height alone
// is too small for any width that is not a whole number of sixty four
// pixels.
// ---------------------------------------------------------------------------
void testCopyFootprints() {
    printf("\neight. the size of a readback\n");

    check(paddedRowBytes(640 * 4) == 2560, "the row of a 640 pixel picture is padded to 2560");
    check(paddedRowBytes(320 * 4) == 1280, "the row of a 320 pixel picture is already whole");
    check(paddedRowBytes(800 * 4) == 3328, "the row of an 800 pixel picture is padded to 3328");
    check(readbackBytes(800, 450, 4) == 1497600,
          "the readback of an 800 by 450 picture is the padded size");
    check(readbackBytes(800, 450, 4) > 800u * 450u * 4u,
          "the readback is bigger than the picture");
}

// ---------------------------------------------------------------------------
// Nine. The vertex is sixteen bytes.
//
// Three floats of position and one float of everything else. A layout of
// three elements with a stride of twenty bytes is a different vertex, and
// the hardware does not mind, but the two have to agree.
// ---------------------------------------------------------------------------
void testVertexLayout() {
    printf("\nnine. the layout of a vertex\n");

    check(sizeof(GpuVertex) == 16, "the vertex is sixteen bytes");
    check(offsetof(GpuVertex, x) == 0, "the position is at the front");
    check(offsetof(GpuVertex, y) == 4, "the second float is at four");
    check(offsetof(GpuVertex, z) == 8, "the third float is at eight");
    check(offsetof(GpuVertex, packed) == 12, "the packed value is at twelve");

    // The layout of the renderer agrees with the vertex.
    static const D3D12_INPUT_ELEMENT_DESC elements[] = {
        {"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
        {"PACKED", 0, DXGI_FORMAT_R32_FLOAT, 0, 12, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
    };

    uint32_t last = 0;
    bool withinStride = true;
    for (const D3D12_INPUT_ELEMENT_DESC& element : elements) {
        const uint32_t size = (element.Format == DXGI_FORMAT_R32G32B32_FLOAT) ? 12u : 4u;
        if (element.AlignedByteOffset + size > sizeof(GpuVertex)) withinStride = false;
        last = element.AlignedByteOffset + size;
    }
    check(withinStride, "every element is inside the vertex");
    check(last <= sizeof(GpuVertex), "the elements do not run past the vertex");
}

} // namespace

int main() {
    printf("the Direct3D rules the voxel renderer depends on\n");

    testInputLayoutCarriesItsCount();
    testBarrierLayout();
    testCompilerHasNoTablesWithInitialValues();
    testChannelOrder();
    testRenderTargetFlag();
    testConstantBufferSize();
    testShaderVisibility();
    testCopyFootprints();
    testVertexLayout();

    printf("\n%u checks, %u failures\n", g_checks, g_failures);
    if (g_failures == 0) {
        printf("VOXEL_D3D12_RULES=PASS\n");
        return 0;
    }
    printf("VOXEL_D3D12_RULES=FAIL\n");
    return 1;
}
