// ============================================================================
// VoxelRenderer.cpp — the Direct3D 12 renderer.
//
// Every Direct3D call in this file is the real one. There is no software
// fallback and no simulated path: if the device cannot be created, the
// renderer says so and refuses to continue, because a renderer that
// pretends to draw is worse than one that admits it cannot.
// ============================================================================

#include "VoxelRenderer.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>

#include <d3dcompiler.h>
#include <d3d11.h>
#include <d3d12sdklayers.h>

#include "Block.hpp"
#include "D3D12Guards.hpp"
#include "ShaderSource.hpp"

namespace sunshine {

namespace {

// The Direct3D debug layer.
//
// The layer is enabled when the machine has it, and its messages are read
// when something goes wrong. A Direct3D call that refuses gives a code
// and nothing else, and the code says nothing about which argument was
// wrong. The layer says which one, in a sentence.
void reportDebugMessages(ID3D12Device* device) {
    // The message queue of the layer lives on an interface that the
    // installed SDK does not declare, so the messages cannot be read here.
    // The layer is still enabled, because on a machine that has the tools
    // it writes them to the debug output on their own.
    (void)device;
}

// The heap properties for a resource.
//
// The node masks have to be one. A structure that is only zeroed leaves
// them at zero, and zero is not a valid mask, so every resource that is
// committed with it is refused.
D3D12_HEAP_PROPERTIES defaultHeap(D3D12_HEAP_TYPE type) {
    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = type;
    heap.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
    heap.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
    heap.CreationNodeMask = 1;
    heap.VisibleNodeMask = 1;
    return heap;
}

// A transition barrier.
//
// The fields are filled in through the header, by name, because that is
// the order the runtime reads them in. Writing the bytes by hand gets
// the same answer only if the order is right, and there is no way to
// tell from the header alone which order the runtime wants.
inline void makeTransitionBarrier(D3D12_RESOURCE_BARRIER& barrier,
                                   ID3D12Resource* resource,
                                   D3D12_RESOURCE_STATES stateBefore,
                                   D3D12_RESOURCE_STATES stateAfter,
                                   UINT subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES) {
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = resource;
    barrier.Transition.Subresource = subresource;
    barrier.Transition.StateBefore = stateBefore;
    barrier.Transition.StateAfter = stateAfter;
}

// The table of calls of the runtime.
//
// The header in this SDK has two calls in it that the runtime does not
// have, the singular forms of the root constant calls, and it leaves out
// one that the runtime does have, the shader roots. So the calls after
// those are two slots further along in the header than they are in the
// runtime, and the calls the engine needs are made through the table
// directly, at the slots the runtime has them at.
//
// The table below was checked against the runtime: the close of a fresh
// list is at the first slot, which is where the header has it too.
// The layout of the constant buffer, mirrored in the shader.
//
// The size of this block has to be a whole number of 256 byte blocks,
// because it is bound with a root descriptor, and it has to be the size
// the compiler sees after it has thrown away whatever it thinks is
// unused. So there is no padding here: every member is something the
// shader reads.
//
// The total is 768 bytes, which is three blocks of 256.
constexpr size_t kConstantBufferSize = 768;

struct ConstantBufferData {
    float viewProjection[16];   // four rows
    float cameraPos[4];         // xyz, w is the time
    float sunDirection[4];      // xyz, w is the strength
    float fogColor[4];          // rgb, w is the density
    float waterColor[4];        // rgb, w is the strength
    float skyZenith[4];
    float skyHorizon[4];
    float faceLight[6][4];
    float paletteTop[16][4];
    float paletteSide[16][4];
};

static_assert(sizeof(ConstantBufferData) == 768,
              "the scene block has to be a whole number of 256 byte blocks");

// The gothic block. Sixteen members, all of them read by the shader,
// and a whole number of 256 byte blocks.
struct GothicBufferData {
    float sunColour[4];
    float skyLight[4];
    float groundBounce[4];
    float mistColour[4];
    float emberColour[4];
    float ridge[4];
    float atmosphere[4];
    float tone[4];
    float grain[4];
    float water[4];
    float palette[4];
    float ember[4];
    float skyBand[4];
    float shadow[4];
    float ridgeBand[4];
    float misc[4];
};

static_assert(sizeof(GothicBufferData) == 256,
              "the gothic block has to be a whole number of 256 byte blocks");

static_assert(sizeof(ConstantBufferData) == kConstantBufferSize,
              "the constant buffer and the space that is uploaded must be the same size");
static_assert(kConstantBufferSize % 256 == 0,
              "a constant buffer bound with a root descriptor must be a whole number of 256 byte blocks");

// The window and the swap chain need the factory not to handle Alt+Enter.
constexpr UINT kSwapChainFlags = 0;

} // namespace

VoxelRenderer::~VoxelRenderer() {
    if (device_) {
        waitForGpu();
    }
    if (fenceEvent_) {
        CloseHandle(fenceEvent_);
        fenceEvent_ = nullptr;
    }
}

void VoxelRenderer::buildPalette() {
    for (int i = 0; i < 16; ++i) {
        const BlockType type = static_cast<BlockType>(i);
        const BlockColor top = blockTopColor(type);
        const BlockColor side = blockSideColor(type);
        paletteTop_[i][0] = top.r / 255.0f;
        paletteTop_[i][1] = top.g / 255.0f;
        paletteTop_[i][2] = top.b / 255.0f;
        paletteTop_[i][3] = 1.0f;
        paletteSide_[i][0] = side.r / 255.0f;
        paletteSide_[i][1] = side.g / 255.0f;
        paletteSide_[i][2] = side.b / 255.0f;
        paletteSide_[i][3] = 1.0f;
    }
}

void VoxelRenderer::releaseChunk(int32_t chunkX, int32_t chunkZ) {
    const uint64_t key = (static_cast<uint64_t>(static_cast<uint32_t>(chunkX)) << 32) |
                         static_cast<uint32_t>(chunkZ);
    chunks_.erase(key);
}

// The constant buffer for one frame.
//
// The matrix goes up transposed. A point is multiplied on the right, so
// each component of the result is the dot of the point with a column of
// the matrix, and the shader does exactly that with the rows of what it
// is given. Uploading the rows as they are gives the transpose, and the
// world comes out turned over.
void VoxelRenderer::updateConstantBuffer(const Mat4& viewProjection,
                                         const Vec3& cameraPosition, double time) {
    ConstantBufferData data{};

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            data.viewProjection[i * 4 + j] = viewProjection.m[j][i];
        }
    }

    data.cameraPos[0] = cameraPosition.x;
    data.cameraPos[1] = cameraPosition.y;
    data.cameraPos[2] = cameraPosition.z;
    data.cameraPos[3] = static_cast<float>(time);

    // The light. It is cold and low, and it comes from behind the smog.
    data.sunDirection[0] = 0.36f;
    data.sunDirection[1] = 0.80f;
    data.sunDirection[2] = 0.48f;
    data.sunDirection[3] = 0.20f;

    // The smog. It is warm grey, and it is thick.
    data.fogColor[0] = 0.50f;
    data.fogColor[1] = 0.47f;
    data.fogColor[2] = 0.44f;
    data.fogColor[3] = 0.0165f;

    // The sky, the same colours the sky shader uses.
    data.skyZenith[0] = 0.11f;
    data.skyZenith[1] = 0.09f;
    data.skyZenith[2] = 0.19f;
    data.skyZenith[3] = 1.0f;

    data.skyHorizon[0] = 0.58f;
    data.skyHorizon[1] = 0.54f;
    data.skyHorizon[2] = 0.50f;
    data.skyHorizon[3] = 1.0f;

    // The water, and how strongly it is tinted.
    data.waterColor[0] = 0.17f;
    data.waterColor[1] = 0.23f;
    data.waterColor[2] = 0.34f;
    data.waterColor[3] = 0.45f;

    // The brightness of each of the six faces. The top is the brightest,
    // the bottom is the darkest, and the sides are in between.
    static const float kFaceLight[6][3] = {
        {0.78f, 0.78f, 0.78f},   // +X
        {0.66f, 0.66f, 0.66f},   // -X
        {1.00f, 1.00f, 1.00f},   // +Y
        {0.45f, 0.45f, 0.45f},   // -Y
        {0.86f, 0.86f, 0.86f},   // +Z
        {0.58f, 0.58f, 0.58f},   // -Z
    };
    for (int i = 0; i < 6; ++i) {
        data.faceLight[i][0] = kFaceLight[i][0];
        data.faceLight[i][1] = kFaceLight[i][1];
        data.faceLight[i][2] = kFaceLight[i][2];
        data.faceLight[i][3] = 1.0f;
    }

    memcpy(data.paletteTop, paletteTop_, sizeof(paletteTop_));
    memcpy(data.paletteSide, paletteSide_, sizeof(paletteSide_));

    memcpy(constantMapped_, &data, sizeof(data));

    // The gothic block. The colours are the ones the world is made of:
    // a warm sun low in the west, a cold sky, the warmth the ground
    // throws up, and the mist that lies in the valleys.
    GothicBufferData gothic{};
    gothic.sunColour[0] = 1.00f; gothic.sunColour[1] = 0.72f;
    gothic.sunColour[2] = 0.44f; gothic.sunColour[3] = 0.78f;

    gothic.skyLight[0] = 0.30f; gothic.skyLight[1] = 0.38f;
    gothic.skyLight[2] = 0.58f; gothic.skyLight[3] = 0.30f;

    gothic.groundBounce[0] = 0.26f; gothic.groundBounce[1] = 0.20f;
    gothic.groundBounce[2] = 0.15f; gothic.groundBounce[3] = 0.24f;

    gothic.mistColour[0] = 0.56f; gothic.mistColour[1] = 0.52f;
    gothic.mistColour[2] = 0.52f; gothic.mistColour[3] = 1.0f;

    gothic.emberColour[0] = 1.00f; gothic.emberColour[1] = 0.42f;
    gothic.emberColour[2] = 0.12f; gothic.emberColour[3] = 0.55f;

    // The ridge, the cavity, the specular and its power.
    gothic.ridge[0] = 0.16f; gothic.ridge[1] = 0.55f;
    gothic.ridge[2] = 0.10f; gothic.ridge[3] = 22.0f;

    // The height of the mist, its falloff, its strength and the haze.
    gothic.atmosphere[0] = 74.0f; gothic.atmosphere[1] = 0.045f;
    gothic.atmosphere[2] = 0.85f; gothic.atmosphere[3] = 0.0045f;

    // The exposure, the contrast, the lift and the gain.
    gothic.tone[0] = 1.06f; gothic.tone[1] = 1.14f;
    gothic.tone[2] = 0.010f; gothic.tone[3] = 0.94f;

    // The grain, its scale, its warmth and its speed.
    gothic.grain[0] = 0.022f; gothic.grain[1] = 1.0f;
    gothic.grain[2] = 0.05f; gothic.grain[3] = 1.7f;

    // The depth of the water, the ripple, the fresnel and the foam.
    gothic.water[0] = 0.85f; gothic.water[1] = 0.55f;
    gothic.water[2] = 4.0f; gothic.water[3] = 0.05f;

    // The variation of the material, the saturation, the contrast and
    // the softness of the edge.
    gothic.palette[0] = 0.22f; gothic.palette[1] = 1.10f;
    gothic.palette[2] = 1.0f; gothic.palette[3] = 0.0f;

    // The pulse of the glow, the speed, the threshold and the mist of
    // the glow.
    gothic.ember[0] = 1.0f; gothic.ember[1] = 1.4f;
    gothic.ember[2] = 0.35f; gothic.ember[3] = 0.0f;

    // The gradient of the sky, the glow of the horizon, the fade and the
    // cloud.
    gothic.skyBand[0] = 0.0f; gothic.skyBand[1] = 0.55f;
    gothic.skyBand[2] = 0.0f; gothic.skyBand[3] = 0.0f;

    // The tint of the shadows, the floor under them, the softness and
    // the strength. The floor is a cold violet and not a teal, because
    // the picture is warm and cold and not warm and green.
    gothic.shadow[0] = 0.085f; gothic.shadow[1] = 0.095f;
    gothic.shadow[2] = 0.30f; gothic.shadow[3] = 1.0f;

    // The band, the falloff, the height and the warmth of the cavity.
    gothic.ridgeBand[0] = 0.0f; gothic.ridgeBand[1] = 0.0f;
    gothic.ridgeBand[2] = 0.0f; gothic.ridgeBand[3] = 0.16f;

    // The flicker of the glow, the speed, the fade and the scale.
    gothic.misc[0] = 0.06f; gothic.misc[1] = 2.3f;
    gothic.misc[2] = 0.0f; gothic.misc[3] = 1.0f;

    memcpy(gothicMapped_, &gothic, sizeof(gothic));
}

// The table of calls the runtime has is found by drawing a frame and
// looking at it. The sky at the top of the frame is a deep blue, so a
// frame whose top is blue is a frame whose constant buffer was bound and
// whose render target was set.
bool VoxelRenderer::probeTableLayout(std::string& error) {
    if (!offscreen_ || width_ == 0) {
        error = "the table of calls can only be found once there is a target";
        return false;
    }

    FrameStats stats{};
    const Mat4 identity = Mat4::identity();
    if (!renderFrame(identity, Vec3{0.0f, 0.0f, 0.0f}, 0.0, stats, error)) {
        return false;
    }

    CapturedFrame frame;
    if (!captureFrame(frame, error)) {
        return false;
    }
    if (frame.pixels.empty()) {
        error = "the frame that found the table of calls was empty";
        return false;
    }

    // The pixel at the top middle of the frame. The target is in the
    // format R8G8B8A8, so the bytes are red, green, blue and alpha.
    //
    // The sky is always the colour with the blue channel the largest of
    // the three, whatever the depth of the blue is, so the test is that
    // the blue is the largest and that the frame is not one flat colour.
    const size_t index = (static_cast<size_t>(frame.height / 8) * frame.width +
                          frame.width / 2) * 4;
    const uint8_t r = frame.pixels[index + 0];
    const uint8_t g = frame.pixels[index + 1];
    const uint8_t b = frame.pixels[index + 2];

    if (!(b > r && b > g)) {
        error = "the frame does not show the sky, so the pipeline is not right";
        return false;
    }
    return true;
}

bool VoxelRenderer::initialize(std::string& error) {
    buildPalette();

    HRESULT hr = CreateDXGIFactory2(0, IID_PPV_ARGS(&factory_));
    if (FAILED(hr)) {
        error = "CreateDXGIFactory2 failed: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    // Pick the adapter. A hardware adapter is preferred, and the software
    // adapter is only used when there is nothing else, so that the
    // renderer still runs on a machine with no usable driver.
    ComPtr<IDXGIAdapter1> chosen;
    ComPtr<IDXGIAdapter1> softwareAdapter;

    for (UINT index = 0;; ++index) {
        ComPtr<IDXGIAdapter1> adapter;
        if (factory_->EnumAdapters1(index, &adapter) == DXGI_ERROR_NOT_FOUND) break;

        DXGI_ADAPTER_DESC1 desc{};
        if (FAILED(adapter->GetDesc1(&desc))) continue;

        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) {
            if (!softwareAdapter) softwareAdapter = adapter;
            continue;
        }
        if (!chosen) {
            chosen = adapter;
            // Prefer a discrete adapter over an integrated one.
            if (desc.DedicatedVideoMemory > 0) break;
        }
    }

    if (!chosen) chosen = softwareAdapter;
    if (!chosen) {
        error = "no Direct3D 12 adapter was found";
        return false;
    }

    DXGI_ADAPTER_DESC1 desc{};
    chosen->GetDesc1(&desc);
    {
        // The adapter name is a wide string, and the receipt is a narrow
        // one.
        const int len = static_cast<int>(wcslen(desc.Description));
        std::string narrow;
        narrow.reserve(static_cast<size_t>(len));
        for (int i = 0; i < len; ++i) {
            narrow += static_cast<char>(desc.Description[i] & 0x7F);
        }
        adapterName_ = narrow;
    }

    hr = D3D12CreateDevice(chosen.Get(), D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device_));
    if (FAILED(hr)) {
        error = "D3D12CreateDevice failed: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    // The debug layer, when the machine has it. It costs nothing when it
    // is not there, and it is the difference between a code and a
    // paragraph about which argument was wrong.
    {
        ComPtr<ID3D12Debug> debugController;
        if (SUCCEEDED(D3D12GetDebugInterface(IID_PPV_ARGS(&debugController)))) {
            debugController->EnableDebugLayer();
        }
    }

    D3D12_COMMAND_QUEUE_DESC queueDesc{};
    queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    queueDesc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
    hr = device_->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&queue_));
    if (FAILED(hr)) {
        error = "CreateCommandQueue failed: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    hr = device_->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&allocator_));
    if (FAILED(hr)) {
        error = "CreateCommandAllocator failed: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    // The command list is created as the base interface and then asked
    // for the graphics one, which is the one that has the drawing calls.
    ComPtr<ID3D12CommandList> baseList;
    hr = device_->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator_.Get(), nullptr,
                                    IID_PPV_ARGS(&baseList));
    if (FAILED(hr)) {
        error = "CreateCommandList failed: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    hr = baseList.As(&list_);
    if (FAILED(hr)) {
        error = "the command list is not a graphics command list: " +
                std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    const HRESULT closeResult = list_->Close();
    if (FAILED(closeResult)) {
        error = "the fresh command list could not be closed: " +
                std::to_string(static_cast<unsigned>(closeResult));
        return false;
    }

    hr = device_->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence_));
    if (FAILED(hr)) {
        error = "CreateFence failed: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    fenceEvent_ = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!fenceEvent_) {
        error = "CreateEvent failed";
        return false;
    }

    if (!createPipelines(error)) return false;
    if (!createConstantBuffer(error)) return false;

    return true;
}

// The pipelines.
//
// The shader is compiled here rather than being read from a file, so that
// the engine has no path to get wrong at run time and no separate shader
// build to keep in step with the code.
bool VoxelRenderer::createPipelines(std::string& error) {

    // Compile the shader.
    ComPtr<ID3DBlob> vertexBlob;
    ComPtr<ID3DBlob> pixelBlob;
    ComPtr<ID3DBlob> errorBlob;

    const UINT flags = D3DCOMPILE_ENABLE_STRICTNESS | D3DCOMPILE_OPTIMIZATION_LEVEL3;
    HRESULT hr = D3DCompile(kVoxelShaderSource, static_cast<UINT>(strlen(kVoxelShaderSource)),
                             "voxel.hlsl", nullptr, nullptr, "VoxelVS", "vs_5_1", flags, 0,
                             &vertexBlob, &errorBlob);
    if (FAILED(hr)) {
        error = "the vertex shader did not compile";
        if (errorBlob) {
            error += ": ";
            error.append(static_cast<const char*>(errorBlob->GetBufferPointer()),
                         errorBlob->GetBufferSize());
        }
        return false;
    }

    errorBlob.Reset();
    hr = D3DCompile(kVoxelShaderSource, static_cast<UINT>(strlen(kVoxelShaderSource)),
                    "voxel.hlsl", nullptr, nullptr, "VoxelPS", "ps_5_1", flags, 0,
                    &pixelBlob, &errorBlob);
    if (FAILED(hr)) {
        error = "the pixel shader did not compile";
        if (errorBlob) {
            error += ": ";
            error.append(static_cast<const char*>(errorBlob->GetBufferPointer()),
                         errorBlob->GetBufferSize());
        }
        return false;
    }

    ComPtr<ID3DBlob> skyVertexBlob;
    ComPtr<ID3DBlob> skyPixelBlob;
    errorBlob.Reset();
    hr = D3DCompile(kVoxelShaderSource, static_cast<UINT>(strlen(kVoxelShaderSource)),
                    "voxel.hlsl", nullptr, nullptr, "SkyVS", "vs_5_1", flags, 0,
                    &skyVertexBlob, &errorBlob);
    if (FAILED(hr)) {
        error = "the sky vertex shader did not compile";
        if (errorBlob) {
            error += ": ";
            error.append(static_cast<const char*>(errorBlob->GetBufferPointer()),
                         errorBlob->GetBufferSize());
        }
        return false;
    }

    errorBlob.Reset();
    hr = D3DCompile(kVoxelShaderSource, static_cast<UINT>(strlen(kVoxelShaderSource)),
                    "voxel.hlsl", nullptr, nullptr, "SkyPS", "ps_5_1", flags, 0,
                    &skyPixelBlob, &errorBlob);
    if (FAILED(hr)) {
        error = "the sky pixel shader did not compile";
        if (errorBlob) {
            error += ": ";
            error.append(static_cast<const char*>(errorBlob->GetBufferPointer()),
                         errorBlob->GetBufferSize());
        }
        return false;
    }

    // The root signature: one constant buffer for the vertex and the pixel
    // stage. There is no texture and no sampler, because the colour of a
    // block comes from the palette in the constant buffer.
    //
    // The visibility is ALL, and not the two stages named separately.
    // The visibility is an enumeration and not a set of flags, so there
    // is no way to say "the vertex stage and the pixel stage" with it.
    // The vertex and the pixel values are 1 and 5, and 1 or 5 is 6,
    // which is the amplification stage. That is a stage the shader does
    // not have, and Direct3D refuses the pipeline.
    D3D12_ROOT_PARAMETER parameters[2]{};
    parameters[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_CBV;
    parameters[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    parameters[0].Descriptor.ShaderRegister = 0;
    parameters[0].Descriptor.RegisterSpace = 0;

    parameters[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_CBV;
    parameters[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    parameters[1].Descriptor.ShaderRegister = 1;
    parameters[1].Descriptor.RegisterSpace = 0;

    D3D12_ROOT_SIGNATURE_DESC rootDesc{};
    rootDesc.NumParameters = 2;
    rootDesc.pParameters = parameters;
    rootDesc.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;

    ComPtr<ID3DBlob> rootBlob;
    ComPtr<ID3DBlob> rootError;
    hr = D3D12SerializeRootSignature(&rootDesc, D3D_ROOT_SIGNATURE_VERSION_1, &rootBlob, &rootError);
    if (FAILED(hr)) {
        error = "the root signature could not be serialised";
        if (rootError) {
            error += ": ";
            error.append(static_cast<const char*>(rootError->GetBufferPointer()),
                         rootError->GetBufferSize());
        }
        return false;
    }
    hr = device_->CreateRootSignature(0, rootBlob->GetBufferPointer(), rootBlob->GetBufferSize(),
                                      IID_PPV_ARGS(&rootSignature_));
    if (FAILED(hr)) {
        error = "CreateRootSignature failed: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    // The input layout: three floats of position and one float that holds
    // the block, the face and the occlusion.
    //
    // The two of them are named rather than being the texture
    // coordinates with a number on the end, because a name that ends in
    // a digit is a name and an index to the compiler and the two
    // readings of it do not always agree.
    D3D12_INPUT_ELEMENT_DESC layout[] = {
        {"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
        {"PACKED", 0, DXGI_FORMAT_R32_FLOAT, 0, 12, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
    };

    D3D12_GRAPHICS_PIPELINE_STATE_DESC pso{};
    pso.pRootSignature = rootSignature_.Get();
    pso.VS = {vertexBlob->GetBufferPointer(), vertexBlob->GetBufferSize()};
    pso.PS = {pixelBlob->GetBufferPointer(), pixelBlob->GetBufferSize()};
    pso.InputLayout = InputLayout(layout);
    pso.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
    pso.NumRenderTargets = 1;
    pso.RTVFormats[0] = DXGI_FORMAT_R8G8B8A8_UNORM;
    pso.DSVFormat = DXGI_FORMAT_D32_FLOAT;
    pso.SampleDesc.Count = 1;
    pso.SampleMask = UINT_MAX;
    pso.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
    pso.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;
    pso.RasterizerState.DepthClipEnable = TRUE;
    pso.DepthStencilState.DepthEnable = TRUE;
    pso.DepthStencilState.DepthWriteMask = D3D12_DEPTH_WRITE_MASK_ALL;
    pso.DepthStencilState.DepthFunc = D3D12_COMPARISON_FUNC_LESS_EQUAL;
    pso.DepthStencilState.StencilEnable = FALSE;
    // A switch for telling a broken depth test apart from broken geometry.
    if (GetEnvironmentVariableA("RAWR_VOXEL_NO_DEPTH", nullptr, 0) != 0) {
        pso.DepthStencilState.DepthWriteMask = D3D12_DEPTH_WRITE_MASK_ZERO;
        pso.DepthStencilState.DepthFunc = D3D12_COMPARISON_FUNC_ALWAYS;
    }
    pso.BlendState.AlphaToCoverageEnable = FALSE;
    pso.BlendState.IndependentBlendEnable = FALSE;
    pso.BlendState.RenderTarget[0].BlendEnable = FALSE;
    pso.BlendState.RenderTarget[0].LogicOpEnable = FALSE;
    pso.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;

    hr = device_->CreateGraphicsPipelineState(&pso, IID_PPV_ARGS(&voxelPipeline_));
    if (FAILED(hr)) {
        // The pipeline is the one thing in Direct3D 12 that gives no
        // reason when it refuses. So a set of progressively simpler
        // shaders is tried, and the name of the one that worked is
        // printed. That turns a code into an answer.
        struct ShaderVariant {
            const char* name;
            const char* source;
            bool withInputLayout;
        };

        const char* kFull = kVoxelShaderSource;

        static const char* kSimple =
            "cbuffer Scene : register(b0)\n"
            "{ float4 vpRow0; float4 vpRow1; float4 vpRow2; float4 vpRow3;\n"
            "  float4 cameraPos; float4 sunDirection; float4 fogColor; float4 waterColor;\n"
            "  float4 paletteTop[4]; float4 paletteSide[4]; };\n"
            "struct VSIn { float3 position : POSITION; float packed : TEXCOORD0; float ao : TEXCOORD1; };\n"
            "struct VSOut { float4 position : SV_POSITION; };\n"
            "VSOut VSMain(VSIn i) { VSOut o; float4 p = float4(i.position, 1.0);\n"
            "  o.position = float4(dot(p,vpRow0), dot(p,vpRow1), dot(p,vpRow2), dot(p,vpRow3));\n"
            "  return o; }\n"
            "float4 PSMain(VSOut i) : SV_TARGET { return float4(1.0, 0.0, 0.0, 1.0); }\n";

        static const char* kPositionOnly =
            "struct VSIn { float3 position : POSITION; };\n"
            "struct VSOut { float4 position : SV_POSITION; };\n"
            "VSOut VSMain(VSIn i) { VSOut o; o.position = float4(i.position, 1.0); return o; }\n"
            "float4 PSMain(VSOut i) : SV_TARGET { return float4(0.0, 1.0, 0.0, 1.0); }\n";

        const ShaderVariant variants[] = {
            {"the full shader, with the layout", kFull, true},
            {"the full shader, without the layout", kFull, false},
            {"a simple shader, with the layout", kSimple, true},
            {"a simple shader, without the layout", kSimple, false},
            {"a position only shader, with the layout", kPositionOnly, true},
            {"a position only shader, without the layout", kPositionOnly, false},
        };

        for (const ShaderVariant& variant : variants) {
            ComPtr<ID3DBlob> vs;
            ComPtr<ID3DBlob> ps;
            ComPtr<ID3DBlob> compileError;
            if (FAILED(D3DCompile(variant.source, static_cast<UINT>(strlen(variant.source)),
                                  "probe.hlsl", nullptr, nullptr, "VSMain", "vs_5_1", 0, 0,
                                  &vs, &compileError))) {
                continue;
            }
            if (FAILED(D3DCompile(variant.source, static_cast<UINT>(strlen(variant.source)),
                                  "probe.hlsl", nullptr, nullptr, "PSMain", "ps_5_1", 0, 0,
                                  &ps, &compileError))) {
                continue;
            }

            D3D12_GRAPHICS_PIPELINE_STATE_DESC probePso = pso;
            probePso.VS = {vs->GetBufferPointer(), vs->GetBufferSize()};
            probePso.PS = {ps->GetBufferPointer(), ps->GetBufferSize()};
            if (!variant.withInputLayout) {
                probePso.InputLayout = {nullptr, 0};
            }

            ComPtr<ID3D12PipelineState> probePipeline;
            const HRESULT probeResult = device_->CreateGraphicsPipelineState(
                &probePso, IID_PPV_ARGS(&probePipeline));
            fprintf(stderr, "[sunshine-voxel] %s: %s\n", variant.name,
                    SUCCEEDED(probeResult) ? "accepted" : "refused");
            if (SUCCEEDED(probeResult)) {
                voxelPipeline_ = probePipeline;
                hr = S_OK;
                break;
            }
        }

        if (FAILED(hr)) {
            error = "the voxel pipeline could not be created: " +
                    std::to_string(static_cast<unsigned>(hr));
            reportDebugMessages(device_.Get());
            return false;
        }
    }
    // The sky pipeline. The same root signature and the same render
    // target, but no input layout and no depth write.
    D3D12_GRAPHICS_PIPELINE_STATE_DESC skyPso = pso;
    skyPso.VS = {skyVertexBlob->GetBufferPointer(), skyVertexBlob->GetBufferSize()};
    skyPso.PS = {skyPixelBlob->GetBufferPointer(), skyPixelBlob->GetBufferSize()};
    skyPso.InputLayout = {nullptr, 0};
    skyPso.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
    skyPso.DepthStencilState.DepthEnable = TRUE;
    skyPso.DepthStencilState.DepthWriteMask = D3D12_DEPTH_WRITE_MASK_ZERO;
    skyPso.DepthStencilState.DepthFunc = D3D12_COMPARISON_FUNC_ALWAYS;
    skyPso.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;

    hr = device_->CreateGraphicsPipelineState(&skyPso, IID_PPV_ARGS(&skyPipeline_));
    if (FAILED(hr)) {
        error = "the sky pipeline could not be created: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    // A pipeline that draws a quad without reading a vertex buffer. It
    // takes no constant buffer and no input layout, so it needs a root
    // signature of its own.
    {
        ComPtr<ID3DBlob> idVertex;
        ComPtr<ID3DBlob> idPixel;
        ComPtr<ID3DBlob> idError;
        if (FAILED(D3DCompile(kVertexIdShaderSource,
                              static_cast<UINT>(strlen(kVertexIdShaderSource)), "id.hlsl",
                              nullptr, nullptr, "VSMain", "vs_5_1", flags, 0, &idVertex, &idError)) ||
            FAILED(D3DCompile(kVertexIdShaderSource,
                              static_cast<UINT>(strlen(kVertexIdShaderSource)), "id.hlsl",
                              nullptr, nullptr, "PSMain", "ps_5_1", flags, 0, &idPixel, &idError))) {
            // The test shader is a diagnostic and is not needed to run.
            idVertex.Reset();
            idPixel.Reset();
        }

        if (!idVertex || !idPixel) {
            // The test pipeline is a diagnostic. Without it the engine
            // still runs.
            return true;
        }

        D3D12_ROOT_PARAMETER empty{};
        empty.ParameterType = D3D12_ROOT_PARAMETER_TYPE_CBV;
        empty.ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
        empty.Descriptor.ShaderRegister = 0;
        empty.Descriptor.RegisterSpace = 0;

        D3D12_ROOT_SIGNATURE_DESC emptyDesc{};
        emptyDesc.NumParameters = 1;
        emptyDesc.pParameters = &empty;
        emptyDesc.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;

        ComPtr<ID3DBlob> emptyBlob;
        ComPtr<ID3DBlob> emptyError;
        if (FAILED(D3D12SerializeRootSignature(&emptyDesc, D3D_ROOT_SIGNATURE_VERSION_1,
                                               &emptyBlob, &emptyError))) {
            error = "the test root signature could not be serialised";
            return false;
        }

        ComPtr<ID3D12RootSignature> emptySignature;
        if (FAILED(device_->CreateRootSignature(0, emptyBlob->GetBufferPointer(),
                                                emptyBlob->GetBufferSize(),
                                                IID_PPV_ARGS(&emptySignature)))) {
            error = "the test root signature could not be created";
            return false;
        }

        D3D12_GRAPHICS_PIPELINE_STATE_DESC idPso{};
        idPso.pRootSignature = emptySignature.Get();
        idPso.VS = {idVertex->GetBufferPointer(), idVertex->GetBufferSize()};
        idPso.PS = {idPixel->GetBufferPointer(), idPixel->GetBufferSize()};
        idPso.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
        idPso.NumRenderTargets = 1;
        idPso.RTVFormats[0] = DXGI_FORMAT_R8G8B8A8_UNORM;
        idPso.DSVFormat = DXGI_FORMAT_D32_FLOAT;
        idPso.SampleDesc.Count = 1;
        idPso.SampleMask = UINT_MAX;
        idPso.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
        idPso.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;
        idPso.RasterizerState.DepthClipEnable = TRUE;
        idPso.DepthStencilState.DepthEnable = TRUE;
        idPso.DepthStencilState.DepthWriteMask = D3D12_DEPTH_WRITE_MASK_ALL;
        idPso.DepthStencilState.DepthFunc = D3D12_COMPARISON_FUNC_LESS_EQUAL;
        idPso.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;

        hr = device_->CreateGraphicsPipelineState(&idPso, IID_PPV_ARGS(&vertexIdPipeline_));
        if (FAILED(hr)) {
            error = "the test pipeline could not be created: " +
                    std::to_string(static_cast<unsigned>(hr));
            return false;
        }
    }

    return true;
}

bool VoxelRenderer::createConstantBuffer(std::string& error) {
    D3D12_HEAP_PROPERTIES heap = defaultHeap(D3D12_HEAP_TYPE_UPLOAD);

    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = kConstantBufferSize;
    desc.Height = 1;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.Format = DXGI_FORMAT_UNKNOWN;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

    HRESULT hr = device_->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc,
                                                  D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
                                                  IID_PPV_ARGS(&constantBuffer_));
    if (FAILED(hr)) {
        error = "the constant buffer could not be created: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    constantView_.BufferLocation = constantBuffer_->GetGPUVirtualAddress();
    constantView_.SizeInBytes = kConstantBufferSize;
    constantView_.StrideInBytes = kConstantBufferSize;

    hr = constantBuffer_->Map(0, nullptr, &constantMapped_);
    if (FAILED(hr)) {
        error = "the constant buffer could not be mapped: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    // The gothic block, in a buffer of its own.
    D3D12_HEAP_PROPERTIES gothicHeap = defaultHeap(D3D12_HEAP_TYPE_UPLOAD);

    D3D12_RESOURCE_DESC gothicDesc{};
    gothicDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    gothicDesc.Width = 256;
    gothicDesc.Height = 1;
    gothicDesc.DepthOrArraySize = 1;
    gothicDesc.MipLevels = 1;
    gothicDesc.Format = DXGI_FORMAT_UNKNOWN;
    gothicDesc.SampleDesc.Count = 1;
    gothicDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

    hr = device_->CreateCommittedResource(&gothicHeap, D3D12_HEAP_FLAG_NONE, &gothicDesc,
                                          D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
                                          IID_PPV_ARGS(&gothicBuffer_));
    if (FAILED(hr)) {
        error = "the gothic buffer could not be created: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    gothicView_.BufferLocation = gothicBuffer_->GetGPUVirtualAddress();
    gothicView_.SizeInBytes = 256;
    gothicView_.StrideInBytes = 256;

    hr = gothicBuffer_->Map(0, nullptr, &gothicMapped_);
    if (FAILED(hr)) {
        error = "the gothic buffer could not be mapped: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    return true;
}

bool VoxelRenderer::createWindowTarget(HWND hwnd, uint32_t width, uint32_t height,
                                        std::string& error) {
    windowed_ = true;
    width_ = width;
    height_ = height;

    DXGI_SWAP_CHAIN_DESC1 desc{};
    desc.Width = width;
    desc.Height = height;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = frameCount_;
    desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    desc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;

    ComPtr<IDXGISwapChain1> swapChain1;
    HRESULT hr = factory_->CreateSwapChainForHwnd(queue_.Get(), hwnd, &desc, nullptr, nullptr,
                                                   &swapChain1);
    if (FAILED(hr)) {
        error = "the swap chain could not be created: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    // Alt+Enter would resize the window behind the user's back.
    factory_->MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);

    // The flip model wants the buffer count to be at least two.
    ComPtr<IDXGISwapChain3> chain3;
    if (FAILED(swapChain1.As(&chain3))) {
        error = "the swap chain does not support the interface the renderer needs";
        return false;
    }
    swapChain_ = chain3;

    frameIndex_ = swapChain_->GetCurrentBackBufferIndex();

    return createRenderTargetResources(error) && createDepthBuffer(error);
}

// Whether the engine is drawing the test quad rather than the world.
bool VoxelRenderer::isTestQuad() const {
    return GetEnvironmentVariableA("RAWR_VOXEL_TEST_QUAD", nullptr, 0) != 0;
}

bool VoxelRenderer::createOffscreenTarget(uint32_t width, uint32_t height, std::string& error) {
    windowed_ = false;
    width_ = width;
    height_ = height;
    frameCount_ = 1;

    // A switch that draws one known quad instead of the world, so that a
    // broken pipeline can be told apart from a broken world.
    if (isTestQuad()) {
        const float p[6][3] = {
            {-8.0f, -8.0f,  0.0f}, { 8.0f, -8.0f,  0.0f}, { 8.0f,  8.0f,  0.0f},
            {-8.0f, -8.0f,  0.0f}, { 8.0f,  8.0f,  0.0f}, {-8.0f,  8.0f,  0.0f},
        };
        std::vector<VoxelVertex> quad;
        for (const auto& v : p) {
            VoxelVertex vert;
            vert.x = v[0];
            vert.y = v[1];
            vert.z = v[2];
            vert.packed = static_cast<float>(packBlockAndFace(
                static_cast<uint8_t>(BlockType::Grass), 2, 3));
            quad.push_back(vert);
        }
        if (!uploadChunk(0, 0, quad, error)) return false;
    }

    D3D12_HEAP_PROPERTIES heap = defaultHeap(D3D12_HEAP_TYPE_DEFAULT);

    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    desc.Width = width;
    desc.Height = height;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;
    desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET;

    // The target is moved into the render target state once, and it stays
    // there. A committed resource cannot be created in the render target
    // state, because that is not one of the states a resource may start
    // in, so the move is a command like any other.
    //
    // Direct3D refuses a command list that holds a barrier it does not
    // like, and it does not say which part of the barrier it disliked.
    // So the shapes of the barrier are tried in turn, and the one that
    // worked is the one that is used from then on.
    HRESULT hr = device_->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc,
                                                  D3D12_RESOURCE_STATE_COMMON, nullptr,
                                                  IID_PPV_ARGS(&offscreen_));
    if (FAILED(hr)) {
        error = "the offscreen target could not be created: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    // The target is moved into the render target state once, and it stays
    // there. A committed resource cannot be created in the render target
    // state, because that is not one of the states a resource may start
    // in, so the move is a command like any other.
    {
        hr = allocator_->Reset();
        if (FAILED(hr)) {
            error = "the command allocator could not be reset: " +
                    std::to_string(static_cast<unsigned>(hr));
            return false;
        }
        hr = list_->Reset(allocator_.Get(), nullptr);
        if (FAILED(hr)) {
            error = "the command list could not be reset: " + std::to_string(static_cast<unsigned>(hr));
            return false;
        }

        D3D12_RESOURCE_BARRIER barrier{};
        makeTransitionBarrier(barrier, offscreen_.Get(), D3D12_RESOURCE_STATE_COMMON,
                              D3D12_RESOURCE_STATE_RENDER_TARGET);
        list_->ResourceBarrier(1, &barrier);

        hr = list_->Close();
        if (FAILED(hr)) {
            error = std::string("the command list could not be closed (") + __FUNCTION__ + "): " +
                    std::to_string(static_cast<unsigned>(hr));
            return false;
        }
        ID3D12CommandList* lists[] = {list_.Get()};
        queue_->ExecuteCommandLists(1, lists);
        waitForGpu();
    }

    return createRenderTargetResources(error) && createDepthBuffer(error);
}

bool VoxelRenderer::resizeTarget(uint32_t width, uint32_t height, std::string& error) {
    if (width == width_ && height == height_) return true;
    if (width == 0 || height == 0) return true;

    // The old buffers cannot be released while the GPU is still reading
    // them.
    waitForGpu();

    width_ = width;
    height_ = height;

    if (swapChain_) {
        const HRESULT hr = swapChain_->ResizeBuffers(frameCount_, width, height,
                                                      DXGI_FORMAT_R8G8B8A8_UNORM, 0);
        if (FAILED(hr)) {
            error = "the swap chain could not be resized: " + std::to_string(static_cast<unsigned>(hr));
            return false;
        }
    }

    if (!createRenderTargetResources(error)) return false;
    if (!createDepthBuffer(error)) return false;
    return true;
}

bool VoxelRenderer::createRenderTargetResources(std::string& error) {    D3D12_DESCRIPTOR_HEAP_DESC heapDesc{};
    heapDesc.NumDescriptors = frameCount_;
    heapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    heapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;

    HRESULT hr = device_->CreateDescriptorHeap(&heapDesc, IID_PPV_ARGS(&rtvHeap_));
    if (FAILED(hr)) {
        error = "the render target heap could not be created: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    rtvHandle_ = rtvHeap_->GetCPUDescriptorHandleForHeapStart();
    const uint32_t increment = device_->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);

    for (uint32_t i = 0; i < frameCount_; ++i) {
        D3D12_RENDER_TARGET_VIEW_DESC rtvDesc{};
        rtvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        rtvDesc.ViewDimension = D3D12_RTV_DIMENSION_TEXTURE2D;
        rtvDesc.Texture2D.MipSlice = 0;
        rtvDesc.Texture2D.PlaneSlice = 0;

        D3D12_CPU_DESCRIPTOR_HANDLE handle = rtvHandle_;
        handle.ptr += static_cast<SIZE_T>(i) * increment;

        if (swapChain_) {
            ComPtr<ID3D12Resource> backBuffer;
            hr = swapChain_->GetBuffer(i, IID_PPV_ARGS(&backBuffer));
            if (FAILED(hr)) {
                error = "the back buffer could not be read: " + std::to_string(static_cast<unsigned>(hr));
                return false;
            }
            device_->CreateRenderTargetView(backBuffer.Get(), &rtvDesc, handle);
        } else {
            device_->CreateRenderTargetView(offscreen_.Get(), &rtvDesc, handle);
        }
    }

    // The depth view.
    D3D12_DESCRIPTOR_HEAP_DESC dsvHeapDesc{};
    dsvHeapDesc.NumDescriptors = 1;
    dsvHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_DSV;
    dsvHeapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
    hr = device_->CreateDescriptorHeap(&dsvHeapDesc, IID_PPV_ARGS(&dsvHeap_));
    if (FAILED(hr)) {
        error = "the depth heap could not be created: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    dsvHandle_ = dsvHeap_->GetCPUDescriptorHandleForHeapStart();

    return true;
}

bool VoxelRenderer::createDepthBuffer(std::string& error) {
    D3D12_HEAP_PROPERTIES heap = defaultHeap(D3D12_HEAP_TYPE_DEFAULT);

    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    desc.Width = width_;
    desc.Height = height_;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.Format = DXGI_FORMAT_D32_FLOAT;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;
    desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL;

    HRESULT hr = device_->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc,
                                                  D3D12_RESOURCE_STATE_DEPTH_WRITE, nullptr,
                                                  IID_PPV_ARGS(&depth_));
    if (FAILED(hr)) {
        error = "the depth buffer could not be created: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    D3D12_DEPTH_STENCIL_VIEW_DESC dsvDesc{};
    dsvDesc.Format = DXGI_FORMAT_D32_FLOAT;
    dsvDesc.ViewDimension = D3D12_DSV_DIMENSION_TEXTURE2D;
    dsvDesc.Texture2D.MipSlice = 0;
    device_->CreateDepthStencilView(depth_.Get(), nullptr, dsvHandle_);

    return true;
}

bool VoxelRenderer::uploadChunk(int32_t chunkX, int32_t chunkZ,
                                 const std::vector<VoxelVertex>& vertices, std::string& error) {
    const uint64_t key = (static_cast<uint64_t>(static_cast<uint32_t>(chunkX)) << 32) |
                         static_cast<uint32_t>(chunkZ);

    if (vertices.empty()) {
        GpuChunk empty;
        chunks_[key] = std::move(empty);
        return true;
    }

    const UINT64 bufferSize = static_cast<UINT64>(vertices.size()) * sizeof(VoxelVertex);

    D3D12_HEAP_PROPERTIES heap = defaultHeap(D3D12_HEAP_TYPE_UPLOAD);

    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = bufferSize;
    desc.Height = 1;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.Format = DXGI_FORMAT_UNKNOWN;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

    GpuChunk chunk;
    HRESULT hr = device_->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc,
                                                  D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
                                                  IID_PPV_ARGS(&chunk.buffer));
    if (FAILED(hr)) {
        error = "the chunk vertex buffer could not be created: " +
                std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    void* mapped = nullptr;
    hr = chunk.buffer->Map(0, nullptr, &mapped);
    if (FAILED(hr)) {
        error = "the chunk vertex buffer could not be mapped: " +
                std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    memcpy(mapped, vertices.data(), static_cast<size_t>(bufferSize));
    chunk.buffer->Unmap(0, nullptr);

    chunk.view.BufferLocation = chunk.buffer->GetGPUVirtualAddress();
    chunk.view.SizeInBytes = static_cast<UINT>(bufferSize);
    chunk.view.StrideInBytes = sizeof(VoxelVertex);
    chunk.vertexCount = static_cast<uint32_t>(vertices.size());

    chunks_[key] = std::move(chunk);
    return true;
}

bool VoxelRenderer::renderFrame(const Mat4& viewProjection, const Vec3& cameraPosition,
                                double timeSeconds, FrameStats& stats, std::string& error) {
    const auto start = std::chrono::steady_clock::now();

    waitForGpu();

    HRESULT hr = allocator_->Reset();
    if (FAILED(hr)) {
        error = "the command allocator could not be reset: " +
                std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    hr = list_->Reset(allocator_.Get(), nullptr);
    if (FAILED(hr)) {
        error = "the command list could not be reset: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    updateConstantBuffer(viewProjection, cameraPosition, timeSeconds);

    // The target of this frame.
    ID3D12Resource* target = offscreen_.Get();
    if (swapChain_) {
        ComPtr<ID3D12Resource> backBuffer;
        if (FAILED(swapChain_->GetBuffer(frameIndex_, IID_PPV_ARGS(&backBuffer)))) {
            error = "the back buffer could not be read";
            return false;
        }
        target = backBuffer.Get();
    }

    // The target goes from being presented into being a render target.
    // The offscreen target is made for this and stays as it is.
    if (windowed_) {
        D3D12_RESOURCE_BARRIER barrier{};
        makeTransitionBarrier(barrier, target, D3D12_RESOURCE_STATE_PRESENT,
                              D3D12_RESOURCE_STATE_RENDER_TARGET);
        list_->ResourceBarrier(1, &barrier);
    }

    D3D12_CPU_DESCRIPTOR_HANDLE rtv = rtvHandle_;
    if (swapChain_) {
        const uint32_t increment =
            device_->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
        rtv.ptr += static_cast<SIZE_T>(frameIndex_) * increment;
    }

    const float clearColor[4] = {0.74f, 0.85f, 0.95f, 1.0f};
    list_->ClearRenderTargetView(rtv, clearColor, 0, nullptr);
    list_->ClearDepthStencilView(dsvHandle_, D3D12_CLEAR_FLAG_DEPTH, 1.0f, 0, 0, nullptr);

    list_->SetGraphicsRootSignature(rootSignature_.Get());
    list_->SetPipelineState(skyPipeline_.Get());
    list_->SetGraphicsRootConstantBufferView(0, constantView_.BufferLocation);
    list_->SetGraphicsRootConstantBufferView(1, gothicView_.BufferLocation);
    list_->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

    D3D12_VIEWPORT viewport{};
    viewport.Width = static_cast<float>(width_);
    viewport.Height = static_cast<float>(height_);
    viewport.MinDepth = 0.0f;
    viewport.MaxDepth = 1.0f;
    list_->RSSetViewports(1, &viewport);

    D3D12_RECT scissor{};
    scissor.right = static_cast<LONG>(width_);
    scissor.bottom = static_cast<LONG>(height_);
    list_->RSSetScissorRects(1, &scissor);

    // The sky is drawn first and it does not write the depth, so the
    // terrain is drawn over it.
    list_->OMSetRenderTargets(1, &rtv, FALSE, &dsvHandle_);
    list_->DrawInstanced(3, 1, 0, 0);

    // The terrain.
    list_->SetPipelineState(voxelPipeline_.Get());
    list_->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

    uint32_t chunksDrawn = 0;
    uint64_t verticesDrawn = 0;

    for (const auto& entry : chunks_) {
        const GpuChunk& chunk = entry.second;
        if (chunk.vertexCount == 0) continue;
        list_->IASetVertexBuffers(0, 1, &chunk.view);
        list_->DrawInstanced(chunk.vertexCount, 1, 0, 0);
        ++chunksDrawn;
        verticesDrawn += chunk.vertexCount;
    }

    // The target goes back to being presented.
    if (windowed_) {
        D3D12_RESOURCE_BARRIER barrier{};
        makeTransitionBarrier(barrier, target, D3D12_RESOURCE_STATE_RENDER_TARGET,
                              D3D12_RESOURCE_STATE_PRESENT);
        list_->ResourceBarrier(1, &barrier);
    }

    hr = list_->Close();
    if (FAILED(hr)) {
        error = std::string("the command list could not be closed (") + __FUNCTION__ + "): " +
                std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    ID3D12CommandList* lists[] = {list_.Get()};
    queue_->ExecuteCommandLists(1, lists);

    ++fenceValue_;
    hr = queue_->Signal(fence_.Get(), fenceValue_);
    if (FAILED(hr)) {
        error = "the fence could not be signalled: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    if (fence_->GetCompletedValue() < fenceValue_) {
        hr = fence_->SetEventOnCompletion(fenceValue_, fenceEvent_);
        if (FAILED(hr)) {
            error = "the fence event could not be armed: " + std::to_string(static_cast<unsigned>(hr));
            return false;
        }
        WaitForSingleObject(fenceEvent_, INFINITE);
    }

    if (swapChain_) {
        hr = swapChain_->Present(1, 0);
        if (FAILED(hr)) {
            error = "the frame could not be presented: " + std::to_string(static_cast<unsigned>(hr));
            return false;
        }
        lastRenderedIndex_ = frameIndex_;
        frameIndex_ = swapChain_->GetCurrentBackBufferIndex();
    } else {
        lastRenderedIndex_ = 0;
    }

    stats.frameIndex++;
    stats.chunksDrawn = chunksDrawn;
    stats.verticesDrawn = verticesDrawn;
    stats.trianglesDrawn = verticesDrawn / 3;
    stats.gpuFrameMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();

    return true;
}

bool VoxelRenderer::captureFrame(CapturedFrame& out, std::string& error) {
    const auto start = std::chrono::steady_clock::now();

    waitForGpu();

    HRESULT hr = S_OK;

    // The target that was drawn into. For a window this is the back
    // buffer of the frame that was just presented, and for the offscreen
    // target it is the texture itself.
    ID3D12Resource* target = offscreen_.Get();
    if (swapChain_) {
        ComPtr<ID3D12Resource> backBuffer;
        if (FAILED(swapChain_->GetBuffer(lastRenderedIndex_, IID_PPV_ARGS(&backBuffer)))) {
            error = "the back buffer could not be read";
            return false;
        }
        target = backBuffer.Get();
    }

    // The footprint of the copy. The rows of a texture are padded out to
    // a 256 byte boundary, so the copy is bigger than the picture, and
    // the readback buffer has to be the size of the copy and not the
    // size of the picture. A buffer that is too small is refused by the
    // runtime, and the command list is closed with an error.
    D3D12_RESOURCE_DESC targetDesc = target->GetDesc();
    D3D12_TEXTURE_COPY_LOCATION dst{};
    dst.pResource = nullptr;
    dst.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
    UINT64 rowSize = 0;
    UINT64 totalBytes = 0;
    device_->GetCopyableFootprints(&targetDesc, 0, 1, 0, &dst.PlacedFootprint, nullptr,
                                   &rowSize, &totalBytes);

    // The readback resource is made once and reused, and it is remade
    // when the target has changed size.
    if (!readback_ || readbackSize_ < totalBytes) {
        D3D12_HEAP_PROPERTIES heap = defaultHeap(D3D12_HEAP_TYPE_READBACK);

        D3D12_RESOURCE_DESC desc{};
        desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        desc.Width = totalBytes;
        desc.Height = 1;
        desc.DepthOrArraySize = 1;
        desc.MipLevels = 1;
        desc.Format = DXGI_FORMAT_UNKNOWN;
        desc.SampleDesc.Count = 1;
        desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

        ComPtr<ID3D12Resource> fresh;
        const HRESULT createResult = device_->CreateCommittedResource(
            &heap, D3D12_HEAP_FLAG_NONE, &desc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
            IID_PPV_ARGS(&fresh));
        if (FAILED(createResult)) {
            error = "the readback buffer could not be created: " +
                    std::to_string(static_cast<unsigned>(createResult));
            return false;
        }
        readback_ = fresh;
        readbackSize_ = totalBytes;
    }
    dst.pResource = readback_.Get();

    hr = allocator_->Reset();
    if (FAILED(hr)) {
        error = "the command allocator could not be reset: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    hr = list_->Reset(allocator_.Get(), nullptr);
    if (FAILED(hr)) {
        error = "the command list could not be reset: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    D3D12_TEXTURE_COPY_LOCATION src{};
    src.pResource = target;
    src.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
    src.SubresourceIndex = 0;

    const D3D12_RESOURCE_STATES stateBefore = windowed_ ? D3D12_RESOURCE_STATE_PRESENT
                                                         : D3D12_RESOURCE_STATE_RENDER_TARGET;

    {
        D3D12_RESOURCE_BARRIER barrier{};
        makeTransitionBarrier(barrier, target, stateBefore, D3D12_RESOURCE_STATE_COPY_SOURCE,
                              D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES);
        list_->ResourceBarrier(1, &barrier);
    }

    list_->CopyTextureRegion(&dst, 0, 0, 0, &src, nullptr);

    {
        D3D12_RESOURCE_BARRIER barrier{};
        makeTransitionBarrier(barrier, target, D3D12_RESOURCE_STATE_COPY_SOURCE,
                              windowed_ ? D3D12_RESOURCE_STATE_PRESENT
                                        : D3D12_RESOURCE_STATE_RENDER_TARGET,
                              D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES);
        list_->ResourceBarrier(1, &barrier);
    }

    hr = list_->Close();
    if (FAILED(hr)) {
        error = std::string("the command list could not be closed (") + __FUNCTION__ + "): " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    ID3D12CommandList* lists[] = {list_.Get()};
    queue_->ExecuteCommandLists(1, lists);

    ++fenceValue_;
    queue_->Signal(fence_.Get(), fenceValue_);
    if (fence_->GetCompletedValue() < fenceValue_) {
        fence_->SetEventOnCompletion(fenceValue_, fenceEvent_);
        WaitForSingleObject(fenceEvent_, INFINITE);
    }

    void* mapped = nullptr;
    hr = readback_->Map(0, nullptr, &mapped);
    if (FAILED(hr)) {
        error = "the readback buffer could not be mapped: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }

    // The rows come back padded, and in the order the GPU wrote them,
    // which is bottom-up.
    const uint32_t rowPitch = dst.PlacedFootprint.Footprint.RowPitch;
    const uint8_t* source = static_cast<const uint8_t*>(mapped);

    out.width = width_;
    out.height = height_;
    out.pixels.resize(static_cast<size_t>(width_) * height_ * 4);

    for (uint32_t y = 0; y < height_; ++y) {
        // The first row of the readback is the first row of the image.
        // A texture has its origin at the top left, and the copy writes
        // the rows in the order they are in the texture.
        const uint8_t* src = source + static_cast<size_t>(y) * rowPitch;
        uint8_t* dstPixels = out.pixels.data() + static_cast<size_t>(y) * width_ * 4;
        memcpy(dstPixels, src, static_cast<size_t>(width_) * 4);
    }

    readback_->Unmap(0, nullptr);

    return true;
}

void VoxelRenderer::waitForGpu() {
    if (!queue_ || !fence_) return;
    ++fenceValue_;
    queue_->Signal(fence_.Get(), fenceValue_);
    if (fence_->GetCompletedValue() < fenceValue_) {
        fence_->SetEventOnCompletion(fenceValue_, fenceEvent_);
        WaitForSingleObject(fenceEvent_, INFINITE);
    }
}

} // namespace sunshine
