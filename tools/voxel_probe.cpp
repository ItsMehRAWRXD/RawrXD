// Diagnostic probe: which D3D12 resource state and view combination this AMD
// driver accepts. Each variant runs in its own process because a device
// removal poisons the D3D12 runtime for the rest of the process.
//
//   voxel_probe <variant>
//
// Variants:
//   rtv_common        colour texture in COMMON + CreateRenderTargetView
//   rtv_copysrc       colour texture in COPY_DEST + CreateRenderTargetView
//   rtv_transition    colour texture in COPY_DEST, transitioned to
//                     RENDER_TARGET by a command list, then the RTV
//   dsv_d24_common    D24_UNORM_S8_UINT depth in COMMON + DSV
//   dsv_d24_copysrc   D24_UNORM_S8_UINT depth in COPY_DEST + DSV
//   dsv_d16_common    D16_UNORM depth in COMMON + DSV
//   dsv_d16_copysrc   D16_UNORM depth in COPY_DEST + DSV
//   dsv_d32_common    D32_FLOAT depth in COMMON + DSV
//   dsv_d32_trans     D32_FLOAT depth in COPY_DEST, transitioned to
//                     DEPTH_WRITE, then the DSV
//
// Not part of the shipped engine; a development instrument.
#include <cstdio>
#include <cstring>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

using Microsoft::WRL::ComPtr;

static ComPtr<ID3D12Device> g_dev;

static void Report(const char* label) {
    printf("  %-34s removed=0x%08lX %s\n", label,
           static_cast<unsigned long>(g_dev->GetDeviceRemovedReason()),
           g_dev->GetDeviceRemovedReason() == S_OK ? "OK" : "DEVICE REMOVED");
}

static ComPtr<ID3D12Resource> MakeTexture(DXGI_FORMAT format, D3D12_RESOURCE_STATES state) {
    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    desc.Width = 640;
    desc.Height = 480;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.Format = format;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;

    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_DEFAULT;
    ComPtr<ID3D12Resource> res;
    const HRESULT hr = g_dev->CreateCommittedResource(
        &heap, D3D12_HEAP_FLAG_NONE, &desc, state, nullptr, IID_PPV_ARGS(&res));
    printf("  create texture fmt=%d state=0x%X hr=0x%08lX %s\n", static_cast<int>(format),
           static_cast<unsigned>(state), static_cast<unsigned long>(hr),
           SUCCEEDED(hr) ? "OK" : "FAILED");
    return res;
}

// Transitions the resource to `target` with a real command list, so the
// driver sees the state change before the view is created.
static bool TransitionAndWait(ID3D12Resource* res, D3D12_RESOURCE_STATES target) {
    D3D12_COMMAND_QUEUE_DESC qd{};
    qd.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    ComPtr<ID3D12CommandQueue> queue;
    g_dev->CreateCommandQueue(&qd, IID_PPV_ARGS(&queue));

    ComPtr<ID3D12CommandAllocator> alloc;
    g_dev->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&alloc));
    ComPtr<ID3D12GraphicsCommandList> list;
    g_dev->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, alloc.Get(), nullptr,
                             IID_PPV_ARGS(&list));

    D3D12_RESOURCE_BARRIER barrier{};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = res;
    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_COPY_DEST;
    barrier.Transition.StateAfter = target;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    list->ResourceBarrier(1, &barrier);
    list->Close();
    ID3D12CommandList* lists[] = {list.Get()};
    queue->ExecuteCommandLists(1, lists);

    ComPtr<ID3D12Fence> fence;
    g_dev->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence));
    const UINT64 fenceTarget = 1;
    queue->Signal(fence.Get(), fenceTarget);
    if (fence->GetCompletedValue() < fenceTarget) {
        HANDLE event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        fence->SetEventOnCompletion(fenceTarget, event);
        WaitForSingleObject(event, INFINITE);
        CloseHandle(event);
    }
    return g_dev->GetDeviceRemovedReason() == S_OK;
}

int main(int argc, char** argv) {
    const char* variant = (argc > 1) ? argv[1] : "rtv_common";
    printf("=== variant: %s ===\n", variant);

    ComPtr<IDXGIFactory4> factory;
    CreateDXGIFactory2(0, IID_PPV_ARGS(&factory));
    ComPtr<IDXGIAdapter1> adapter;
    ComPtr<IDXGIAdapter> warp;
    const bool useWarp = strstr(variant, "warp") != nullptr;
    if (useWarp) {
        factory->EnumWarpAdapter(IID_PPV_ARGS(&warp));
        printf("adapter: WARP (software rasterizer)\n");
    } else {
        factory->EnumAdapters1(0, &adapter);
        DXGI_ADAPTER_DESC1 ad{};
        adapter->GetDesc1(&ad);
        printf("adapter: %ls\n", ad.Description);
    }

    if (FAILED(D3D12CreateDevice(useWarp ? static_cast<IUnknown*>(warp.Get())
                                         : static_cast<IUnknown*>(adapter.Get()),
                                 D3D_FEATURE_LEVEL_12_0, IID_PPV_ARGS(&g_dev)))) {
        printf("D3D12CreateDevice failed\n");
        return 1;
    }
    Report("device created");

    const bool wantRtv = strstr(variant, "rtv") != nullptr;
    const bool isD32 = strstr(variant, "d32") != nullptr;
    const bool isD16 = strstr(variant, "d16") != nullptr;
    const bool isD24 = strstr(variant, "d24") != nullptr;
    const bool useCommon = strstr(variant, "common") != nullptr;
    const bool useTransition = strstr(variant, "transition") != nullptr ||
                               strstr(variant, "trans") != nullptr;

    const DXGI_FORMAT format = strstr(variant, "uav") != nullptr ? DXGI_FORMAT_R32_FLOAT
                             : wantRtv ? DXGI_FORMAT_R8G8B8A8_UNORM
                             : isD32  ? DXGI_FORMAT_D32_FLOAT
                             : isD16  ? DXGI_FORMAT_D16_UNORM
                                       : DXGI_FORMAT_D24_UNORM_S8_UINT;

    const D3D12_RESOURCE_STATES createState = useCommon ? D3D12_RESOURCE_STATE_COMMON
                                                        : D3D12_RESOURCE_STATE_COPY_DEST;
    ComPtr<ID3D12Resource> res = MakeTexture(format, createState);
    if (!res) return 1;

    if (useTransition) {
        const D3D12_RESOURCE_STATES target = wantRtv ? D3D12_RESOURCE_STATE_RENDER_TARGET
                                                     : D3D12_RESOURCE_STATE_DEPTH_WRITE;
        printf("  transition to 0x%X -> %s\n", static_cast<unsigned>(target),
               TransitionAndWait(res.Get(), target) ? "OK" : "FAILED");
        Report("after transition");
    }

    D3D12_DESCRIPTOR_HEAP_DESC heapDesc{};
    heapDesc.NumDescriptors = 1;
    heapDesc.Type = wantRtv ? D3D12_DESCRIPTOR_HEAP_TYPE_RTV
                            : D3D12_DESCRIPTOR_HEAP_TYPE_DSV;
    ComPtr<ID3D12DescriptorHeap> heap;
    g_dev->CreateDescriptorHeap(&heapDesc, IID_PPV_ARGS(&heap));
    Report("descriptor heap created");

    if (wantRtv) {
        g_dev->CreateRenderTargetView(res.Get(), nullptr,
                                       heap->GetCPUDescriptorHandleForHeapStart());
        Report("CreateRenderTargetView");
    } else if (strstr(variant, "uav") != nullptr) {
        // A UAV on a texture needs a UAV-writable format. R32_FLOAT is one.
        D3D12_DESCRIPTOR_HEAP_DESC uavHeapDesc{};
        uavHeapDesc.NumDescriptors = 1;
        uavHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
        ComPtr<ID3D12DescriptorHeap> uavHeap;
        g_dev->CreateDescriptorHeap(&uavHeapDesc, IID_PPV_ARGS(&uavHeap));
        g_dev->CreateUnorderedAccessView(res.Get(), nullptr, nullptr,
                                         uavHeap->GetCPUDescriptorHandleForHeapStart());
        Report("CreateUnorderedAccessView");
    } else {
        D3D12_DEPTH_STENCIL_VIEW_DESC dv{};
        dv.Format = format;
        dv.ViewDimension = D3D12_DSV_DIMENSION_TEXTURE2D;
        dv.Flags = D3D12_DSV_FLAG_NONE;
        g_dev->CreateDepthStencilView(res.Get(), nullptr,
                                      heap->GetCPUDescriptorHandleForHeapStart());
        Report("CreateDepthStencilView");
    }
    return 0;
}
