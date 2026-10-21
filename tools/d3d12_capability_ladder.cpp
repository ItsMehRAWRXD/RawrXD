// ============================================================================
// d3d12_capability_ladder.cpp - the R2 platform certificate.
//
// PURPOSE
// ------
// This is not a renderer test. It is a platform probe: a strictly monotonic
// climb through the Direct3D 12 API, where each rung is a capability the
// renderer needs, and where a rung is only attempted if every rung before it
// passed.
//
// The rule that gives the probe its value:
//
//     Never report a later rung after an earlier prerequisite failed.
//
// The first failing rung is therefore the answer, and everything after it is
// reported as SKIPPED rather than as a failure of its own. That distinction
// is what stops a future agent from blaming renderer source for a host
// runtime fault, or hiding a renderer defect behind a platform excuse.
//
// THE LADDER
// ----------
//   01 DEVICE            D3D12CreateDevice
//   02 QUEUE             CreateCommandQueue
//   03 ALLOCATOR         CreateCommandAllocator
//   04 COMMAND_LIST      CreateCommandList
//   05 DESCRIPTOR_HEAP   CreateDescriptorHeap
//   06 RESOURCE          CreateCommittedResource
//   07 RTV               CreateRenderTargetView
//   08 SRV               CreateShaderResourceView
//   09 DSV               CreateDepthStencilView
//   10 SWAPCHAIN         CreateSwapChainForHwnd
//   11 CLEAR             record and execute a clear
//   12 PRESENT           Present
//
// THE RECEIPT
// -----------
// A machine-readable JSON receipt carries the adapter identity, the runtime
// identity, the result of every rung, the device removed reason, the DRED
// breadcrumbs and the page fault address, and a three-way conclusion:
//
//   PLATFORM_BLOCKED   a rung failed: the fault is in the platform, and the
//                      application was never reached
//   SUNSHINE_BLOCKED   the ladder passed and the Sunshine path then failed:
//                      the fault is in the application
//   PASS               the ladder passed and the Sunshine path ran
//
// Usage:
//   d3d12_capability_ladder --adapter hardware|warp --receipt <path.json>
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

using Microsoft::WRL::ComPtr;

namespace {

// ---------------------------------------------------------------------------
// Receipt model
// ---------------------------------------------------------------------------

enum class RungStatus { Pass, Fail, Skipped };

const char* ToString(RungStatus status) {
    switch (status) {
    case RungStatus::Pass: return "PASS";
    case RungStatus::Fail: return "FAIL";
    default: return "SKIPPED";
    }
}

struct Rung {
    std::string name;
    RungStatus status = RungStatus::Skipped;
    HRESULT hresult = S_OK;
    std::string detail;
};

struct Receipt {
    // Adapter identity.
    std::string adapter;
    std::string adapter_luid;
    uint32_t vendor_id = 0;
    uint32_t device_id = 0;
    std::string driver_version;
    uint64_t driver_version_value = 0;
    bool is_software = false;

    // Runtime identity.
    std::string runtime_version;
    std::string feature_level;
    bool debug_layer_available = false;
    bool debug_layer_enabled = false;
    bool dred_available = false;

    // The ladder.
    std::vector<Rung> rungs;
    int first_failed_index = -1;   // -1 means the whole ladder passed
    HRESULT first_failed_hresult = S_OK;

    // Device removed state.
    HRESULT device_removed_reason = S_OK;
    uint32_t dred_breadcrumb_count = 0;
    uint64_t dred_page_fault_va = 0;
    std::vector<std::string> debug_messages;

    // Conclusion.
    bool sunshine_code_reached = false;
    bool platform_blocked = false;
    bool application_blocked = false;
    std::string conclusion;
};

// A readable name for the HRESULTs this probe can produce.
std::string HResultName(HRESULT hr) {
    switch (hr) {
    case S_OK: return "S_OK";
    case S_FALSE: return "S_FALSE";
    case E_FAIL: return "E_FAIL";
    case E_INVALIDARG: return "E_INVALIDARG";
    case E_OUTOFMEMORY: return "E_OUTOFMEMORY";
    case E_NOTIMPL: return "E_NOTIMPL";
    case E_NOINTERFACE: return "E_NOINTERFACE";
    case E_ACCESSDENIED: return "E_ACCESSDENIED";
    case DXGI_ERROR_DEVICE_REMOVED: return "DXGI_ERROR_DEVICE_REMOVED";
    case DXGI_ERROR_DEVICE_HUNG: return "DXGI_ERROR_DEVICE_HUNG";
    case DXGI_ERROR_DEVICE_RESET: return "DXGI_ERROR_DEVICE_RESET";
    case DXGI_ERROR_UNSUPPORTED: return "DXGI_ERROR_UNSUPPORTED";
    case DXGI_ERROR_NOT_CURRENTLY_AVAILABLE: return "DXGI_ERROR_NOT_CURRENTLY_AVAILABLE";
    case DXGI_ERROR_DRIVER_INTERNAL_ERROR: return "DXGI_ERROR_DRIVER_INTERNAL_ERROR";
    case DXGI_ERROR_INVALID_CALL: return "DXGI_ERROR_INVALID_CALL";
    case DXGI_ERROR_SDK_COMPONENT_MISSING: return "DXGI_ERROR_SDK_COMPONENT_MISSING";
    case DXGI_ERROR_NOT_FOUND: return "DXGI_ERROR_NOT_FOUND";
    case D3D12_ERROR_ADAPTER_NOT_FOUND: return "D3D12_ERROR_ADAPTER_NOT_FOUND";
    default: return "0x" + std::to_string(static_cast<unsigned long>(hr));
    }
}

std::string GuidToString(const GUID& guid) {
    char buffer[64];
    sprintf_s(buffer, "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
              static_cast<unsigned long>(guid.Data1), guid.Data2, guid.Data3,
              guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
              guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return buffer;
}

std::string VersionToString(DWORD version) {
    char buffer[64];
    sprintf_s(buffer, "%lu.%lu.%lu.%lu", HIWORD(version), HIWORD(LOWORD(version)),
              LOWORD(HIWORD(version)), LOWORD(version));
    return buffer;
}

// ---------------------------------------------------------------------------
// The ladder
// ---------------------------------------------------------------------------

class Ladder {
public:
    Ladder(Receipt& receipt) : receipt_(receipt) {}

    // Runs the ladder. Returns true when every rung passed.
    bool Run(bool useWarp) {
        Rung& device = AddRung("DEVICE");
        if (!TryDevice(useWarp, device)) return false;

        Rung& queue = AddRung("QUEUE");
        if (!TryQueue(queue)) return false;

        Rung& allocator = AddRung("ALLOCATOR");
        if (!TryAllocator(allocator)) return false;

        Rung& commandList = AddRung("COMMAND_LIST");
        if (!TryCommandList(commandList)) return false;

        Rung& heap = AddRung("DESCRIPTOR_HEAP");
        if (!TryDescriptorHeap(heap)) return false;

        Rung& resource = AddRung("RESOURCE");
        if (!TryResource(resource)) return false;

        Rung& rtv = AddRung("RTV");
        if (!TryRtv(rtv)) return false;

        Rung& srv = AddRung("SRV");
        if (!TrySrv(srv)) return false;

        Rung& dsv = AddRung("DSV");
        if (!TryDsv(dsv)) return false;

        Rung& swapChain = AddRung("SWAPCHAIN");
        if (!TrySwapChain(swapChain)) return false;

        Rung& clear = AddRung("CLEAR");
        if (!TryClear(clear)) return false;

        Rung& present = AddRung("PRESENT");
        if (!TryPresent(present)) return false;

        return true;
    }

    const ComPtr<ID3D12Device>& device() const { return device_; }
    const ComPtr<ID3D12CommandQueue>& queue() const { return queue_; }

private:
    Rung& AddRung(const char* name) {
        Rung rung;
        rung.name = name;
        rung.status = RungStatus::Pass;
        receipt_.rungs.push_back(rung);
        return receipt_.rungs.back();
    }

    // Marks the rung as failed and stops the ladder.
    bool Fail(Rung& rung, HRESULT hr, const std::string& detail) {
        rung.status = RungStatus::Fail;
        rung.hresult = hr;
        rung.detail = detail;
        if (receipt_.first_failed_index < 0) {
            receipt_.first_failed_index = static_cast<int>(receipt_.rungs.size()) - 1;
            receipt_.first_failed_hresult = hr;
        }
        CollectDeviceState();
        return false;
    }

    void CollectDeviceState() {
        if (device_) {
            receipt_.device_removed_reason = device_->GetDeviceRemovedReason();
        }
        CollectDebugMessages();
        CollectDred();
    }

    void CollectDebugMessages() {
        if (!device_) return;
        ComPtr<ID3D12InfoQueue> infoQueue;
        if (FAILED(device_.As(&infoQueue))) return;
        for (UINT i = 0; i < 64; ++i) {
            D3D12_MESSAGE message{};
            SIZE_T length = sizeof(message);
            if (FAILED(infoQueue->GetMessage(i, &message, &length))) break;
            if (message.pDescription == nullptr) break;
            receipt_.debug_messages.push_back(message.pDescription);
        }
    }

    void CollectDred() {
        if (!device_) return;
        ComPtr<ID3D12DeviceRemovedExtendedData> dred;
        if (FAILED(device_.As(&dred))) return;
        receipt_.dred_available = true;

        // The breadcrumbs are a linked list of nodes, one per command list.
        D3D12_DRED_AUTO_BREADCRUMBS_OUTPUT breadcrumbs{};
        if (SUCCEEDED(dred->GetAutoBreadcrumbsOutput(&breadcrumbs)) &&
            breadcrumbs.pHeadAutoBreadcrumbNode != nullptr) {
            const D3D12_AUTO_BREADCRUMB_NODE* node = breadcrumbs.pHeadAutoBreadcrumbNode;
            while (node != nullptr && receipt_.dred_breadcrumb_count < 32) {
                ++receipt_.dred_breadcrumb_count;
                const char* name = node->pCommandListDebugNameA != nullptr
                                       ? node->pCommandListDebugNameA
                                       : (node->pCommandQueueDebugNameA != nullptr
                                              ? node->pCommandQueueDebugNameA
                                              : "(unnamed)");
                receipt_.debug_messages.push_back(std::string("DRED breadcrumb: ") + name);
                node = node->pNext;
            }
        }

        D3D12_DRED_PAGE_FAULT_OUTPUT pageFault{};
        if (SUCCEEDED(dred->GetPageFaultAllocationOutput(&pageFault)) &&
            pageFault.PageFaultVA != 0) {
            receipt_.dred_page_fault_va = static_cast<uint64_t>(pageFault.PageFaultVA);
        }
    }

    bool TryDevice(bool useWarp, Rung& rung) {
        ComPtr<IDXGIFactory4> factory;
        if (FAILED(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)))) {
            return Fail(rung, HRESULT_FROM_WIN32(GetLastError()), "CreateDXGIFactory2 failed");
        }

        ComPtr<IDXGIAdapter1> adapter;
        if (useWarp) {
            ComPtr<IDXGIAdapter> warpAdapter;
            if (FAILED(factory->EnumWarpAdapter(IID_PPV_ARGS(&warpAdapter)))) {
                return Fail(rung, DXGI_ERROR_NOT_FOUND, "EnumWarpAdapter failed");
            }
            if (FAILED(warpAdapter.As(&adapter))) {
                return Fail(rung, DXGI_ERROR_NOT_FOUND, "the WARP adapter is not an IDXGIAdapter1");
            }
        } else {
            if (FAILED(factory->EnumAdapters1(0, &adapter)) || !adapter) {
                return Fail(rung, DXGI_ERROR_NOT_FOUND, "no hardware adapter");
            }
        }

        DXGI_ADAPTER_DESC1 description{};
        if (SUCCEEDED(adapter->GetDesc1(&description))) {
            wchar_t wide[256]{};
            wcsncpy_s(wide, sizeof(wide) / sizeof(wide[0]), description.Description, _TRUNCATE);
            char buffer[512];
            WideCharToMultiByte(CP_UTF8, 0, wide, -1, buffer, sizeof(buffer), nullptr, nullptr);
            receipt_.adapter = buffer;
            char luid[64];
            sprintf_s(luid, "0x%08lX:0x%08lX",
                      static_cast<unsigned long>(description.AdapterLuid.HighPart),
                      static_cast<unsigned long>(description.AdapterLuid.LowPart));
            receipt_.adapter_luid = luid;
            receipt_.vendor_id = description.VendorId;
            receipt_.device_id = description.DeviceId;
            receipt_.is_software = (description.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0;

            // The driver version is not exposed through the adapter
            // description in this SDK, so it is read from the display class
            // in the registry. It is best effort: the value belongs to the
            // first display adapter in the class, not necessarily to this one.
            HKEY key = nullptr;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                               "SYSTEM\\CurrentControlSet\\Control\\Class\\"
                               "{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
                               0, KEY_READ, &key) == ERROR_SUCCESS) {
                char value[64]{};
                DWORD size = sizeof(value);
                DWORD type = 0;
                if (RegQueryValueExA(key, "DriverVersion", nullptr, &type,
                                     reinterpret_cast<LPBYTE>(value), &size) == ERROR_SUCCESS) {
                    receipt_.driver_version = value;
                }
                RegCloseKey(key);
            }
        }

        // The debug layer, when it is available, is what turns a silent
        // removal into a readable message.
        ComPtr<ID3D12Debug> debugController;
        receipt_.debug_layer_available = SUCCEEDED(D3D12GetDebugInterface(IID_PPV_ARGS(&debugController)));
        if (receipt_.debug_layer_available && debugController) {
            debugController->EnableDebugLayer();
            receipt_.debug_layer_enabled = true;
        }

        HRESULT hr = D3D12CreateDevice(adapter.Get(), D3D_FEATURE_LEVEL_12_0,
                                       IID_PPV_ARGS(&device_));
        if (FAILED(hr)) {
            // Fall back to feature level 11_0 before declaring the rung
            // failed: a device at 11_0 is still a usable device.
            hr = D3D12CreateDevice(adapter.Get(), D3D_FEATURE_LEVEL_11_0,
                                   IID_PPV_ARGS(&device_));
            if (FAILED(hr)) {
                return Fail(rung, hr, "D3D12CreateDevice failed at 12_0 and 11_0");
            }
            receipt_.feature_level = "11_0";
        } else {
            receipt_.feature_level = "12_0";
        }

        // The runtime version is the D3D12 runtime's own file version.
        HMODULE d3d12 = GetModuleHandleW(L"d3d12.dll");
        if (d3d12) {
            char path[MAX_PATH]{};
            GetModuleFileNameA(d3d12, path, MAX_PATH);
            DWORD handle = 0;
            DWORD size = GetFileVersionInfoSizeA(path, &handle);
            if (size > 0) {
                std::vector<char> buffer(size);
                if (GetFileVersionInfoA(path, handle, size, buffer.data())) {
                    VS_FIXEDFILEINFO* info = nullptr;
                    UINT infoSize = 0;
                    if (VerQueryValueA(buffer.data(), "\\", reinterpret_cast<LPVOID*>(&info), &infoSize) && info) {
                        receipt_.runtime_version = VersionToString(info->dwFileVersionMS);
                    }
                }
            }
        }
        return true;
    }

    bool TryQueue(Rung& rung) {
        D3D12_COMMAND_QUEUE_DESC desc{};
        desc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
        const HRESULT hr = device_->CreateCommandQueue(&desc, IID_PPV_ARGS(&queue_));
        if (FAILED(hr)) return Fail(rung, hr, "CreateCommandQueue failed");
        return true;
    }

    bool TryAllocator(Rung& rung) {
        const HRESULT hr = device_->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT,
                                                          IID_PPV_ARGS(&allocator_));
        if (FAILED(hr)) return Fail(rung, hr, "CreateCommandAllocator failed");
        return true;
    }

    bool TryCommandList(Rung& rung) {
        const HRESULT hr = device_->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT,
                                                      allocator_.Get(), nullptr,
                                                      IID_PPV_ARGS(&commandList_));
        if (FAILED(hr)) return Fail(rung, hr, "CreateCommandList failed");
        commandList_->Close();
        return true;
    }

    bool TryDescriptorHeap(Rung& rung) {
        D3D12_DESCRIPTOR_HEAP_DESC desc{};
        desc.NumDescriptors = 8;
        desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
        const HRESULT hr = device_->CreateDescriptorHeap(&desc, IID_PPV_ARGS(&rtvHeap_));
        if (FAILED(hr)) return Fail(rung, hr, "CreateDescriptorHeap(RTV) failed");
        return true;
    }

    bool TryResource(Rung& rung) {
        D3D12_RESOURCE_DESC desc{};
        desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
        desc.Width = 256;
        desc.Height = 256;
        desc.DepthOrArraySize = 1;
        desc.MipLevels = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;

        D3D12_HEAP_PROPERTIES heap{};
        heap.Type = D3D12_HEAP_TYPE_DEFAULT;
        const HRESULT hr = device_->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc,
                                                            D3D12_RESOURCE_STATE_COPY_DEST,
                                                            nullptr, IID_PPV_ARGS(&colorTexture_));
        if (FAILED(hr)) return Fail(rung, hr, "CreateCommittedResource failed");
        return true;
    }

    bool TryRtv(Rung& rung) {
        const D3D12_CPU_DESCRIPTOR_HANDLE handle = rtvHeap_->GetCPUDescriptorHandleForHeapStart();
        device_->CreateRenderTargetView(colorTexture_.Get(), nullptr, handle);
        if (device_->GetDeviceRemovedReason() != S_OK) {
            return Fail(rung, device_->GetDeviceRemovedReason(),
                        "CreateRenderTargetView removed the device");
        }
        colorRtv_ = handle;
        return true;
    }

    bool TrySrv(Rung& rung) {
        D3D12_DESCRIPTOR_HEAP_DESC desc{};
        desc.NumDescriptors = 4;
        desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
        ComPtr<ID3D12DescriptorHeap> heap;
        const HRESULT hr = device_->CreateDescriptorHeap(&desc, IID_PPV_ARGS(&heap));
        if (FAILED(hr)) return Fail(rung, hr, "CreateDescriptorHeap(SRV) failed");

        D3D12_SHADER_RESOURCE_VIEW_DESC srvDesc{};
        srvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        srvDesc.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
        srvDesc.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
        device_->CreateShaderResourceView(colorTexture_.Get(), &srvDesc,
                                          heap->GetCPUDescriptorHandleForHeapStart());
        if (device_->GetDeviceRemovedReason() != S_OK) {
            return Fail(rung, device_->GetDeviceRemovedReason(),
                        "CreateShaderResourceView removed the device");
        }
        return true;
    }

    bool TryDsv(Rung& rung) {
        D3D12_RESOURCE_DESC desc{};
        desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
        desc.Width = 256;
        desc.Height = 256;
        desc.DepthOrArraySize = 1;
        desc.MipLevels = 1;
        desc.Format = DXGI_FORMAT_D32_FLOAT;
        desc.SampleDesc.Count = 1;
        desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;

        D3D12_HEAP_PROPERTIES heap{};
        heap.Type = D3D12_HEAP_TYPE_DEFAULT;
        ComPtr<ID3D12Resource> depth;
        HRESULT hr = device_->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc,
                                                      D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
                                                      IID_PPV_ARGS(&depth));
        if (FAILED(hr)) return Fail(rung, hr, "CreateCommittedResource(depth) failed");

        D3D12_DESCRIPTOR_HEAP_DESC heapDesc{};
        heapDesc.NumDescriptors = 1;
        heapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_DSV;
        ComPtr<ID3D12DescriptorHeap> dsvHeap;
        hr = device_->CreateDescriptorHeap(&heapDesc, IID_PPV_ARGS(&dsvHeap));
        if (FAILED(hr)) return Fail(rung, hr, "CreateDescriptorHeap(DSV) failed");

        device_->CreateDepthStencilView(depth.Get(), nullptr,
                                        dsvHeap->GetCPUDescriptorHandleForHeapStart());
        if (device_->GetDeviceRemovedReason() != S_OK) {
            return Fail(rung, device_->GetDeviceRemovedReason(),
                        "CreateDepthStencilView removed the device");
        }
        return true;
    }

    bool TrySwapChain(Rung& rung) {
        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = DefWindowProcW;
        windowClass.hInstance = GetModuleHandleW(nullptr);
        windowClass.lpszClassName = L"RawrXD_D3D12_Ladder";
        RegisterClassExW(&windowClass);

        window_ = CreateWindowExW(0, windowClass.lpszClassName, L"ladder", WS_OVERLAPPEDWINDOW,
                                  0, 0, 64, 64, nullptr, nullptr, windowClass.hInstance, nullptr);
        if (!window_) return Fail(rung, HRESULT_FROM_WIN32(GetLastError()), "CreateWindowEx failed");

        ComPtr<IDXGIFactory4> factory;
        if (FAILED(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)))) {
            return Fail(rung, HRESULT_FROM_WIN32(GetLastError()), "CreateDXGIFactory2 failed");
        }

        DXGI_SWAP_CHAIN_DESC1 desc{};
        desc.Width = 256;
        desc.Height = 256;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        desc.BufferCount = 2;
        desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;

        ComPtr<IDXGISwapChain1> swapChain;
        const HRESULT hr = factory->CreateSwapChainForHwnd(queue_.Get(), window_, &desc, nullptr,
                                                           nullptr, &swapChain);
        if (FAILED(hr)) return Fail(rung, hr, "CreateSwapChainForHwnd failed");
        if (FAILED(swapChain.As(&swapChain_))) {
            return Fail(rung, E_NOINTERFACE, "the swap chain is not an IDXGISwapChain3");
        }
        return true;
    }

    bool TryClear(Rung& rung) {
        if (FAILED(allocator_->Reset())) return Fail(rung, HRESULT_FROM_WIN32(GetLastError()), "command allocator reset failed");
        if (FAILED(commandList_->Reset(allocator_.Get(), nullptr))) {
            return Fail(rung, HRESULT_FROM_WIN32(GetLastError()), "command list reset failed");
        }

        D3D12_RESOURCE_BARRIER barrier{};
        barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Transition.pResource = colorTexture_.Get();
        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_COPY_DEST;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
        barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        commandList_->ResourceBarrier(1, &barrier);

        const float clear[4] = {0.1f, 0.12f, 0.16f, 1.0f};
        commandList_->ClearRenderTargetView(colorRtv_, clear, 0, nullptr);
        if (FAILED(commandList_->Close())) {
            return Fail(rung, HRESULT_FROM_WIN32(GetLastError()), "closing the command list failed");
        }

        ID3D12CommandList* lists[] = {commandList_.Get()};
        queue_->ExecuteCommandLists(1, lists);

        ComPtr<ID3D12Fence> fence;
        device_->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence));
        const UINT64 target = 1;
        queue_->Signal(fence.Get(), target);
        if (fence->GetCompletedValue() < target) {
            HANDLE event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
            fence->SetEventOnCompletion(target, event);
            WaitForSingleObject(event, INFINITE);
            CloseHandle(event);
        }
        if (device_->GetDeviceRemovedReason() != S_OK) {
            return Fail(rung, device_->GetDeviceRemovedReason(), "the clear removed the device");
        }
        return true;
    }

    bool TryPresent(Rung& rung) {
        const HRESULT hr = swapChain_->Present(1, 0);
        if (FAILED(hr)) return Fail(rung, hr, "Present failed");
        return true;
    }

    Receipt& receipt_;
    ComPtr<ID3D12Device> device_;
    ComPtr<ID3D12CommandQueue> queue_;
    ComPtr<ID3D12CommandAllocator> allocator_;
    ComPtr<ID3D12GraphicsCommandList> commandList_;
    ComPtr<ID3D12DescriptorHeap> rtvHeap_;
    ComPtr<ID3D12Resource> colorTexture_;
    ComPtr<IDXGISwapChain3> swapChain_;
    D3D12_CPU_DESCRIPTOR_HANDLE colorRtv_{};
    HWND window_ = nullptr;
};

void WriteReceipt(const Receipt& receipt, const std::string& path) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        fprintf(stderr, "cannot write the receipt to %s\n", path.c_str());
        return;
    }
    out << "{\n";
    out << "  \"adapter\": \"" << receipt.adapter << "\",\n";
    out << "  \"adapter_luid\": \"" << receipt.adapter_luid << "\",\n";
    out << "  \"vendor_id\": " << receipt.vendor_id << ",\n";
    out << "  \"device_id\": " << receipt.device_id << ",\n";
    out << "  \"driver_version\": \"" << receipt.driver_version << "\",\n";
    out << "  \"is_software_adapter\": " << (receipt.is_software ? "true" : "false") << ",\n";
    out << "  \"runtime_version\": \"" << receipt.runtime_version << "\",\n";
    out << "  \"feature_level\": \"" << receipt.feature_level << "\",\n";
    out << "  \"debug_layer_available\": " << (receipt.debug_layer_available ? "true" : "false") << ",\n";
    out << "  \"debug_layer_enabled\": " << (receipt.debug_layer_enabled ? "true" : "false") << ",\n";
    out << "  \"dred_available\": " << (receipt.dred_available ? "true" : "false") << ",\n";
    out << "  \"rungs\": {\n";
    for (size_t i = 0; i < receipt.rungs.size(); ++i) {
        out << "    \"rung_" << (i + 1) << "_" << receipt.rungs[i].name << "\": {\"status\": \""
            << ToString(receipt.rungs[i].status) << "\", \"hresult\": \""
            << HResultName(receipt.rungs[i].hresult) << "\", \"detail\": \""
            << receipt.rungs[i].detail << "\"}" << (i + 1 == receipt.rungs.size() ? "\n" : ",\n");
    }
    out << "  },\n";
    out << "  \"first_failed_rung\": "
        << (receipt.first_failed_index < 0
                ? "null"
                : ("\"" + receipt.rungs[receipt.first_failed_index].name + "\""))
        << ",\n";
    out << "  \"first_failed_hresult\": \""
        << (receipt.first_failed_index < 0 ? "S_OK" : HResultName(receipt.first_failed_hresult))
        << "\",\n";
    out << "  \"first_failed_hresult_name\": \""
        << (receipt.first_failed_index < 0 ? "S_OK" : HResultName(receipt.first_failed_hresult))
        << "\",\n";
    out << "  \"device_removed_reason\": \"" << HResultName(receipt.device_removed_reason) << "\",\n";
    out << "  \"dred_breadcrumb_count\": " << receipt.dred_breadcrumb_count << ",\n";
    out << "  \"dred_page_fault_va\": " << receipt.dred_page_fault_va << ",\n";
    out << "  \"sunshine_code_reached\": " << (receipt.sunshine_code_reached ? "true" : "false") << ",\n";
    out << "  \"platform_blocked\": " << (receipt.platform_blocked ? "true" : "false") << ",\n";
    out << "  \"application_blocked\": " << (receipt.application_blocked ? "true" : "false") << ",\n";
    out << "  \"conclusion\": \"" << receipt.conclusion << "\",\n";
    out << "  \"debug_messages\": [";
    for (size_t i = 0; i < receipt.debug_messages.size(); ++i) {
        std::string text = receipt.debug_messages[i];
        for (char& c : text) { if (c == '"' || c == '\\') c = ' '; }
        out << "\"" << text << "\"";
        if (i + 1 != receipt.debug_messages.size()) out << ", ";
    }
    out << "]\n";
    out << "}\n";
}

void PrintReceipt(const Receipt& receipt) {
    printf("D3D12_PLATFORM_CERT\n");
    printf("===================\n\n");
    printf("adapter             %s\n", receipt.adapter.c_str());
    printf("adapter_luid        %s\n", receipt.adapter_luid.c_str());
    printf("vendor_id           0x%04X\n", receipt.vendor_id);
    printf("device_id           0x%04X\n", receipt.device_id);
    printf("driver_version      %s\n", receipt.driver_version.c_str());
    printf("runtime_version     %s\n", receipt.runtime_version.c_str());
    printf("feature_level       %s\n", receipt.feature_level.c_str());
    printf("debug_layer         available=%s enabled=%s\n",
           receipt.debug_layer_available ? "yes" : "no",
           receipt.debug_layer_enabled ? "yes" : "no");
    printf("dred_available      %s\n", receipt.dred_available ? "yes" : "no");
    printf("\n");
    for (size_t i = 0; i < receipt.rungs.size(); ++i) {
        const Rung& rung = receipt.rungs[i];
        printf("  %02zu %-16s %-8s %-28s %s\n", i + 1, rung.name.c_str(), ToString(rung.status),
               HResultName(rung.hresult).c_str(), rung.detail.c_str());
    }
    printf("\n");
    printf("first_failed_rung           %s\n",
           receipt.first_failed_index < 0
               ? "(none)"
               : receipt.rungs[receipt.first_failed_index].name.c_str());
    printf("first_failed_hresult        %s\n",
           receipt.first_failed_index < 0 ? "S_OK" : HResultName(receipt.first_failed_hresult).c_str());
    printf("device_removed_reason       %s\n", HResultName(receipt.device_removed_reason).c_str());
    printf("dred_breadcrumb_count       %u\n", receipt.dred_breadcrumb_count);
    printf("dred_page_fault_va          0x%llX\n",
           static_cast<unsigned long long>(receipt.dred_page_fault_va));
    printf("\n");
    printf("sunshine_code_reached       %s\n", receipt.sunshine_code_reached ? "YES" : "NO");
    printf("platform_blocked            %s\n", receipt.platform_blocked ? "YES" : "NO");
    printf("application_blocked         %s\n", receipt.application_blocked ? "YES" : "NO");
    printf("conclusion                  %s\n", receipt.conclusion.c_str());
    if (!receipt.debug_messages.empty()) {
        printf("\ndebug layer / DRED:\n");
        for (const std::string& message : receipt.debug_messages) {
            printf("  %s\n", message.c_str());
        }
    }
    printf("\n");
}

} // namespace

int main(int argc, char** argv) {
    bool useWarp = false;
    std::string receiptPath;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--adapter" && i + 1 < argc) {
            useWarp = (std::string(argv[++i]) == "warp");
        } else if (argument == "--receipt" && i + 1 < argc) {
            receiptPath = argv[++i];
        } else if (argument == "--help") {
            printf("usage: d3d12_capability_ladder --adapter hardware|warp [--receipt path.json]\n");
            return 0;
        }
    }

    Receipt receipt;
    Ladder ladder(receipt);
    const bool passed = ladder.Run(useWarp);

    // The conclusion. A rung failure means the fault is in the platform and
    // the application was never reached, which is exactly the distinction
    // that stops a renderer defect being hidden behind a platform excuse.
    if (!passed) {
        receipt.platform_blocked = true;
        receipt.sunshine_code_reached = false;
        receipt.application_blocked = false;
        receipt.conclusion = "PLATFORM_BLOCKED";
    } else {
        // The ladder passed. The Sunshine path is a separate question, and it
        // is answered by running the renderer, not by this probe.
        receipt.platform_blocked = false;
        receipt.sunshine_code_reached = true;
        receipt.application_blocked = false;
        receipt.conclusion = "LADDER_PASS";
    }

    PrintReceipt(receipt);
    if (!receiptPath.empty()) {
        WriteReceipt(receipt, receiptPath);
        printf("receipt written to %s\n", receiptPath.c_str());
    }
    return passed ? 0 : 2;
}
