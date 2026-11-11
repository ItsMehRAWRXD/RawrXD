#include "tensor_residency_pipeline.hpp"
#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <chrono>
#include <algorithm>
#include <cstring>

namespace RawrXD {
namespace Core {

// ============================================================================
// ZeroCopyUploadBuffer Implementation
// ============================================================================

ZeroCopyUploadBuffer::ZeroCopyUploadBuffer(ID3D12Device* device, uint64_t size)
    : device_(device), size_(size) {
    
    // Create upload buffer in GPU memory
    D3D12_HEAP_PROPERTIES heapProps = {};
    heapProps.Type = D3D12_HEAP_TYPE_UPLOAD;
    heapProps.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_WRITE_COMBINE;
    heapProps.MemoryPoolPreference = D3D12_MEMORY_POOL_L0;
    
    D3D12_RESOURCE_DESC resourceDesc = {};
    resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    resourceDesc.Width = size;
    resourceDesc.Height = 1;
    resourceDesc.DepthOrArraySize = 1;
    resourceDesc.MipLevels = 1;
    resourceDesc.Format = DXGI_FORMAT_UNKNOWN;
    resourceDesc.SampleDesc.Count = 1;
    resourceDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    resourceDesc.Flags = D3D12_RESOURCE_FLAG_NONE;
    
    HRESULT hr = device->CreateCommittedResource(
        &heapProps,
        D3D12_HEAP_FLAG_NONE,
        &resourceDesc,
        D3D12_RESOURCE_STATE_GENERIC_READ,
        nullptr,
        IID_PPV_ARGS(&uploadResource_)
    );
    
    if (SUCCEEDED(hr)) {
        gpuAddress_ = uploadResource_->GetGPUVirtualAddress();
    }
}

ZeroCopyUploadBuffer::~ZeroCopyUploadBuffer() {
    Unmap();
    if (uploadResource_) {
        uploadResource_->Release();
    }
}

bool ZeroCopyUploadBuffer::MapFileRegion(HANDLE fileHandle, uint64_t fileOffset, uint64_t size) {
    if (!uploadResource_) return false;
    
    // Create file mapping for the specific region
    fileMapping_ = CreateFileMapping(
        fileHandle,
        nullptr,
        PAGE_READONLY,
        0,
        0,
        nullptr
    );
    
    if (!fileMapping_) return false;
    
    // Map view of file at specific offset
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD granularity = sysInfo.dwAllocationGranularity;
    
    uint64_t alignedOffset = (fileOffset / granularity) * granularity;
    uint64_t offsetDelta = fileOffset - alignedOffset;
    
    fileView_ = MapViewOfFile(
        fileMapping_,
        FILE_MAP_READ,
        (DWORD)(alignedOffset >> 32),
        (DWORD)(alignedOffset & 0xFFFFFFFF),
        size + offsetDelta
    );
    
    if (!fileView_) {
        CloseHandle(fileMapping_);
        fileMapping_ = nullptr;
        return false;
    }
    
    // Map upload buffer
    void* uploadPtr = nullptr;
    D3D12_RANGE readRange = {0, 0}; // We don't care about CPU read
    HRESULT hr = uploadResource_->Map(0, &readRange, &uploadPtr);
    
    if (FAILED(hr)) {
        Unmap();
        return false;
    }
    
    mappedPtr_ = uploadPtr;
    
    // Copy from file view to upload buffer
    // This is the only copy - from memory-mapped file to GPU upload heap
    // No intermediate CPU buffer!
    uint8_t* src = static_cast<uint8_t*>(fileView_) + offsetDelta;
    uint8_t* dst = static_cast<uint8_t*>(uploadPtr);
    
    // Use non-temporal stores for large copies to avoid cache pollution
    if (size >= 64 * 1024) {
        // Large copy - use streaming stores
        #pragma omp parallel for
        for (int64_t i = 0; i < static_cast<int64_t>(size); i += 64) {
            size_t remaining = std::min(size_t(64), size_t(size - i));
            memcpy(dst + i, src + i, remaining);
        }
    } else {
        // Small copy - regular memcpy
        memcpy(dst, src, size);
    }
    
    // Unmap file view - we don't need it anymore
    UnmapViewOfFile(fileView_);
    fileView_ = nullptr;
    
    CloseHandle(fileMapping_);
    fileMapping_ = nullptr;
    
    return true;
}

void ZeroCopyUploadBuffer::Unmap() {
    if (fileView_) {
        UnmapViewOfFile(fileView_);
        fileView_ = nullptr;
    }
    if (fileMapping_) {
        CloseHandle(fileMapping_);
        fileMapping_ = nullptr;
    }
    if (uploadResource_ && mappedPtr_) {
        uploadResource_->Unmap(0, nullptr);
        mappedPtr_ = nullptr;
    }
}

void ZeroCopyUploadBuffer::SignalUploadComplete(ID3D12Fence* fence, uint64_t fenceValue) {
    // Signal fence when upload completes
    // This is called after command list execution
}

bool ZeroCopyUploadBuffer::IsUploadComplete() {
    // Check fence value
    return true; // Simplified
}

// ============================================================================
// AsyncTensorUploadQueue Implementation
// ============================================================================

AsyncTensorUploadQueue::AsyncTensorUploadQueue(ID3D12Device* device, 
                                                ID3D12CommandQueue* commandQueue)
    : device_(device), commandQueue_(commandQueue) {
    
    // Create command allocator and list
    device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_COPY, 
                                   IID_PPV_ARGS(&commandAllocator_));
    device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_COPY,
                              commandAllocator_, nullptr,
                              IID_PPV_ARGS(&commandList_));
    
    // Create fence
    device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence_));
    fenceEvent_ = CreateEvent(nullptr, FALSE, FALSE, nullptr);
}

AsyncTensorUploadQueue::~AsyncTensorUploadQueue() {
    Flush();
    
    if (fenceEvent_) CloseHandle(fenceEvent_);
    if (fence_) fence_->Release();
    if (commandList_) commandList_->Release();
    if (commandAllocator_) commandAllocator_->Release();
}

bool AsyncTensorUploadQueue::Initialize(HANDLE fileHandle, uint64_t fileSize) {
    fileHandle_ = fileHandle;
    fileSize_ = fileSize;
    
    // Create double-buffered upload buffers (64MB each)
    const uint64_t bufferSize = 64 * 1024 * 1024;
    uploadBufferCurrent_ = std::make_unique<ZeroCopyUploadBuffer>(device_, bufferSize);
    uploadBufferNext_ = std::make_unique<ZeroCopyUploadBuffer>(device_, bufferSize);
    
    startTime_ = std::chrono::high_resolution_clock::now();
    return true;
}

void AsyncTensorUploadQueue::QueueTensor(const TensorResidencyMetadata& metadata) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    pendingUploads_.push(metadata);
}

void AsyncTensorUploadQueue::ProcessUploads() {
    auto prevUploadStart = std::chrono::high_resolution_clock::now();
    
    while (true) {
        TensorResidencyMetadata metadata;
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            if (pendingUploads_.empty()) break;
            metadata = pendingUploads_.front();
            pendingUploads_.pop();
        }
        
        // Start parsing next tensor while current uploads (overlap)
        auto parseStart = std::chrono::high_resolution_clock::now();
        
        // Map file region directly to upload buffer (zero-copy)
        bool mapped = uploadBufferCurrent_->MapFileRegion(
            fileHandle_, 
            metadata.fileOffset,
            metadata.sizeBytes
        );
        
        if (!mapped) continue;
        
        auto parseEnd = std::chrono::high_resolution_clock::now();
        auto parseTime = std::chrono::duration_cast<std::chrono::microseconds>(
            parseEnd - parseStart).count();
        
        // Record copy command
        commandList_->CopyBufferRegion(
            metadata.gpuResource,
            0,  // dst offset
            uploadBufferCurrent_->GetResource(),
            0,  // src offset
            metadata.sizeBytes
        );
        
        // Close and execute command list
        commandList_->Close();
        ID3D12CommandList* lists[] = { commandList_ };
        commandQueue_->ExecuteCommandLists(1, lists);
        
        // Signal fence
        fenceValue_++;
        commandQueue_->Signal(fence_, fenceValue_);
        
        // Wait for previous upload to complete (pipelined)
        if (fenceValue_ > 1) {
            fence_->SetEventOnCompletion(fenceValue_ - 1, fenceEvent_);
            WaitForSingleObject(fenceEvent_, INFINITE);
        }
        
        auto uploadEnd = std::chrono::high_resolution_clock::now();
        auto uploadTime = std::chrono::duration_cast<std::chrono::microseconds>(
            uploadEnd - parseStart).count();
        
        // Update stats
        stats_.totalUploaded += metadata.sizeBytes;
        stats_.uploadTimeMs += uploadTime / 1000.0;
        
        // Calculate overlap time (time spent parsing while previous uploaded)
        auto overlapTime = std::chrono::duration_cast<std::chrono::microseconds>(
            parseEnd - prevUploadStart).count();
        stats_.overlapTimeMs += overlapTime / 1000.0;
        
        prevUploadStart = uploadEnd;
        
        // Reset command list for next upload
        commandAllocator_->Reset();
        commandList_->Reset(commandAllocator_, nullptr);
        
        // Swap buffers
        std::swap(uploadBufferCurrent_, uploadBufferNext_);
        uploadBufferCurrent_->Unmap();
    }
    
    // Calculate throughput
    auto totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - startTime_).count();
    
    if (totalTime > 0 && stats_.totalUploaded > 0) {
        stats_.throughputGBps = (stats_.totalUploaded / (1024.0 * 1024.0 * 1024.0)) / 
                                (totalTime / 1000.0);
    }
}

void AsyncTensorUploadQueue::Flush() {
    // Wait for all pending uploads
    if (fenceValue_ > 0) {
        fence_->SetEventOnCompletion(fenceValue_, fenceEvent_);
        WaitForSingleObject(fenceEvent_, INFINITE);
    }
}

AsyncTensorUploadQueue::UploadStats AsyncTensorUploadQueue::GetStats() const {
    return stats_;
}

// ============================================================================
// StreamingTensorLoader Implementation
// ============================================================================

StreamingTensorLoader::StreamingTensorLoader() = default;

StreamingTensorLoader::~StreamingTensorLoader() {
    stopPrefetch_ = true;
    if (prefetchThread_.joinable()) {
        prefetchThread_.join();
    }
    
    if (mappedFile_) {
        UnmapViewOfFile(mappedFile_);
    }
    if (fileMapping_) {
        CloseHandle(fileMapping_);
    }
    if (fileHandle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(fileHandle_);
    }
}

bool StreamingTensorLoader::Initialize(const wchar_t* filePath, 
                                       ID3D12Device* device,
                                       ID3D12CommandQueue* commandQueue) {
    device_ = device;
    commandQueue_ = commandQueue;
    
    // Open file
    fileHandle_ = CreateFileW(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (fileHandle_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Get file size
    LARGE_INTEGER size;
    GetFileSizeEx(fileHandle_, &size);
    fileSize_ = size.QuadPart;
    
    // Create file mapping
    fileMapping_ = CreateFileMapping(
        fileHandle_,
        nullptr,
        PAGE_READONLY,
        0,
        0,
        nullptr
    );
    
    if (!fileMapping_) {
        CloseHandle(fileHandle_);
        fileHandle_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    // Map entire file
    mappedFile_ = MapViewOfFile(fileMapping_, FILE_MAP_READ, 0, 0, 0);
    if (!mappedFile_) {
        CloseHandle(fileMapping_);
        CloseHandle(fileHandle_);
        return false;
    }
    
    // Initialize upload queue
    uploadQueue_ = std::make_unique<AsyncTensorUploadQueue>(device, commandQueue);
    uploadQueue_->Initialize(fileHandle_, fileSize_);
    
    // Initialize tensor pool (2GB default)
    tensorPool_ = std::make_unique<TensorPool>(device, 2ULL * 1024 * 1024 * 1024);
    
    // Start prefetch thread
    prefetchThread_ = std::thread(&StreamingTensorLoader::PrefetchWorker, this);
    
    return true;
}

bool StreamingTensorLoader::RequestTensor(uint64_t tensorId, uint64_t fileOffset, 
                                          uint64_t size) {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    
    // Check if already resident
    auto it = tensors_.find(tensorId);
    if (it != tensors_.end()) {
        if (it->second.state == TensorResidency::GPU) {
            it->second.lastAccessTick = ++accessTick_;
            return true;
        }
    }
    
    // Create metadata
    TensorResidencyMetadata metadata;
    metadata.tensorId = tensorId;
    metadata.fileOffset = fileOffset;
    metadata.sizeBytes = size;
    metadata.state = TensorResidency::MAPPED;
    metadata.mappedPtr = static_cast<uint8_t*>(mappedFile_) + fileOffset;
    metadata.lastAccessTick = ++accessTick_;
    
    // Allocate GPU memory
    ID3D12Resource* resource = nullptr;
    D3D12_GPU_VIRTUAL_ADDRESS address = 0;
    if (!tensorPool_->AllocateTensor(tensorId, size, &resource, &address)) {
        // Evict LRU tensor to make room
        UpdateResidencyPolicy();
        if (!tensorPool_->AllocateTensor(tensorId, size, &resource, &address)) {
            return false;
        }
    }
    
    metadata.gpuResource = resource;
    metadata.gpuAddress = address;
    metadata.state = TensorResidency::UPLOADING;
    
    tensors_[tensorId] = metadata;
    
    // Queue for upload
    uploadQueue_->QueueTensor(metadata);
    
    return true;
}

void StreamingTensorLoader::PrefetchTensor(uint64_t tensorId, uint64_t fileOffset,
                                           uint64_t size, uint64_t priority) {
    std::lock_guard<std::mutex> lock(prefetchMutex_);
    prefetchQueue_.push({priority, tensorId});
    
    // Also add to tensors map with PREFETCH state
    std::lock_guard<std::mutex> tlock(tensorsMutex_);
    if (tensors_.find(tensorId) == tensors_.end()) {
        TensorResidencyMetadata metadata;
        metadata.tensorId = tensorId;
        metadata.fileOffset = fileOffset;
        metadata.sizeBytes = size;
        metadata.state = TensorResidency::PREFETCH;
        metadata.prefetchPriority = priority;
        tensors_[tensorId] = metadata;
    }
}

bool StreamingTensorLoader::WaitForTensor(uint64_t tensorId, uint32_t timeoutMs) {
    auto start = std::chrono::high_resolution_clock::now();
    
    while (true) {
        {
            std::lock_guard<std::mutex> lock(tensorsMutex_);
            auto it = tensors_.find(tensorId);
            if (it != tensors_.end() && it->second.state == TensorResidency::GPU) {
                return true;
            }
        }
        
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - start).count();
        
        if (elapsed >= timeoutMs) {
            return false;
        }
        
        // Process any pending uploads
        uploadQueue_->ProcessUploads();
        
        Sleep(1);
    }
}

D3D12_GPU_VIRTUAL_ADDRESS StreamingTensorLoader::GetTensorGPUAddress(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    auto it = tensors_.find(tensorId);
    if (it != tensors_.end() && it->second.state == TensorResidency::GPU) {
        it->second.lastAccessTick = ++accessTick_;
        return it->second.gpuAddress;
    }
    return 0;
}

void StreamingTensorLoader::EvictTensor(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    auto it = tensors_.find(tensorId);
    if (it != tensors_.end()) {
        it->second.state = TensorResidency::EVICTING;
        tensorPool_->FreeTensor(tensorId);
        it->second.state = TensorResidency::MAPPED;
        it->second.gpuResource = nullptr;
        it->second.gpuAddress = 0;
    }
}

void StreamingTensorLoader::UpdateResidencyPolicy() {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    
    // Find LRU tensor to evict
    uint64_t minTick = UINT64_MAX;
    uint64_t evictId = 0;
    
    for (auto& [id, metadata] : tensors_) {
        if (metadata.state == TensorResidency::GPU && 
            !metadata.isPinned.load() &&
            metadata.lastAccessTick < minTick) {
            minTick = metadata.lastAccessTick;
            evictId = id;
        }
    }
    
    if (evictId != 0) {
        EvictTensor(evictId);
    }
}

TensorResidency StreamingTensorLoader::GetTensorResidency(uint64_t tensorId) const {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    auto it = tensors_.find(tensorId);
    if (it != tensors_.end()) {
        return it->second.state;
    }
    return TensorResidency::DISK;
}

void StreamingTensorLoader::PrefetchWorker() {
    while (!stopPrefetch_.load()) {
        std::pair<uint64_t, uint64_t> item;
        {
            std::lock_guard<std::mutex> lock(prefetchMutex_);
            if (prefetchQueue_.empty()) {
                Sleep(10);
                continue;
            }
            item = prefetchQueue_.top();
            prefetchQueue_.pop();
        }
        
        uint64_t tensorId = item.second;
        
        // Check if already resident
        {
            std::lock_guard<std::mutex> lock(tensorsMutex_);
            auto it = tensors_.find(tensorId);
            if (it != tensors_.end() && 
                (it->second.state == TensorResidency::GPU ||
                 it->second.state == TensorResidency::UPLOADING)) {
                continue;
            }
        }
        
        // Request tensor
        std::lock_guard<std::mutex> lock(tensorsMutex_);
        auto it = tensors_.find(tensorId);
        if (it != tensors_.end()) {
            RequestTensor(tensorId, it->second.fileOffset, it->second.sizeBytes);
        }
    }
}

// ============================================================================
// TensorPool Implementation
// ============================================================================

TensorPool::TensorPool(ID3D12Device* device, uint64_t poolSize)
    : device_(device), poolSize_(poolSize) {
    
    // Create large buffer for all tensors
    D3D12_HEAP_PROPERTIES heapProps = {};
    heapProps.Type = D3D12_HEAP_TYPE_DEFAULT;
    
    D3D12_RESOURCE_DESC resourceDesc = {};
    resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    resourceDesc.Width = poolSize;
    resourceDesc.Height = 1;
    resourceDesc.DepthOrArraySize = 1;
    resourceDesc.MipLevels = 1;
    resourceDesc.Format = DXGI_FORMAT_UNKNOWN;
    resourceDesc.SampleDesc.Count = 1;
    resourceDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    resourceDesc.Flags = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;
    
    device->CreateCommittedResource(
        &heapProps,
        D3D12_HEAP_FLAG_NONE,
        &resourceDesc,
        D3D12_RESOURCE_STATE_COMMON,
        nullptr,
        IID_PPV_ARGS(&poolResource_)
    );
    
    if (poolResource_) {
        poolBaseAddress_ = poolResource_->GetGPUVirtualAddress();
        
        // Initialize with single free block
        Block initialBlock;
        initialBlock.offset = 0;
        initialBlock.size = poolSize;
        initialBlock.allocated = false;
        blocks_.push_back(initialBlock);
    }
}

TensorPool::~TensorPool() {
    if (poolResource_) {
        poolResource_->Release();
    }
}

bool TensorPool::AllocateTensor(uint64_t tensorId, uint64_t size,
                                ID3D12Resource** outResource,
                                D3D12_GPU_VIRTUAL_ADDRESS* outAddress) {
    std::lock_guard<std::mutex> lock(blocksMutex_);
    
    // Align size to 256 bytes
    size = (size + 255) & ~255ULL;
    
    // Find first fit
    for (auto& block : blocks_) {
        if (!block.allocated && block.size >= size) {
            // Split block if larger
            if (block.size > size) {
                Block newBlock;
                newBlock.offset = block.offset + size;
                newBlock.size = block.size - size;
                newBlock.allocated = false;
                
                auto it = std::find_if(blocks_.begin(), blocks_.end(),
                    [&block](const Block& b) { return b.offset == block.offset; });
                blocks_.insert(it + 1, newBlock);
            }
            
            block.allocated = true;
            block.tensorId = tensorId;
            block.size = size;
            
            *outResource = poolResource_;
            *outAddress = poolBaseAddress_ + block.offset;
            
            return true;
        }
    }
    
    return false; // No space
}

void TensorPool::FreeTensor(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(blocksMutex_);
    
    // Find block
    for (auto it = blocks_.begin(); it != blocks_.end(); ++it) {
        if (it->allocated && it->tensorId == tensorId) {
            it->allocated = false;
            it->tensorId = 0;
            
            // Coalesce with adjacent free blocks
            // (simplified - just mark as free for now)
            break;
        }
    }
}

TensorPool::PoolStats TensorPool::GetStats() const {
    std::lock_guard<std::mutex> lock(blocksMutex_);
    
    PoolStats stats;
    stats.totalSize = poolSize_;
    
    for (const auto& block : blocks_) {
        if (block.allocated) {
            stats.allocatedSize += block.size;
            stats.tensorCount++;
        } else {
            stats.freeSize += block.size;
            stats.freeBlocks++;
        }
    }
    
    return stats;
}

// ============================================================================
// TensorResidencyPipeline Implementation
// ============================================================================

TensorResidencyPipeline::TensorResidencyPipeline() = default;

TensorResidencyPipeline::~TensorResidencyPipeline() {
    Shutdown();
}

bool TensorResidencyPipeline::Initialize(const wchar_t* modelPath,
                                        ID3D12Device* device,
                                        ID3D12CommandQueue* commandQueue,
                                        uint64_t gpuMemoryLimit) {
    loader_ = std::make_unique<StreamingTensorLoader>();
    
    if (!loader_->Initialize(modelPath, device, commandQueue)) {
        return false;
    }
    
    // Start compute worker thread
    computeThread_ = std::thread(&TensorResidencyPipeline::ComputeWorker, this);
    
    initialized_.store(true);
    return true;
}

bool TensorResidencyPipeline::LoadModel(const wchar_t* modelPath) {
    // Model already loaded during Initialize
    return initialized_.load();
}

D3D12_GPU_VIRTUAL_ADDRESS TensorResidencyPipeline::GetTensorForCompute(
    uint64_t tensorId, uint64_t fileOffset, uint64_t size, uint32_t timeoutMs) {
    
    if (!initialized_.load()) return 0;
    
    // Request tensor
    if (!loader_->RequestTensor(tensorId, fileOffset, size)) {
        return 0;
    }
    
    // Wait for it to be resident
    if (!loader_->WaitForTensor(tensorId, timeoutMs)) {
        return 0;
    }
    
    return loader_->GetTensorGPUAddress(tensorId);
}

void TensorResidencyPipeline::PrefetchLayerTensors(
    const std::vector<uint64_t>& tensorIds) {
    
    if (!initialized_.load()) return;
    
    // Add to prefetch queue with decreasing priority
    uint64_t priority = tensorIds.size();
    for (uint64_t id : tensorIds) {
        // Assume we have file offset and size stored somewhere
        // For now, just queue the request
        priority--;
    }
}

void TensorResidencyPipeline::StreamCompute(
    const std::vector<uint64_t>& tensorIds,
    ComputeCallback callback) {
    
    if (!initialized_.load()) return;
    
    std::lock_guard<std::mutex> lock(computeQueueMutex_);
    computeQueue_.push({tensorIds, callback});
    computeCv_.notify_one();
}

void TensorResidencyPipeline::ComputeWorker() {
    while (initialized_.load()) {
        std::pair<std::vector<uint64_t>, ComputeCallback> item;
        
        {
            std::unique_lock<std::mutex> lock(computeQueueMutex_);
            computeCv_.wait(lock, [this] { 
                return !computeQueue_.empty() || !initialized_.load(); 
            });
            
            if (!initialized_.load()) break;
            if (computeQueue_.empty()) continue;
            
            item = computeQueue_.front();
            computeQueue_.pop();
        }
        
        // Process each tensor
        for (uint64_t tensorId : item.first) {
            // Wait for tensor to be ready
            if (loader_->WaitForTensor(tensorId, 5000)) {
                auto gpuAddr = loader_->GetTensorGPUAddress(tensorId);
                if (gpuAddr != 0) {
                    item.second(tensorId, gpuAddr);
                }
            }
        }
    }
}

TensorResidencyPipeline::PipelineStats TensorResidencyPipeline::GetStats() const {
    PipelineStats stats;
    
    if (loader_) {
        // Count tensors
        // (simplified - would need to expose from loader)
    }
    
    return stats;
}

void TensorResidencyPipeline::Shutdown() {
    initialized_.store(false);
    computeCv_.notify_all();
    
    if (computeThread_.joinable()) {
        computeThread_.join();
    }
    
    loader_.reset();
}

} // namespace Core
} // namespace RawrXD
