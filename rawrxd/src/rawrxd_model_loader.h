#pragma once
// rawrxd_model_loader.h — RawrXDModelLoader: file-backed tensor residency
// Used by: gguf_swarm_plan_builder.cpp, swarm_scheduler.cpp/hpp, main.cpp

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <vector>

namespace RawrXD {

/// Absolute file byte span of one GGUF tensor, measured from byte 0 of the
/// file (i.e. already includes the GGUF data-section offset).
struct TensorFileSpan {
    std::string name;
    std::uint64_t fileOffset = 0;
    std::uint64_t sizeBytes = 0;
    /// ggml type id of the payload (0=F32, 1=F16, 2=Q4_0 ... 14=Q6_K).
    std::uint32_t ggmlType = 0;
    /// Payload length in bytes as declared by the tensor table.
    std::uint64_t payloadBytes = 0;
};

/// File-backed sliding-window mapper for one GGUF model.
///
/// Invariant: a compute view and a prefetch view may be mapped at the same
/// time and are torn down independently. Compute views live in a small fixed
/// slot array so an LRU eviction can never unmap a range the caller still
/// holds (see markComputeRangeInUse).
class RawrXDModelLoader {
public:
    RawrXDModelLoader();
    ~RawrXDModelLoader();

    RawrXDModelLoader(const RawrXDModelLoader&) = delete;
    RawrXDModelLoader& operator=(const RawrXDModelLoader&) = delete;

    // ---- lifetime -------------------------------------------------------

    /// Open `path`, map the whole file read-only, and parse the GGUF tensor
    /// table. Returns false and leaves the loader closed on any failure.
    bool Open(const std::string& path);
    void Close();
    bool IsOpen() const;

    std::uint64_t GetFileSizeBytes() const;

    /// Tensor table parsed by Open(). Empty when the loader is closed.
    std::vector<TensorFileSpan> listTensorFileSpans() const;

    /// Byte offset of the GGUF payload (tensor data section) start.
    std::uint64_t GetDataSectionOffset() const;

    // ---- compute windows -------------------------------------------------

    /// Map [offset, offset+size) into a compute slot and return a pointer to
    /// the requested byte, or nullptr. On a covering hit the existing slot is
    /// reused and only its LRU stamp is refreshed.
    void* MapWindow(std::uint64_t offset, std::size_t size);

    /// Unmap every compute slot.
    void UnmapWindow();

    /// Number of compute slots currently holding a view.
    std::size_t ComputeSlotCount() const;

    // ---- prefetch window ------------------------------------------------

    void* MapPrefetchWindow(std::uint64_t offset, std::size_t size);
    void UnmapPrefetchWindow();

    // ---- range tracking --------------------------------------------------

    /// Pin/unpin a compute range. A slot with inUseCount > 0 is never chosen
    /// as an LRU victim. Ranges are matched to slots by full containment.
    void markComputeRangeInUse(std::uint64_t offset, std::uint64_t size);
    void unmarkComputeRangeInUse(std::uint64_t offset, std::uint64_t size);

    /// True when any compute slot fully contains [offset, offset+size).
    bool ComputeMappingCovers(std::uint64_t offset, std::uint64_t size) const;

    bool HasActivePrefetchMapping() const;

    // ---- telemetry -------------------------------------------------------

    void recordSwarmPinBackoffCycle();
    std::uint64_t GetSwarmPinBackoffCycles() const;

private:
    class Impl;
    Impl* m_impl;
};

}  // namespace RawrXD