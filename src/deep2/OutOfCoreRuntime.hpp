// ============================================================================
// OutOfCoreRuntime.hpp — Stub header for OutOfCoreRuntime base class
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace rawrxd {

// Forward declarations
class Chamber;
class PlasmaGovernor;
enum class ChamberResult : uint8_t;
struct FormulaRoute;
struct ThermalState;

// Ensure telemetry namespace exists for Deep2Telemetry.hpp
namespace telemetry {}

// Minimal stub types
using TensorId = uint64_t;

enum class Residency : uint8_t {
    None = 0,
    RAM = 1,
    VRAM = 2,
    NVMe = 3
};

enum class PatchKind : uint8_t {
    Replace = 0,
    Merge = 1,
    Subtract = 2
};

enum class Backend : uint8_t {
    CPU = 0,
    GPU = 1
};

using PatchId = uint64_t;

struct PatchRequest {
    TensorId tensor = 0;
    PatchKind kind = PatchKind::Replace;
    uint64_t offset = 0;
    const void* data = nullptr;
    size_t size = 0;
};

struct TensorDescriptor {
    TensorId id = 0;
    std::string name;
    size_t size = 0;
    Residency residency = Residency::None;
};

struct RuntimeStats {
    size_t ramUsed = 0;
    size_t vramUsed = 0;
    size_t tensorCount = 0;
};

class ResidencyLease {
public:
    ResidencyLease() = default;
    explicit ResidencyLease(TensorId /*id*/) {}
    bool valid() const { return false; }
};

class ExecutionBuffer {
public:
    virtual ~ExecutionBuffer() = default;
};

class ExecutionBackend {
public:
    virtual ~ExecutionBackend() = default;
    virtual Backend type() const { return Backend::CPU; }
    virtual std::shared_ptr<ExecutionBuffer> upload(const uint8_t* /*data*/, size_t /*bytes*/) { return nullptr; }
    virtual bool download(const std::shared_ptr<ExecutionBuffer>& /*buffer*/, uint8_t* /*destination*/, size_t /*bytes*/) { return false; }
    virtual void release(std::shared_ptr<ExecutionBuffer>& /*buffer*/) {}
    virtual bool execute(const TensorDescriptor& /*tensor*/, const std::shared_ptr<ExecutionBuffer>& /*buffer*/) { return false; }
};

class Storage {
public:
    virtual ~Storage() = default;
    virtual bool valid() const { return true; }
};

class FileStorage : public Storage {
public:
    explicit FileStorage(const std::string& /*path*/) {}
};

class CPUBackend : public ExecutionBackend {
public:
    CPUBackend() = default;
};

class OutOfCoreRuntime {
public:
    OutOfCoreRuntime(std::shared_ptr<Storage> /*storage*/,
                     size_t /*ramBudget*/, size_t /*vramBudget*/) {}
    virtual ~OutOfCoreRuntime() = default;

    void setBackend(std::shared_ptr<ExecutionBackend> /*backend*/) {}

    // Stub methods called by SovereignOutOfCoreRuntime
    void registerTensor(const TensorDescriptor& /*descriptor*/) {}
    bool hasTensor(TensorId /*id*/) const { return false; }
    ResidencyLease acquire(TensorId /*id*/, Backend /*backend*/) { return ResidencyLease{}; }
    bool execute(TensorId /*id*/) { return false; }
    PatchId installPatch(const PatchRequest& /*request*/) { return 0; }
    PatchId installPatch(TensorId /*tensor*/, PatchKind /*kind*/, uint64_t /*offset*/, const void* /*data*/, size_t /*size*/) { return 0; }
    bool removePatch(PatchId /*id*/) { return false; }
    bool setPatchEnabled(PatchId /*id*/, bool /*enabled*/) { return false; }
    bool reapplyPatches(TensorId /*id*/) { return false; }
    Residency residency(TensorId /*id*/) const { return Residency::None; }
    bool evict(TensorId /*id*/) { return false; }
    RuntimeStats stats() const { return RuntimeStats{}; }
    void clearStats() {}
    size_t ramUsed() const { return 0; }
    size_t vramUsed() const { return 0; }
};

} // namespace rawrxd
