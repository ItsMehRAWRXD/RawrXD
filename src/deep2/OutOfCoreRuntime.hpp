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

class ExecutionBackend {
public:
    virtual ~ExecutionBackend() = default;
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
};

} // namespace rawrxd
