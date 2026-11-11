#ifndef RAWRXD_CORE_CHECKPOINT_MANAGER_H
#define RAWRXD_CORE_CHECKPOINT_MANAGER_H
#include "core_export.h"
#include <memory>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT CheckpointManager {
public:
    CheckpointManager();
    ~CheckpointManager();
    CheckpointManager(const CheckpointManager&) = delete;
    CheckpointManager& operator=(const CheckpointManager&) = delete;
    CheckpointManager(CheckpointManager&&) noexcept;
    CheckpointManager& operator=(CheckpointManager&&) noexcept;
    bool Save();
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_CHECKPOINT_MANAGER_H
