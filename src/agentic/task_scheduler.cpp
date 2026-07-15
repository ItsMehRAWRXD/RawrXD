// Stub implementation for task_scheduler.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/task_scheduler.h"
namespace RawrXD { namespace Core {
class TaskScheduler::Impl {};
TaskScheduler::TaskScheduler() : pImpl(new Impl()) {}
TaskScheduler::~TaskScheduler() = default;
TaskScheduler::TaskScheduler(TaskScheduler&&) noexcept = default;
TaskScheduler& TaskScheduler::operator=(TaskScheduler&&) noexcept = default;
bool TaskScheduler::Schedule() { return true; }
}} // namespace RawrXD::Core
