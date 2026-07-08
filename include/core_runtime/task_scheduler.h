#ifndef RAWRXD_CORE_TASK_SCHEDULER_H
#define RAWRXD_CORE_TASK_SCHEDULER_H
#include "core_export.h"
#include <memory>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT TaskScheduler {
public:
    TaskScheduler();
    ~TaskScheduler();
    TaskScheduler(const TaskScheduler&) = delete;
    TaskScheduler& operator=(const TaskScheduler&) = delete;
    TaskScheduler(TaskScheduler&&) noexcept;
    TaskScheduler& operator=(TaskScheduler&&) noexcept;
    bool Schedule();
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_TASK_SCHEDULER_H
