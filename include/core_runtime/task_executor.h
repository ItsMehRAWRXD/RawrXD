#ifndef RAWRXD_CORE_TASK_EXECUTOR_H
#define RAWRXD_CORE_TASK_EXECUTOR_H
#include "core_export.h"
#include <memory>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT TaskExecutor {
public:
    TaskExecutor();
    ~TaskExecutor();
    TaskExecutor(const TaskExecutor&) = delete;
    TaskExecutor& operator=(const TaskExecutor&) = delete;
    TaskExecutor(TaskExecutor&&) noexcept;
    TaskExecutor& operator=(TaskExecutor&&) noexcept;
    bool Execute();
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_TASK_EXECUTOR_H
