#ifndef RAWRXD_CORE_TASK_GRAPH_H
#define RAWRXD_CORE_TASK_GRAPH_H
#include "core_export.h"
#include <memory>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT TaskGraph {
public:
    TaskGraph();
    ~TaskGraph();
    TaskGraph(const TaskGraph&) = delete;
    TaskGraph& operator=(const TaskGraph&) = delete;
    TaskGraph(TaskGraph&&) noexcept;
    TaskGraph& operator=(TaskGraph&&) noexcept;
    bool AddTask(const char* name);
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_TASK_GRAPH_H
