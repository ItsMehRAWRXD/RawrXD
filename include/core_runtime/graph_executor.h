#ifndef RAWRXD_CORE_GRAPH_EXECUTOR_H
#define RAWRXD_CORE_GRAPH_EXECUTOR_H
#include "core_export.h"
#include <memory>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT GraphExecutor {
public:
    GraphExecutor();
    ~GraphExecutor();
    GraphExecutor(const GraphExecutor&) = delete;
    GraphExecutor& operator=(const GraphExecutor&) = delete;
    GraphExecutor(GraphExecutor&&) noexcept;
    GraphExecutor& operator=(GraphExecutor&&) noexcept;
    bool Execute();
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_GRAPH_EXECUTOR_H
