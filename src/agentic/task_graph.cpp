// Stub implementation for task_graph.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/task_graph.h"
namespace RawrXD { namespace Core {
class TaskGraph::Impl {};
TaskGraph::TaskGraph() : pImpl(new Impl()) {}
TaskGraph::~TaskGraph() = default;
TaskGraph::TaskGraph(TaskGraph&&) noexcept = default;
TaskGraph& TaskGraph::operator=(TaskGraph&&) noexcept = default;
bool TaskGraph::AddTask(const char*) { return true; }
}} // namespace RawrXD::Core
