#pragma once

#include "Win32IDE_ExecutionGraph.h"
#include "Win32IDE_KVManager.h" // Includes KVCacheManager

namespace RawrXD {
namespace OS {

#define XR_TICK_BUDGET_NS 1000000  // 1ms deterministic slice

struct KVExecutionWindow {
    uint64_t node_id;
    uint64_t kv_base_ptr;
    uint64_t kv_span_bytes;
    uint64_t ttl_ns;
};

struct XR_SCHEDULER_STATE {
    XR_GRAPH* graph;
    KVCacheManager* kv_manager;

    uint64_t current_time_ns;
    uint64_t tick_budget_ns;

    uint32_t* ready_queue;
    uint32_t  ready_count;

    uint32_t* defer_queue;
    uint32_t  defer_count;

    uint8_t* node_ready_flag;
    uint64_t* dependency_remaining;
};

static inline uint8_t XR_CheckMemoryBinding(XR_EXEC_CONTRACT* c)
{
    return (
        c->mem.input < 6 &&
        c->mem.output < 6 &&
        c->input_size > 0 &&
        c->output_size > 0
    );
}

// Forward declaration for KV binding
static inline void KV_BindExecutionWindow(XR_SCHEDULER_STATE* s, XR_NODE_FULL* node);

static inline bool XR_ResolveDependencies(XR_SCHEDULER_STATE* s, XR_NODE_FULL* n)
{
    // Causal struct dependency check
    if (s->dependency_remaining[n->node.node_id] > 0)
        return false;

    // Phase A -- Graph Validity (Memory checks)
    for (uint32_t i = 0; i < n->contract.kv.read_count; i++)
    {
        uint64_t page = n->contract.kv.kv_read_pages[i];
        if (!s->kv_manager->IsResident(page))
        {
            if (!n->contract.kv.allow_page_fault)
                return false;

            s->kv_manager->PinState(page, s->current_time_ns); // soft fault via NVME
            // If the fault is asynchronous, we'd return false here to wait.
            // Returning false defers execution until resident.
            if (!s->kv_manager->IsResident(page)) return false; 
        }
    }

    // Phase B -- Execution Lock
    if (n->contract.kv.requires_kv_lock)
    {
        for (uint32_t i = 0; i < n->contract.kv.read_count; i++) {
            s->kv_manager->PinState(n->contract.kv.kv_read_pages[i], s->current_time_ns);
        }
        for (uint32_t i = 0; i < n->contract.kv.write_count; i++) {
            s->kv_manager->PinState(n->contract.kv.kv_write_pages[i], s->current_time_ns);
        }
    }

    return true;
}

static inline void XR_UpdateEdgeDependencies(XR_GRAPH* g,
                                             uint64_t* dep_count,
                                             uint8_t* ready_flag)
{
    for (uint32_t i = 0; i < g->edge_count; i++)
    {
        XR_EDGE* e = &g->edges[i];

        if (dep_count[e->to_node] > 0) {
            dep_count[e->to_node]--;

            if (dep_count[e->to_node] == 0)
            {
                ready_flag[e->to_node] = 1;
            }
        }
    }
}

static inline uint32_t XR_BuildReadyQueue(
    XR_SCHEDULER_STATE* s,
    uint32_t node_count)
{
    uint32_t out = 0;

    for (uint32_t i = 0; i < node_count; i++)
    {
        if (s->node_ready_flag[i])
        {
            s->ready_queue[out++] = i;
        }
    }

    s->ready_count = out;
    return out;
}

static inline void XR_ExecuteNode(XR_NODE_FULL* node)
{
    switch (node->node.domain)
    {
        case CPU_MASM:
            ((void(*)())node->node.entry)();
            break;

        case CPU_CPP:
            ((void(*)())node->node.entry)();
            break;

        case GPU_VK:
            // enqueue to GPU ring (zerocopy bridge)
            break;

        case IO_RING:
            // write syscall into RawrXD ring buffer
            break;

        default:
            break;
    }
}

static inline void KV_BindExecutionWindow(XR_SCHEDULER_STATE* s, XR_NODE_FULL* node)
{
    KVExecutionWindow win;
    win.node_id = node->node.node_id;
    win.ttl_ns = node->contract.latency_budget_ns;
    win.kv_span_bytes = node->contract.kv.read_count * 4096; // Example scalar
    if (node->contract.kv.read_count > 0) {
        win.kv_base_ptr = s->kv_manager->GetPhysAddr(node->contract.kv.kv_read_pages[0]);
    } else {
        win.kv_base_ptr = 0;
    }
    
    // MASM explicitly assumes the environment bound here.
    // E.g. Set thread-local context or pass into execution logic
}

static inline void XR_Scheduler_Tick(XR_SCHEDULER_STATE* s)
{
    // Step 1: rebuild ready queue (including previously deferred nodes)
    // In a real system, we'd merge defer_queue back. For now, XR_BuildReadyQueue uses node_ready_flag.
    XR_BuildReadyQueue(s, s->graph->node_count);
    s->defer_count = 0;

    // Step 2: execute budgeted nodes with Memory-Causality Contracts
    for (uint32_t i = 0; i < s->ready_count; i++)
    {
        uint32_t node_id = s->ready_queue[i];
        XR_NODE_FULL* node = &((XR_NODE_FULL*)s->graph->nodes)[node_id];

        // Memory & Causality Gate
        if (!XR_ResolveDependencies(s, node))
        {
            s->defer_queue[s->defer_count++] = node_id;
            continue;
        }
        
        // latency gate
        if (node->contract.latency_budget_ns <= s->tick_budget_ns)
        {
            KV_BindExecutionWindow(s, node); // Memory Identity binding
            XR_ExecuteNode(node);
            
            // Post-execution eviction safety
            if (node->contract.kv.eviction_safe) {
                for (uint32_t j = 0; j < node->contract.kv.read_count; j++) {
                    s->kv_manager->UnpinState(node->contract.kv.kv_read_pages[j]);
                }
            }
        }

        // update timing
        node->last_exec_time_ns = s->current_time_ns;
    }

    // Step 3: advance time
    s->current_time_ns += s->tick_budget_ns;

    // Step 4: dependency resolution (next tick causality edges)
    XR_UpdateEdgeDependencies(s->graph,
                              s->dependency_remaining,
                              s->node_ready_flag);
}

static inline void XR_Runtime_Run(XR_SCHEDULER_STATE* s)
{
    while (1)
    {
        XR_Scheduler_Tick(s);

        // optional: feed telemetry into Win32IDE
        // optional: push tokens into ring buffer
    }
}

} // namespace OS
} // namespace RawrXD