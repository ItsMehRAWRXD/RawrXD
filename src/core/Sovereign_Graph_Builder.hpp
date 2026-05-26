#pragma once
#include <vector>
#include <algorithm>
#include <queue>
#include <map>

// Assuming XR_Binary_Node maps to our XR_Node or is defined alongside it
// For this context, we will forward declare it or use XR_Node equivalents
struct XR_Binary_Node {
    uint64_t output_addr;
    uint64_t input_addr;
    // other fields...
};

// XR_Graph_Builder: Operates on the hydrated manifest nodes
class XR_Graph_Builder {
public:
    // Implements Kahn's Algorithm to generate the static rank
    // Input: Vector of raw node pointers from the binary manifest
    static std::vector<XR_Binary_Node*> build_topological_rank(std::vector<XR_Binary_Node*>& nodes) {
        std::map<XR_Binary_Node*, int> in_degree;
        std::map<XR_Binary_Node*, std::vector<XR_Binary_Node*>> adj;

        // 1. Build adjacency list based on causality edges (OutputAddr -> InputAddr)
        for (auto* node : nodes) {
            for (auto* target : nodes) {
                // If a node's output feeds into a target's input, it's a dependency edge
                if (node->output_addr == target->input_addr && node != target) {
                    adj[node].push_back(target);
                    in_degree[target]++;
                }
            }
        }

        // 2. Queue all roots (nodes with in-degree 0)
        std::queue<XR_Binary_Node*> q;
        for (auto* node : nodes) {
            if (in_degree[node] == 0) q.push(node);
        }

        // 3. Linearize the graph
        std::vector<XR_Binary_Node*> sorted_plan;
        while (!q.empty()) {
            auto* u = q.front();
            q.pop();
            sorted_plan.push_back(u);

            for (auto* v : adj[u]) {
                if (--in_degree[v] == 0) q.push(v);
            }
        }

        return sorted_plan;
    }
};
