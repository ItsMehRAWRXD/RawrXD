#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace d2rc {

enum class Status : uint8_t { NotRun=0, Ready=1, Pass=2, Hold=3, Fail=4, Skipped=5 };
enum class Authority : uint8_t { Unknown=0, Projected=1, Derived=2, Measured=3 };
enum class Risk : uint8_t { ReadOnly=0, Reversible=1, SideEffect=2, Destructive=3 };

struct Evidence {
    Authority authority = Authority::Unknown;
    std::string source;
    std::string proof;
    uint64_t state_hash = 0;
};

struct Node {
    uint32_t id = 0;
    std::string raw;
    std::string canonical;
    std::string verb;
    std::string object;
    std::string completion;
    std::vector<uint32_t> deps;
    std::vector<uint32_t> users;
    Status status = Status::NotRun;
    Risk risk = Risk::ReadOnly;
    uint32_t priority = 0;
    uint32_t uncertainty = 0;
    uint64_t semantic_hash = 0;
    Evidence evidence;
};

struct Plan {
    std::vector<Node> nodes;
    std::vector<uint32_t> critical_path;
    std::vector<uint32_t> ready;
    std::vector<uint32_t> blockers;
    uint64_t state_hash = 0;
    uint32_t duplicate_nodes_eliminated = 0;
    uint32_t transitive_edges_eliminated = 0;
    uint32_t dominated_nodes_eliminated = 0;
};

struct CompileOptions {
    bool deduplicate = true;
    bool transitive_reduce = true;
    bool dominance_prune = true;
    bool infer_dependencies = true;
    bool fixed_point_ready = true;
};

struct Result {
    bool ok = false;
    std::string error;
    Plan plan;
};

uint64_t fnv1a64(const void* p, size_t n);
uint64_t fnv1a64(const std::string& s);

std::string canonicalize(const std::string& s);
std::vector<std::string> split_requirements(const std::string& request);

Result compile(const std::string& request, const CompileOptions& opt = {});
void mark(Plan& plan, uint32_t id, Status st, const Evidence* evidence = nullptr);
void recompute(Plan& plan);

const char* mechanism_name(size_t one_based_index);
size_t mechanism_count();

} // namespace d2rc

extern "C" {
    struct d2rc_plan_handle;
    d2rc_plan_handle* d2rc_compile(const char* utf8_request);
    void d2rc_free(d2rc_plan_handle*);
    size_t d2rc_node_count(const d2rc_plan_handle*);
    const char* d2rc_node_canonical(const d2rc_plan_handle*, size_t index);
    int d2rc_node_status(const d2rc_plan_handle*, size_t index);
    int d2rc_mark(d2rc_plan_handle*, uint32_t id, int status);
    size_t d2rc_ready_count(const d2rc_plan_handle*);
    uint32_t d2rc_ready_id(const d2rc_plan_handle*, size_t index);
    const char* d2rc_last_error(const d2rc_plan_handle*);
    size_t d2rc_mechanism_count();
    const char* d2rc_mechanism_name(size_t one_based_index);
}
