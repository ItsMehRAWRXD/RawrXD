#include "PersistentGraphState.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cstdlib>
#include <cmath>

namespace rawrxd::runtime {

namespace {

template <typename T>
bool WriteAll(HANDLE h, const T* data, size_t bytes) noexcept {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
    while (bytes) {
        DWORD chunk = bytes > 0x7ffff000u ? 0x7ffff000u : static_cast<DWORD>(bytes);
        DWORD done = 0;
        if (!WriteFile(h, p, chunk, &done, nullptr) || done == 0) return false;
        p += done;
        bytes -= done;
    }
    return true;
}

template <typename T>
bool ReadAll(HANDLE h, T* data, size_t bytes) noexcept {
    uint8_t* p = reinterpret_cast<uint8_t*>(data);
    while (bytes) {
        DWORD chunk = bytes > 0x7ffff000u ? 0x7ffff000u : static_cast<DWORD>(bytes);
        DWORD done = 0;
        if (!ReadFile(h, p, chunk, &done, nullptr) || done == 0) return false;
        p += done;
        bytes -= done;
    }
    return true;
}

const char* TypeName(ValueType t) noexcept {
    switch (t) {
    case ValueType::U32: return "u32";
    case ValueType::U64: return "u64";
    case ValueType::I64: return "i64";
    case ValueType::F32: return "f32";
    case ValueType::F64: return "f64";
    case ValueType::Bool: return "bool";
    default: return "unknown";
    }
}

bool ParseU64(const char* s, uint64_t* out) noexcept {
    if (!s || !out) return false;
    char* end = nullptr;
    unsigned long long v = _strtoui64(s, &end, 0);
    if (end == s) return false;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') ++end;
    if (*end) return false;
    *out = static_cast<uint64_t>(v);
    return true;
}

bool ParseI64(const char* s, int64_t* out) noexcept {
    if (!s || !out) return false;
    char* end = nullptr;
    long long v = _strtoi64(s, &end, 0);
    if (end == s) return false;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') ++end;
    if (*end) return false;
    *out = static_cast<int64_t>(v);
    return true;
}

bool ParseF64(const char* s, double* out) noexcept {
    if (!s || !out) return false;
    char* end = nullptr;
    double v = std::strtod(s, &end);
    if (end == s || !std::isfinite(v)) return false;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') ++end;
    if (*end) return false;
    *out = v;
    return true;
}

} // namespace

uint64_t PersistentGraphState::Hash64(const void* data, size_t bytes) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < bytes; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h ? h : 1ull;
}

uint64_t PersistentGraphState::StableId(const char* text) noexcept {
    if (!text) return 0;
    return Hash64(text, std::strlen(text));
}

bool PersistentGraphState::Build(
    const GraphNode* nodes, uint32_t node_count,
    const GraphDependency* deps, uint32_t dep_count,
    const PersistentValue* values, uint32_t value_count) noexcept {

    if ((!nodes && node_count) || (!deps && dep_count) || (!values && value_count))
        return false;

    try {
        nodes_.assign(nodes, nodes + node_count);
        deps_.assign(deps, deps + dep_count);
        values_.assign(values, values + value_count);
    } catch (...) {
        return false;
    }

    std::sort(values_.begin(), values_.end(),
        [](const PersistentValue& a, const PersistentValue& b) { return a.id < b.id; });

    for (size_t i = 1; i < values_.size(); ++i)
        if (values_[i - 1].id == values_[i].id) return false;

    generation_ = 0;
    RehashGraph();
    return ValidateGraph();
}

void PersistentGraphState::RehashGraph() noexcept {
    uint64_t h = 1469598103934665603ull;
    auto mix = [&h](const void* p, size_t n) {
        const auto* b = static_cast<const uint8_t*>(p);
        for (size_t i = 0; i < n; ++i) {
            h ^= b[i];
            h *= 1099511628211ull;
        }
    };

    if (!nodes_.empty()) mix(nodes_.data(), nodes_.size() * sizeof(GraphNode));
    if (!deps_.empty()) mix(deps_.data(), deps_.size() * sizeof(GraphDependency));

    // Hash schema, not mutable current values.
    for (const auto& v : values_) {
        mix(&v.id, sizeof(v.id));
        mix(&v.type, sizeof(v.type));
        mix(&v.flags, sizeof(v.flags));
        mix(&v.default_value, sizeof(v.default_value));
        mix(&v.min_value, sizeof(v.min_value));
        mix(&v.max_value, sizeof(v.max_value));
    }
    graph_hash_ = h ? h : 1ull;
}

bool PersistentGraphState::ValidateGraph() const noexcept {
    for (const auto& d : deps_) {
        if (d.producer_node >= nodes_.size() || d.consumer_node >= nodes_.size())
            return false;
        if (d.producer_node == d.consumer_node) return false;
    }

    for (const auto& n : nodes_) {
        if (static_cast<uint64_t>(n.first_dependency) + n.dependency_count > deps_.size())
            return false;
        if (static_cast<uint64_t>(n.first_value) + n.value_count > values_.size())
            return false;
    }

    // Fixed graph must be acyclic.
    std::vector<uint32_t> indegree(nodes_.size(), 0);
    for (const auto& d : deps_) ++indegree[d.consumer_node];

    std::vector<uint32_t> q;
    q.reserve(nodes_.size());
    for (uint32_t i = 0; i < indegree.size(); ++i)
        if (indegree[i] == 0) q.push_back(i);

    size_t head = 0, visited = 0;
    while (head < q.size()) {
        uint32_t u = q[head++];
        ++visited;
        for (const auto& d : deps_) {
            if (d.producer_node == u) {
                if (--indegree[d.consumer_node] == 0)
                    q.push_back(d.consumer_node);
            }
        }
    }
    return visited == nodes_.size();
}

PersistentValue* PersistentGraphState::Find(uint64_t id) noexcept {
    auto it = std::lower_bound(values_.begin(), values_.end(), id,
        [](const PersistentValue& a, uint64_t b) { return a.id < b; });
    return (it != values_.end() && it->id == id) ? &*it : nullptr;
}

const PersistentValue* PersistentGraphState::Find(uint64_t id) const noexcept {
    auto it = std::lower_bound(values_.begin(), values_.end(), id,
        [](const PersistentValue& a, uint64_t b) { return a.id < b; });
    return (it != values_.end() && it->id == id) ? &*it : nullptr;
}

bool PersistentGraphState::CanConfigure(const PersistentValue& p) noexcept {
    return (p.flags & Value_Configurable) && !(p.flags & Value_ReadOnly);
}

bool PersistentGraphState::IsInRange(const PersistentValue& p, const ValueBits& v) noexcept {
    switch (p.type) {
    case ValueType::U32: return v.u32 >= p.min_value.u32 && v.u32 <= p.max_value.u32;
    case ValueType::U64: return v.u64 >= p.min_value.u64 && v.u64 <= p.max_value.u64;
    case ValueType::I64: return v.i64 >= p.min_value.i64 && v.i64 <= p.max_value.i64;
    case ValueType::F32: return std::isfinite(v.f32) && v.f32 >= p.min_value.f32 && v.f32 <= p.max_value.f32;
    case ValueType::F64: return std::isfinite(v.f64) && v.f64 >= p.min_value.f64 && v.f64 <= p.max_value.f64;
    case ValueType::Bool: return v.boolean <= 1;
    default: return false;
    }
}

bool PersistentGraphState::SetRaw(uint64_t id, ValueType type, ValueBits v) noexcept {
    PersistentValue* p = Find(id);
    if (!p || p->type != type || (p->flags & Value_ReadOnly) || !IsInRange(*p, v))
        return false;
    p->value = v;
    ++generation_;
    return true;
}

bool PersistentGraphState::GetRaw(uint64_t id, ValueType type, ValueBits* out) const noexcept {
    if (!out) return false;
    const PersistentValue* p = Find(id);
    if (!p || p->type != type) return false;
    *out = p->value;
    return true;
}

#define RX_SETGET(NAME, TYPEENUM, CTYPE, FIELD) \
bool PersistentGraphState::Set##NAME(uint64_t id, CTYPE v) noexcept { ValueBits b{}; b.FIELD = v; return SetRaw(id, ValueType::TYPEENUM, b); } \
bool PersistentGraphState::Get##NAME(uint64_t id, CTYPE* out) const noexcept { ValueBits b{}; if (!GetRaw(id, ValueType::TYPEENUM, &b) || !out) return false; *out = b.FIELD; return true; }

RX_SETGET(U32, U32, uint32_t, u32)
RX_SETGET(U64, U64, uint64_t, u64)
RX_SETGET(I64, I64, int64_t, i64)
RX_SETGET(F32, F32, float, f32)
RX_SETGET(F64, F64, double, f64)

bool PersistentGraphState::SetBool(uint64_t id, bool v) noexcept {
    ValueBits b{}; b.boolean = v ? 1 : 0; return SetRaw(id, ValueType::Bool, b);
}
bool PersistentGraphState::GetBool(uint64_t id, bool* out) const noexcept {
    if (!out) return false;
    ValueBits b{}; if (!GetRaw(id, ValueType::Bool, &b)) return false;
    *out = b.boolean != 0; return true;
}

void PersistentGraphState::ResetDefaults() noexcept {
    for (auto& p : values_) {
        if (!(p.flags & Value_ReadOnly)) p.value = p.default_value;
    }
    ++generation_;
}

bool PersistentGraphState::SaveSnapshot(const wchar_t* path) const noexcept {
    if (!path) return false;

    std::vector<PersistentValue> persisted;
    try {
        for (const auto& v : values_)
            if ((v.flags & Value_Persistent) && !(v.flags & Value_RuntimeOnly))
                persisted.push_back(v);
    } catch (...) { return false; }

    SnapshotHeader h{};
    std::memcpy(h.magic, "RXPGS001", 8);
    h.version = 1;
    h.header_bytes = sizeof(SnapshotHeader);
    h.graph_hash = graph_hash_;
    h.generation = generation_;
    h.value_count = static_cast<uint32_t>(persisted.size());
    h.value_bytes = sizeof(PersistentValue);
    h.payload_hash = persisted.empty() ? Hash64("", 0) :
        Hash64(persisted.data(), persisted.size() * sizeof(PersistentValue));

    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    bool ok = WriteAll(f, &h, sizeof(h));
    if (ok && !persisted.empty())
        ok = WriteAll(f, persisted.data(), persisted.size() * sizeof(PersistentValue));
    FlushFileBuffers(f);
    CloseHandle(f);
    return ok;
}

bool PersistentGraphState::LoadSnapshot(const wchar_t* path, bool require_same_graph) noexcept {
    if (!path) return false;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    SnapshotHeader h{};
    bool ok = ReadAll(f, &h, sizeof(h));
    if (!ok || std::memcmp(h.magic, "RXPGS001", 8) != 0 ||
        h.version != 1 || h.header_bytes != sizeof(SnapshotHeader) ||
        h.value_bytes != sizeof(PersistentValue) ||
        (require_same_graph && h.graph_hash != graph_hash_)) {
        CloseHandle(f); return false;
    }

    std::vector<PersistentValue> incoming;
    try { incoming.resize(h.value_count); } catch (...) { CloseHandle(f); return false; }

    if (h.value_count)
        ok = ReadAll(f, incoming.data(), incoming.size() * sizeof(PersistentValue));
    CloseHandle(f);
    if (!ok) return false;

    uint64_t ph = incoming.empty() ? Hash64("", 0) :
        Hash64(incoming.data(), incoming.size() * sizeof(PersistentValue));
    if (ph != h.payload_hash) return false;

    // Transactional validation before mutation.
    for (const auto& in : incoming) {
        const PersistentValue* local = Find(in.id);
        if (!local || local->type != in.type) return false;
        if (!(local->flags & Value_Persistent) || (local->flags & Value_RuntimeOnly)) return false;
        if (!IsInRange(*local, in.value)) return false;
    }

    for (const auto& in : incoming) {
        PersistentValue* local = Find(in.id);
        local->value = in.value;
    }
    generation_ = h.generation + 1;
    return true;
}

bool PersistentGraphState::ApplyConfigFile(const wchar_t* path) noexcept {
    if (!path) return false;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f) return false;

    char line[1024];
    bool all_ok = true;
    while (std::fgets(line, sizeof(line), f)) {
        char* p = line;
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p || *p == '#' || *p == ';' || *p == '\r' || *p == '\n') continue;

        char* eq = std::strchr(p, '=');
        if (!eq) { all_ok = false; continue; }
        *eq++ = '\0';

        char* end_key = p + std::strlen(p);
        while (end_key > p && (end_key[-1] == ' ' || end_key[-1] == '\t')) *--end_key = '\0';
        while (*eq == ' ' || *eq == '\t') ++eq;

        char* end_val = eq + std::strlen(eq);
        while (end_val > eq && (end_val[-1] == '\r' || end_val[-1] == '\n' ||
                                end_val[-1] == ' ' || end_val[-1] == '\t')) *--end_val = '\0';

        uint64_t id = 0;
        if (!ParseU64(p, &id)) id = StableId(p);

        PersistentValue* v = Find(id);
        if (!v || !CanConfigure(*v)) { all_ok = false; continue; }

        ValueBits b{};
        bool parsed = false;
        uint64_t u = 0;
        int64_t i = 0;
        double d = 0;

        switch (v->type) {
        case ValueType::U32:
            parsed = ParseU64(eq, &u) && u <= UINT32_MAX; b.u32 = static_cast<uint32_t>(u); break;
        case ValueType::U64:
            parsed = ParseU64(eq, &u); b.u64 = u; break;
        case ValueType::I64:
            parsed = ParseI64(eq, &i); b.i64 = i; break;
        case ValueType::F32:
            parsed = ParseF64(eq, &d); b.f32 = static_cast<float>(d); break;
        case ValueType::F64:
            parsed = ParseF64(eq, &d); b.f64 = d; break;
        case ValueType::Bool:
            if (_stricmp(eq, "true") == 0 || std::strcmp(eq, "1") == 0) { b.boolean = 1; parsed = true; }
            else if (_stricmp(eq, "false") == 0 || std::strcmp(eq, "0") == 0) { b.boolean = 0; parsed = true; }
            break;
        default: break;
        }

        if (!parsed || !IsInRange(*v, b)) { all_ok = false; continue; }
        v->value = b;
        ++generation_;
    }

    std::fclose(f);
    return all_ok;
}

bool PersistentGraphState::DumpDecoded(const wchar_t* path) const noexcept {
    if (!path) return false;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"wb") != 0 || !f) return false;

    std::fprintf(f, "id\ttype\tflags\tvalue\tdefault\tmin\tmax\n");
    for (const auto& v : values_) {
        std::fprintf(f, "0x%016llx\t%s\t0x%08x\t",
            static_cast<unsigned long long>(v.id), TypeName(v.type), v.flags);

        auto printBits = [&](const ValueBits& b) {
            switch (v.type) {
            case ValueType::U32: std::fprintf(f, "%u", b.u32); break;
            case ValueType::U64: std::fprintf(f, "%llu", static_cast<unsigned long long>(b.u64)); break;
            case ValueType::I64: std::fprintf(f, "%lld", static_cast<long long>(b.i64)); break;
            case ValueType::F32: std::fprintf(f, "%.9g", b.f32); break;
            case ValueType::F64: std::fprintf(f, "%.17g", b.f64); break;
            case ValueType::Bool: std::fprintf(f, "%u", b.boolean ? 1u : 0u); break;
            default: std::fprintf(f, "?"); break;
            }
        };

        printBits(v.value); std::fputc('\t', f);
        printBits(v.default_value); std::fputc('\t', f);
        printBits(v.min_value); std::fputc('\t', f);
        printBits(v.max_value); std::fputc('\n', f);
    }

    std::fclose(f);
    return true;
}

namespace StateId {
#define RX_ID_FN(fn, txt) uint64_t fn() noexcept { static const uint64_t v = PersistentGraphState::StableId(txt); return v; }
RX_ID_FN(TokenStep, "decode.token_step")
RX_ID_FN(Position, "decode.position")
RX_ID_FN(KvWriteCursor, "decode.kv_write_cursor")
RX_ID_FN(SequenceId, "decode.sequence_id")
RX_ID_FN(MaxTokens, "decode.max_tokens")
RX_ID_FN(Temperature, "sample.temperature")
RX_ID_FN(TopK, "sample.top_k")
RX_ID_FN(TopP, "sample.top_p")
RX_ID_FN(RepeatPenalty, "sample.repeat_penalty")
RX_ID_FN(RngState, "sample.rng_state")
RX_ID_FN(ActiveQRows, "kernel.q_rows")
RX_ID_FN(ActiveQaRows, "kernel.qa_rows")
RX_ID_FN(ActiveQkvRows, "kernel.qkv_rows")
#undef RX_ID_FN
}

} // namespace rawrxd::runtime
