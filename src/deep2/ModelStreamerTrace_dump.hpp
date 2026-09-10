#pragma once
/* After-generation dump only — not on the decode hot path. */
namespace Deep2 {
namespace ModelStreamerTrace {

inline const char* StageName(uint32_t s) {
    switch ((Stage)s) {
    case Stage::MODEL_READ: return "MODEL_READ";
    case Stage::MAP: return "MAP";
    case Stage::STREAMER: return "STREAMER";
    case Stage::QKV_READBACK: return "QKV_READBACK";
    case Stage::QKV: return "QKV";
    case Stage::ATTENTION: return "ATTENTION";
    case Stage::O_PROJ: return "O_PROJ";
    case Stage::FFN: return "FFN";
    case Stage::LOGITS: return "LOGITS";
    case Stage::WAIT: return "WAIT";
    case Stage::SAMPLE: return "SAMPLE";
    case Stage::EMIT: return "EMIT";
    case Stage::TOKEN_WALL: return "TOKEN_WALL";
    default: return "UNKNOWN";
    }
}

inline const BindingEntry* FindBinding(uint32_t id) {
    BindingTable& t = GetBindings();
    for (uint32_t i = 0; i < t.count; ++i) {
        if (t.rows[i].binding_id == id) return &t.rows[i];
    }
    return nullptr;
}

inline bool DumpRawTsv(const char* path) {
    if (!path) return false;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") != 0 || !f) return false;
    std::fprintf(f,
        "qpc_begin_ns\tqpc_end_ns\tticket\ttoken_step\tlayer\tstage\t"
        "file_id\tfile_offset\tbytes\ttensor\tbinding_id\tkernel_id\tdevice_id\n");
    Ring& r = GetRing();
    const uint32_t n = r.write.load(std::memory_order_relaxed);
    const uint32_t lim = n < kCapacity ? n : kCapacity;
    for (uint32_t i = 0; i < lim; ++i) {
        const HotPathEvent& b = r.slots[i];
        if (b.event != (uint32_t)Event::BEGIN) continue;
        uint64_t end_ns = 0;
        for (uint32_t j = i + 1; j < lim; ++j) {
            const HotPathEvent& e = r.slots[j];
            if (e.event == (uint32_t)Event::END && e.ticket == b.ticket &&
                e.binding_id == b.binding_id && e.token_step == b.token_step &&
                e.layer == b.layer) {
                end_ns = e.qpc_ns;
                break;
            }
        }
        const BindingEntry* be = FindBinding(b.binding_id);
        const char* stage = be ? StageName(be->stage) : "UNKNOWN";
        const uint32_t fid = be ? be->model_file_id : 0;
        const uint64_t off = be ? be->file_offset : 0;
        const uint64_t bytes = be ? be->bytes : 0;
        const uint64_t tid = be ? be->tensor_id : 0;
        const uint32_t kid = be ? be->kernel_id : 0;
        const uint32_t did = be ? be->device_id : 0;
        std::fprintf(f,
            "%llu\t%llu\t%llu\t%u\t%u\t%s\t%u\t%llu\t%llu\ttensor_%llu\t%u\t%u\t%u\n",
            (unsigned long long)b.qpc_ns, (unsigned long long)end_ns,
            (unsigned long long)b.ticket, b.token_step, b.layer, stage, fid,
            (unsigned long long)off, (unsigned long long)bytes,
            (unsigned long long)tid, b.binding_id, kid, did);
    }
    std::fclose(f);
    return true;
}

inline void Reset() {
    Ring& r = GetRing();
    r.write.store(0, std::memory_order_relaxed);
    r.dropped.store(0, std::memory_order_relaxed);
    std::memset(r.slots, 0, sizeof(r.slots));
    BindingTable& t = GetBindings();
    t.count = 0;
    std::memset(t.rows, 0, sizeof(t.rows));
}

} // namespace ModelStreamerTrace
} // namespace Deep2
