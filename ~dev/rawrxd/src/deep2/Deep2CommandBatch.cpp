#include "Deep2CommandBatch.hpp"

namespace Deep2::Roofline {

u64 CommandBatch::bytes() const noexcept {
    u64 n = 0;
    for (const auto& op : ops_) n += op.bytes;
    return n;
}

u32 CommandBatch::gpuOps(unsigned gpu) const noexcept {
    u32 n = 0;
    for (const auto& op : ops_) if (op.gpu == gpu) ++n;
    return n;
}

} // namespace Deep2::Roofline
