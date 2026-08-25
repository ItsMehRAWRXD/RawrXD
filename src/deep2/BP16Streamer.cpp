// ============================================================================
// BP16Streamer.cpp — Stub implementation
// ============================================================================

#include "BP16Streamer.hpp"

bool BP16Streamer::open(const char* /*path*/) {
    opened_ = true;
    lastError_.clear();
    return true;
}

void BP16Streamer::close() {
    opened_ = false;
    records_.clear();
}

const char* BP16Streamer::error() const {
    return lastError_.c_str();
}

size_t BP16Streamer::tensorCount() const {
    return records_.size();
}

size_t BP16Streamer::fileSize() const {
    return 0;
}

const BP16Streamer::Record* BP16Streamer::find(const std::string& name) const {
    for (const auto& rec : records_) {
        if (rec.name == name) return &rec;
    }
    return nullptr;
}

const std::vector<BP16Streamer::Record>& BP16Streamer::records() const {
    return records_;
}

bool BP16Streamer::map_tensor(const std::string& /*name*/,
                               const uint8_t*& data, size_t& bytes) {
    data = nullptr;
    bytes = 0;
    return false;
}
