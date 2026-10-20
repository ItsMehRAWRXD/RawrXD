#include "deep2/StreamTransferCounters.hpp"

// Compile-time/runtime linkage witness for the production stream receipt.
// The test executable's main lives in deep2_weight_streamer_test.cpp.
void deep2_stream_transfer_emit_compile_anchor() {
    Deep2::StreamTransfer_Reset();
    Deep2::StreamTransfer_RecordToken();
    Deep2::StreamTransfer_RecordGpuUpload(360000000ull);
    Deep2::StreamTransfer_Emit(nullptr);
}
