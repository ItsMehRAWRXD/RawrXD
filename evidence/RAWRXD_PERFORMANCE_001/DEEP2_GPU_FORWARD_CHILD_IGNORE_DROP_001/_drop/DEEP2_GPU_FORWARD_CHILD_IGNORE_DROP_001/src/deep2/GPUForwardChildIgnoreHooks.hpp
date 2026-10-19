#pragma once
#include "GPUForwardChildIgnore.hpp"

// Integration helpers. They deliberately do NOT fabricate replacement tensors.
// The caller must use an existing diagnostic-safe bypass at the exact child
// boundary. If a child cannot be skipped without inventing data, do not mark
// that rung PASS; emit SELECTED_CHILD_EVIDENCE_FIRED=0 / a runtime disposition.

#define DEEP2_GPU_FORWARD_LAYER_ENTER() \
    ::RawrXD::Deep2::GpuForwardIgnore::MarkGpuForwardLayer()

#define DEEP2_GPU_CHILD_SCOPE(varName, childName) \
    ::RawrXD::Deep2::GpuForwardIgnore::Scope varName( \
        ::RawrXD::Deep2::GpuForwardIgnore::Child::childName)

// Example:
//   DEEP2_GPU_CHILD_SCOPE(qkvGate, QKV);
//   if (!qkvGate.skipped()) {
//       real_gpu_qkv(...);
//   } else {
//       return DiagnosticSkipDisposition::SkippedQKV; // project-owned safe bypass
//   }
