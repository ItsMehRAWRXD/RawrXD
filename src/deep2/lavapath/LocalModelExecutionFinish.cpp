#include "LocalModelExecutionFinish.hpp"

// This file intentionally contains NO fake Deep2 implementation.
// Bind each callback below to the existing shipping ProductRuntime/Deep2 code.
//
// RawrXD::Finish::Deep2Binding ops;
// ops.create_session = ... real ProductRuntime create/bind ...;
// ops.prefill = ... real Deep2 prefill ...;
// ops.generate_stream = ... Deep2Engine::generateStream ...;
// ops.request_cancel = ... real ProductRuntime cancel ...;
// ops.unload = ... real ProductRuntime unload ...;
//
// RawrXD::Finish::LocalModelExecutor executor(std::move(ops));
// auto receipt = executor.Run(authority, options);
// write_receipt(receipt.ToText());
