#pragma once
#include <cstddef>
#include <cstdint>

#ifdef _WIN32
  #ifdef RAWRXD_SCREENPILOT_EXPORTS
    #define RAWRXD_SP_API __declspec(dllexport)
  #else
    #define RAWRXD_SP_API
  #endif
#else
  #define RAWRXD_SP_API
#endif

extern "C" {

static constexpr std::uint32_t RAWRXD_SCREENPILOT_ABI_V1 = 1;

struct RawrXD_SP_String {
    const char* data;
    std::size_t size;
};

struct RawrXD_SP_AgentRequestV1 {
    RawrXD_SP_String request_id;
    RawrXD_SP_String mode;       // ask | plan | build | agent
    RawrXD_SP_String model;
    RawrXD_SP_String workspace;  // canonical, validated absolute path
    RawrXD_SP_String prompt;
};

using RawrXD_SP_EmitFn =
    int (*)(void* emit_user, const char* event_type, const char* data, std::size_t data_size);

using RawrXD_SP_IsCancelledFn =
    int (*)(void* cancel_user);

struct RawrXD_SP_AuthorityV1 {
    std::uint32_t abi_version;
    void* user;

    // REQUIRED.
    // Must enter the same canonical Agent Coordinator / Tool Authority used by
    // native IDE + CLI. Return the agent's terminal status/exit code.
    int (*run_agent)(
        void* user,
        const RawrXD_SP_AgentRequestV1* request,
        RawrXD_SP_EmitFn emit,
        void* emit_user,
        RawrXD_SP_IsCancelledFn is_cancelled,
        void* cancel_user
    );

    // OPTIONAL. Return a UTF-8 JSON object. The returned pointer only needs to
    // remain valid until the callback returns.
    int (*capabilities_json)(
        void* user,
        RawrXD_SP_EmitFn emit,
        void* emit_user
    );
};

struct RawrXD_SP_HttpRequestV1 {
    RawrXD_SP_String method;
    RawrXD_SP_String path;
    RawrXD_SP_String host;
    RawrXD_SP_String origin;
    RawrXD_SP_String session_token;
    RawrXD_SP_String content_type;
    RawrXD_SP_String body;
};

struct RawrXD_SP_HttpSinkV1 {
    void* user;

    // Called once before write().
    int (*begin)(void* user, int status_code, const char* content_type, int chunked);

    // Optional; called before begin() returns control to the route body if your
    // LocalServer implementation supports response headers.
    int (*header)(void* user, const char* name, const char* value);

    // May be called many times for streamed NDJSON.
    int (*write)(void* user, const char* data, std::size_t size);

    // Called exactly once after begin() on normal route completion.
    int (*end)(void* user);
};

struct RawrXD_SP_ConfigV1 {
    std::uint32_t abi_version;

    // The exact LocalServer port hosting ScreenPilot.
    std::uint16_t port;

    // UTF-8 absolute root. Agent workspaces must be this directory or a child.
    RawrXD_SP_String workspace_root;

    // Recommended: 0. Set to 1 only while opening ide_chatbot.html directly
    // from file://. Production should serve the page from localhost instead.
    int allow_null_origin;
};

// Call once during LocalServer startup.
RAWRXD_SP_API int RawrXD_ScreenPilot_Initialize(
    const RawrXD_SP_ConfigV1* config,
    const RawrXD_SP_AuthorityV1* authority
);

// Call once during shutdown.
RAWRXD_SP_API void RawrXD_ScreenPilot_Shutdown();

// Invoke from your existing LocalServer router.
// Returns 1 if the path belongs to ScreenPilot and was handled, 0 otherwise.
RAWRXD_SP_API int RawrXD_ScreenPilot_HandleHttp(
    const RawrXD_SP_HttpRequestV1* request,
    const RawrXD_SP_HttpSinkV1* sink
);

} // extern "C"
