// rawrxd_syntax_bridge.h - Syntax bridge for Win32IDE
// Stub header for build compatibility

#pragma once

#ifndef RAWRXD_SYNTAX_BRIDGE_H
#define RAWRXD_SYNTAX_BRIDGE_H

#include <cstdint>
#include <string>

namespace RawrXD {
namespace SyntaxBridge {

// Stub structures
struct SyntaxToken {
    uint32_t token_id;
    uint32_t start_pos;
    uint32_t end_pos;
    uint32_t token_type;
};

struct SyntaxBridgeContext {
    void* parser_state;
    uint32_t token_count;
};

// Stub functions
inline void InitSyntaxBridge(SyntaxBridgeContext* ctx) {
    ctx->parser_state = nullptr;
    ctx->token_count = 0;
}

inline void FreeSyntaxBridge(SyntaxBridgeContext* ctx) {
    // No-op stub
}

} // namespace SyntaxBridge
} // namespace RawrXD

#endif // RAWRXD_SYNTAX_BRIDGE_H