// ============================================================================
// include/agent/hexmag_client.hpp
// ============================================================================
// This file previously carried its own complete copy of HexMagClient, so which
// definition a translation unit saw depended on its include-path order
// (src/agent and include/ are both on it).  Two declarations of one type that
// can differ is a duplicate-authority hazard, so this one now forwards to the
// single definition in src/agent/hexmag_client.hpp.
#pragma once
#include "../../src/agent/hexmag_client.hpp"