// ============================================================================
// src/video/tubi_backend.h -- Video clip render interface
// ============================================================================
// Declares rawrxd::video::renderVideoClip and its request/result types.
//
// ----------------------------------------------------------------------------
// WHY THIS FILE EXISTS NOW (RAWRXD_MISSING_SOURCE_001)
// ----------------------------------------------------------------------------
// src/core/gold_link_closure.cpp:772 opens with this header, and that file is in
// the RawrXD_Gold source list:
//
//     src\core\gold_link_closure.cpp(772,10): error C1083: Cannot open include
//         file: 'video/tubi_backend.h': No such file or directory
//
// The directory src/video/ did not exist either, so nothing in the tree had ever
// compiled against this interface.
//
// ----------------------------------------------------------------------------
// WHY THIS MATCHES gold_link_closure.cpp AND NOT gold_link_closure_v2.cpp
// ----------------------------------------------------------------------------
// Two files in this tree stub the same function and they disagree:
//
//   src/core/gold_link_closure.cpp:777
//       TubiRenderResult renderVideoClip(const TubiRenderRequest&)
//   src/core/gold_link_closure_v2.cpp:247
//       std::expected<TubiRenderResult, std::string> renderVideoClip(
//           const TubiRenderRequest&)
//
// They cannot both be satisfied by one declaration -- same parameter list, two
// different return types. Membership in the build graph decides it, not
// preference: gold_link_closure.cpp is in RawrXD_Gold, and
// gold_link_closure_v2.cpp is in NO target in this build tree (verified against
// every .vcxproj). So the non-expected form is declared here, which is what the
// only live consumer compiles against.
//
// The practical consequence for anyone reviving gold_link_closure_v2.cpp is
// recorded rather than hidden: that file will not compile against this header,
// and the disagreement is a real API decision that has not been made yet. It is
// not resolved here because no live code depends on the answer.
// ============================================================================

#pragma once

#include <string>

namespace rawrxd {
namespace video {

// Request to render a clip. No field of this struct is read by the live
// implementation -- gold_link_closure.cpp:778 discards the argument with
// `(void)request` -- so it carries no fields. It is declared as an empty
// aggregate rather than forward-declared because the parameter is by reference
// and an incomplete type would not be sufficient for a caller to construct one.
struct TubiRenderRequest {};

// Result of a render attempt. encoderDiagnostics is the only member written by
// the live implementation, which sets it to the fixed string
// "Video rendering not implemented in Gold build" and returns the default-
// constructed remainder. bool success is supplied so that a future
// implementation can report failure without changing the signature; nothing
// reads it today.
struct TubiRenderResult {
    bool        success = false;
    std::string encoderDiagnostics;
};

// Renders one clip. The live implementation performs no rendering and reports
// through encoderDiagnostics; the section comment above the definition in
// gold_link_closure.cpp says this stub exists for AgentToolHandlers.cpp and
// tool_registry.cpp.
TubiRenderResult renderVideoClip(const TubiRenderRequest& request);

} // namespace video
} // namespace rawrxd