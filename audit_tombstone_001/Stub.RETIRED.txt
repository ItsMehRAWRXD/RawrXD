// RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001
//
// RETIRED. This file is a tombstone, not an implementation, and it is
// intentionally empty. It is retained on disk (rather than deleted) only so
// that this filename cannot be silently re-created by a configure-time source
// sweep. It is referenced by NO CMake target.
//
// MEASURED BASIS FOR RETIREMENT (2026-10-02, not assumed):
//
//   1. It has never had an implementation. `git log --follow` over the file
//      yields 7 revisions; every one is this single line. There is no lost
//      work to restore and no regression to repair.
//   2. It declared no API. No header of this name exists, so it could not
//      declare one.
//   3. It had no consumer. Zero #include sites, zero callers, zero symbol
//      references anywhere in the tree.
//   4. It reached no target. rawrxd/CMakeLists.txt appended it to
//      WIN32IDE_SOURCES and then stripped it again with list(REMOVE_ITEM);
//      the source list advertised a translation unit that was never compiled.
//      That append/remove round trip is the defect. Both entries are gone.
//   5. Nothing specifies the product. No design doc, client, port assignment
//      or interface contract names a "Sovereign Deep2 server".
//      src/core/sovereign_interface_contract.h is a ring-attention swarm
//      contract (RingStatus / RingMetrics / LayerRequest), not a server.
//
// WHAT ACTUALLY SERVES DEEP2 OVER HTTP:
//
//   rawr-server  (rawrxd/CMakeLists.txt, target rawr-server)
//     src/deep2/deep2_openai_server_main.cpp
//     src/deep2/deep2_openai_server.cpp
//   Port 11435. OpenAI-compatible (/health, /v1/models, /v1/chat/completions)
//   plus Ollama-compatible /api/tags and the agentic routes. It is real, it
//   links, and it is covered by the smoke test in
//   rawrxd/audit/RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001/.
//
// DO NOT fill this file with a speculative server. Writing an API, a port and
// a route table here in order to then certify it would fabricate a product
// with no consumer, and the resulting receipt would measure nothing except
// the author's own ability to satisfy a test they also wrote.
//
// SHA256_AT_RETIREMENT = 91A41EDF8BB3338796B19C3CD11B9120EFDFDB5A425A2C620E0015682ECDC557
// (hash of the one-line stub this file replaced)
//
// RESTORE = git -C F:/~dev checkout HEAD -- rawrxd/src/deep2/Deep2Server_Sovereign.cpp
