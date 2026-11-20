# S017 native bridge harness revalidation

`tools/release/bridge_lifecycle_test.cpp` is a real non-HTTP lifecycle test. It
constructs `Deep2Bridge`, initializes a GGUF path, performs three streamed
requests, requires a completion callback and at least one token per request,
then calls `Stop()`.

The current CMake configuration does not register this source as a standalone
target. The bridge implementation is compiled only as part of the full native
IDE target, so no standalone executable, executable hash, or runtime result can
be claimed from source inspection.

```ini
S017=SOURCE_REVALIDATED
HARNESS_SOURCE=PRESENT
HTTP_DEPENDENCY=NONE_IN_TEST
CMAKE_TARGET=MISSING
STANDALONE_BUILD=NOT_RUN
RUNTIME=NOT_RUN
ACCEPTANCE=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
