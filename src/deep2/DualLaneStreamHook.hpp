// DualLaneStreamHook.hpp — generateStream bind; stub if engine not linked.
#pragma once
#include <cstdint>

extern "C" int RawrLaneGenerateStream(void* engine, const char* prompt,
                                      uint32_t maxTok, uint32_t* tokensOut);
extern "C" int RawrLaneGenerateStreamStub(void* engine, const char* prompt,
                                          uint32_t maxTok, uint32_t* tokensOut);
extern "C" int RawrLaneStreamIsLive(void);
extern "C" int RawrLaneStreamIsLiveStub(void);

#ifdef _MSC_VER
#pragma comment(linker, "/alternatename:RawrLaneGenerateStream=RawrLaneGenerateStreamStub")
#pragma comment(linker, "/alternatename:RawrLaneStreamIsLive=RawrLaneStreamIsLiveStub")
#endif
