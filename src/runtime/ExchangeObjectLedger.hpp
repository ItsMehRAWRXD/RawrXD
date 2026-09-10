#pragma once
#include <stdint.h>

namespace rawrxd {

struct ExchangeObjectEvent {
    const char* phase;
    const char* model;
    const char* prompt;
    const char* exchangeId;
    const char* objectClass;
    const char* objectName;
    const char* owner;
    uint64_t bytes;
    bool visibleInMirror;
    const char* mirrorKey;
    bool mirrorMiss;
    const char* note;
};

void ExchangeLedger_Open(const char* path);
void ExchangeLedger_Close();
void ExchangeLedger_Log(const ExchangeObjectEvent& e);

} // namespace rawrxd
