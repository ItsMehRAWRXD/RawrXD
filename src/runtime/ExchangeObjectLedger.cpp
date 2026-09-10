#include "ExchangeObjectLedger.hpp"
#include <stdio.h>
#include <string.h>

namespace rawrxd {
namespace {
FILE* g_exchangeLedger = nullptr;
uint64_t g_seq = 0;
const char* safe(const char* s) { return s ? s : ""; }

void write_json_string(FILE* f, const char* s) {
    fputc('"', f);
    for (const char* p = safe(s); *p; ++p) {
        if (*p == '"' || *p == '\\') {
            fputc('\\', f);
            fputc(*p, f);
        } else if (*p == '\n') {
            fputs("\\n", f);
        } else if (*p == '\r') {
            fputs("\\r", f);
        } else if (*p == '\t') {
            fputs("\\t", f);
        } else {
            fputc(*p, f);
        }
    }
    fputc('"', f);
}
} // namespace

void ExchangeLedger_Open(const char* path) {
    ExchangeLedger_Close();
    if (!path || !path[0]) return;
    g_exchangeLedger = fopen(path, "wb");
    g_seq = 0;
}

void ExchangeLedger_Close() {
    if (!g_exchangeLedger) return;
    fflush(g_exchangeLedger);
    fclose(g_exchangeLedger);
    g_exchangeLedger = nullptr;
}

void ExchangeLedger_Log(const ExchangeObjectEvent& e) {
    if (!g_exchangeLedger) return;
    FILE* f = g_exchangeLedger;
    fputc('{', f);
    fprintf(f, "\"seq\":%llu,", (unsigned long long)g_seq++);
    fputs("\"phase\":", f); write_json_string(f, e.phase); fputc(',', f);
    fputs("\"model\":", f); write_json_string(f, e.model); fputc(',', f);
    fputs("\"prompt\":", f); write_json_string(f, e.prompt); fputc(',', f);
    fputs("\"exchange_id\":", f); write_json_string(f, e.exchangeId); fputc(',', f);
    fputs("\"object_class\":", f); write_json_string(f, e.objectClass); fputc(',', f);
    fputs("\"object_name\":", f); write_json_string(f, e.objectName); fputc(',', f);
    fputs("\"owner\":", f); write_json_string(f, e.owner); fputc(',', f);
    fprintf(f, "\"bytes\":%llu,", (unsigned long long)e.bytes);
    fprintf(f, "\"visible_in_mirror\":%s,", e.visibleInMirror ? "true" : "false");
    fputs("\"mirror_key\":", f); write_json_string(f, e.mirrorKey); fputc(',', f);
    fprintf(f, "\"mirror_miss\":%s,", e.mirrorMiss ? "true" : "false");
    fputs("\"note\":", f); write_json_string(f, e.note);
    fputs("}\n", f);
    fflush(f);
}

} // namespace rawrxd
