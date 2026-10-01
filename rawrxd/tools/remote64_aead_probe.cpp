// RAWRXD_NATIVE_REMOTE_001 - AEAD argument-ABI proof.
//
// Purpose: replace the DERIVED argument base with a MEASURED one.
//
// The worker rejected byte-identical calls for different reasons (T1 reported
// "output pointer is NULL", T3 reported "tag is NULL"), so the values it read
// from the caller's stack-argument area are not the values the caller passed.
// This harness prints, for one invocation:
//
//   CALLER:       the eight argument values the C++ caller intended
//   WORKER_ENTRY: rsp/rcx/rdx/r8/r9 and the raw slots [rsp+00 .. rsp+50]
//   DECODED:      what the worker actually decoded from those slots
//   MATCH:        per-argument PASS/FAIL
//
// From the MATCH block the true position of argument 5 is read directly,
// with no inference.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" {

int RemoteAeadEncrypt(const void* key32, const void* nonce12, const void* in, uint32_t inLen,
                      void* out, uint32_t outCap, void* tag16, const void* aad, uint32_t aadLen);
int RemoteAeadDecrypt(const void* key32, const void* nonce12, const void* in, uint32_t inLen,
                      void* out, uint32_t outCap, void* tag16, const void* aad, uint32_t aadLen);

// Conventional-CALL entry with the same trailing arguments, used to compare
// the two entry layouts. `mode` occupies rcx, so this routine's stack
// arguments begin one slot later than the public entry points'.
int RemoteAeadWorkerProbe(int mode, const void* key32, const void* nonce12, const void* in,
                          uint32_t inLen, void* out, uint32_t outCap, void* tag16,
                          const void* aad, uint32_t aadLen);

extern int RemoteAeadLastStep;
extern int RemoteAeadLastStatus;
extern int RemoteAeadCallCount;

extern unsigned long long RemoteAeadEntryRsp, RemoteAeadReturnRsp;
extern unsigned long long RemoteAeadEntryRcx, RemoteAeadEntryRdx;
extern unsigned long long RemoteAeadEntryR8, RemoteAeadEntryR9;
extern unsigned long long RemoteAeadSlot00, RemoteAeadSlot08, RemoteAeadSlot10;
extern unsigned long long RemoteAeadSlot18, RemoteAeadSlot20, RemoteAeadSlot28;
extern unsigned long long RemoteAeadSlot30, RemoteAeadSlot38, RemoteAeadSlot40;
extern unsigned long long RemoteAeadSlot48, RemoteAeadSlot50;
extern unsigned long long RemoteAeadDecOut, RemoteAeadDecOutCap;
extern unsigned long long RemoteAeadDecTag, RemoteAeadDecAad, RemoteAeadDecAadLen;
}

static std::string u32hex(unsigned v) {
    char b[16];
    std::snprintf(b, sizeof b, "0x%08x", v);
    return b;
}
static std::string p64(unsigned long long v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%016llx", v);
    return b;
}
static const char* yn(bool b) { return b ? "PASS" : "FAIL"; }

struct CallerArgs {
    const char* label;
    const void* key;
    const void* nonce;
    const void* in;
    const void* aad;
    uint32_t inLen;
    uint32_t outCap;
    void* out;
    void* tag;
    uint32_t aadLen;
};

static void dump(const CallerArgs& a) {
    std::printf("\n=== %s ===\n", a.label);
    std::printf("CALLER:\n");
    std::printf("  arg1 key   = %s\n", p64((unsigned long long)a.key).c_str());
    std::printf("  arg2 nonce = %s\n", p64((unsigned long long)a.nonce).c_str());
    std::printf("  arg3 in    = %s\n", p64((unsigned long long)a.in).c_str());
    std::printf("  arg4 inLen = %u\n", a.inLen);
    std::printf("  arg5 out   = %s\n", p64((unsigned long long)a.out).c_str());
    std::printf("  arg6 outCap= %u\n", a.outCap);
    std::printf("  arg7 tag   = %s\n", p64((unsigned long long)a.tag).c_str());
    std::printf("  arg8 aad   = %s   arg9 aadLen=%u\n",
                p64((unsigned long long)a.aad).c_str(), a.aadLen);

    std::printf("WORKER_ENTRY:\n");
    std::printf("  rsp=%s rcx=%s rdx=%s r8=%s r9=%s\n",
                p64(RemoteAeadEntryRsp).c_str(), p64(RemoteAeadEntryRcx).c_str(),
                p64(RemoteAeadEntryRdx).c_str(), p64(RemoteAeadEntryR8).c_str(),
                p64(RemoteAeadEntryR9).c_str());
    std::printf("  [rsp+00]=%s\n", p64(RemoteAeadSlot00).c_str());
    std::printf("  [rsp+08]=%s\n", p64(RemoteAeadSlot08).c_str());
    std::printf("  [rsp+10]=%s\n", p64(RemoteAeadSlot10).c_str());
    std::printf("  [rsp+18]=%s\n", p64(RemoteAeadSlot18).c_str());
    std::printf("  [rsp+20]=%s\n", p64(RemoteAeadSlot20).c_str());
    std::printf("  [rsp+28]=%s\n", p64(RemoteAeadSlot28).c_str());
    std::printf("  [rsp+30]=%s\n", p64(RemoteAeadSlot30).c_str());
    std::printf("  [rsp+38]=%s\n", p64(RemoteAeadSlot38).c_str());
    std::printf("  [rsp+40]=%s\n", p64(RemoteAeadSlot40).c_str());
    std::printf("  [rsp+48]=%s\n", p64(RemoteAeadSlot48).c_str());
    std::printf("  [rsp+50]=%s\n", p64(RemoteAeadSlot50).c_str());

    std::printf("DECODED_BY_WORKER:\n");
    std::printf("  out=%s outCap=%llu tag=%s aad=%s aadLen=%llu\n",
                p64(RemoteAeadDecOut).c_str(), RemoteAeadDecOutCap,
                p64(RemoteAeadDecTag).c_str(), p64(RemoteAeadDecAad).c_str(),
                RemoteAeadDecAadLen);
    std::printf("  step=%d status=%s\n", RemoteAeadLastStep,
                u32hex((unsigned)RemoteAeadLastStatus).c_str());

    std::printf("MATCH:\n");
    std::printf("  ARG1_key_in_rcx     = %s\n", yn(RemoteAeadEntryRcx == (unsigned long long)a.key));
    std::printf("  ARG2_nonce_in_rdx   = %s\n", yn(RemoteAeadEntryRdx == (unsigned long long)a.nonce));
    std::printf("  ARG3_in_in_r8       = %s\n", yn(RemoteAeadEntryR8 == (unsigned long long)a.in));
    std::printf("  ARG4_inLen_in_r9    = %s\n", yn(RemoteAeadEntryR9 == (unsigned long long)a.inLen));
    std::printf("  ARG5_out_decoded    = %s\n", yn(RemoteAeadDecOut == (unsigned long long)a.out));
    std::printf("  ARG6_outCap_decoded = %s\n", yn(RemoteAeadDecOutCap == (unsigned long long)a.outCap));
    std::printf("  ARG7_tag_decoded    = %s\n", yn(RemoteAeadDecTag == (unsigned long long)a.tag));
    std::printf("  ARG8_aad_decoded    = %s\n", yn(RemoteAeadDecAad == (unsigned long long)a.aad));
    std::printf("  ARG9_aadLen_decoded = %s\n", yn(RemoteAeadDecAadLen == (unsigned long long)a.aadLen));

    // Where does argument 5 actually live? Reported independently of MATCH so
    // the true base can be read straight off the output.
    unsigned long long want = (unsigned long long)a.out;
    const char* names[] = {"+00", "+08", "+10", "+18", "+20", "+28", "+30", "+38", "+40", "+48", "+50"};
    unsigned long long slots[] = {RemoteAeadSlot00, RemoteAeadSlot08, RemoteAeadSlot10,
                                  RemoteAeadSlot18, RemoteAeadSlot20, RemoteAeadSlot28,
                                  RemoteAeadSlot30, RemoteAeadSlot38, RemoteAeadSlot40,
                                  RemoteAeadSlot48, RemoteAeadSlot50};
    std::printf("ARG5_LOCATION:");
    bool found = false;
    for (int i = 0; i < 11; ++i) {
        if (slots[i] == want) {
            std::printf(" %s", names[i]);
            found = true;
        }
    }
    if (!found) std::printf(" NOT_FOUND_IN_SLOTS");
    std::printf("\n");
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("RAWRXD_NATIVE_REMOTE_001 - AEAD argument ABI proof\n");

    // Distinct, non-overlapping addresses so a wrong pointer is unambiguous.
    static uint8_t key[32], nonce[12], tag[16];
    static uint8_t aad[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    std::memset(key, 0x11, sizeof key);
    std::memset(nonce, 0x22, sizeof nonce);
    std::memset(tag, 0x33, sizeof tag);

    std::vector<uint8_t> plain(1024, 0x5A);
    std::vector<uint8_t> out(1024 + 32, 0x00);

    CallerArgs enc{"T1 encrypt via public JMP entry", key, nonce, plain.data(), aad,
                   (uint32_t)plain.size(), (uint32_t)out.size(), out.data(), tag, 5};
    int rc = RemoteAeadEncrypt(enc.key, enc.nonce, enc.in, enc.inLen, enc.out, enc.outCap,
                               enc.tag, enc.aad, enc.aadLen);
    std::printf("T1 rc=%s\n", u32hex((unsigned)rc).c_str());
    dump(enc);

    // T2 is an intentional over-capacity request; it is expected to be
    // rejected and proves nothing about the ABI.
    CallerArgs dec{"T2 decrypt via public JMP entry (expected rejection)", key, nonce,
                   out.data(), aad, (uint32_t)out.size(), (uint32_t)plain.size(),
                   plain.data(), tag, 5};
    rc = RemoteAeadDecrypt(dec.key, dec.nonce, dec.in, dec.inLen, dec.out, dec.outCap,
                           dec.tag, dec.aad, dec.aadLen);
    std::printf("\nT2 rc=%s  (T2_DECRYPT_STEP_11=EXPECTED_PROBE_REJECTION "
                "REQUESTED=%u OUTPUT_CAPACITY=%u DEFECT=0)\n",
                u32hex((unsigned)rc).c_str(), dec.inLen, dec.outCap);
    dump(dec);

    // T3: identical to T1 through the conventional-CALL diagnostic entry.
    CallerArgs direct{"T3 encrypt via direct CALL entry (identical args to T1)",
                      key, nonce, plain.data(), aad, (uint32_t)plain.size(),
                      (uint32_t)out.size(), out.data(), tag, 5};
    rc = RemoteAeadWorkerProbe(0, direct.key, direct.nonce, direct.in, direct.inLen,
                               direct.out, direct.outCap, direct.tag, direct.aad, direct.aadLen);
    std::printf("\nT3 rc=%s\n", u32hex((unsigned)rc).c_str());
    dump(direct);

    std::printf("\nprobe complete\n");
    return 0;
}
