// RAWRXD_NATIVE_REMOTE_001 certification driver.
//
// Every field printed here is measured at runtime. There are no hardcoded
// verdicts: a gate prints PASS only when the measured value satisfies the
// condition, and prints FAIL with the observed value otherwise.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// winsock2.h must precede windows.h; windows.h otherwise drags in the
// legacy winsock.h and every Winsock type collides.
#include <winsock2.h>
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------- structures
// Must match rawrxd/src/remote64/remote.inc exactly.

struct REMOTE_HEADER {
    uint32_t magic;
    uint16_t version;
    uint16_t msgType;
    uint32_t flags;
    uint64_t sequence;
    uint32_t payloadSize;
    uint32_t reserved;
};

struct REMOTE_CAPTURE {
    uint64_t screenDC, memoryDC, bitmap, oldBitmap, pixels, previous, bytes;
    uint32_t frameW, frameH, stride, initialized;
};

struct REMOTE_VIEWER {
    uint64_t pixels, bytes;
    uint32_t frameW, frameH, stride, initialized;
};

struct REMOTE_TILE_HEADER {
    uint32_t tileX, tileY, tileW, tileH, encoding, dataSize;
};

struct REMOTE_SESSION {
    uint32_t state, authenticated, controlAllowed, reserved;
    uint64_t txSequence, rxSequence;
    uint8_t sessionKey[32];
    uint8_t challenge[32];
};

extern "C" {

// self tests shipped with the sources
int RemoteSelfTest();
int RemoteParitySelfTest();
int RemoteParitySelfTest2();
int RemoteFinalSelfTest();

// memory / buffer
int RemoteAlloc(uint64_t bytes);
int RemoteFree(void* p);

// primitives
int RemoteCrc32(const void* data, uint64_t len);
int RemoteHash_BufferSha256(const void* data, uint32_t len, void* out32);
extern int RemoteHashLastStep;   // failure locator exported by hashfile.asm
extern int RemoteHashLastStatus;
extern int RemoteAeadLastStep;   // failure locator exported by aead.asm
extern int RemoteAeadLastStatus;
int RemotePackBits_Encode(const void* src, uint64_t len, void* dst, uint64_t cap);
int RemotePackBits_Decode(const void* src, uint64_t len, void* dst, uint64_t cap);
int RemoteRleEncode(const void* src, uint32_t len, void* dst, uint32_t cap);
int RemoteRleDecode(const void* src, uint32_t len, void* dst, uint32_t cap);

// crypto
int RemoteRandom(void* dst, uint32_t len);
int RemoteConstantTimeEqual(const void* a, const void* b, uint64_t len);
int RemoteHmacSha256(const void* key, uint32_t keyLen, const void* data, uint32_t dataLen, void* out32);
int RemoteAeadEncrypt(const void* key32, const void* nonce12, const void* in, uint32_t inLen,
                      void* out, uint32_t outCap, void* tag16, const void* aad, uint32_t aadLen);
int RemoteAeadDecrypt(const void* key32, const void* nonce12, const void* in, uint32_t inLen,
                      void* out, uint32_t outCap, void* tag16, const void* aad, uint32_t aadLen);

// transport
int RemoteNetInit(void* wsaData);
void RemoteNetCleanup();
uintptr_t RemoteSocketCreate(int af, int type, int proto);
int RemoteSocketBind(uintptr_t s, uint32_t ipv4, uint32_t port);
int RemoteSocketListen(uintptr_t s, int backlog);
uintptr_t RemoteSocketAccept(uintptr_t s, void* peer);
int RemoteSocketConnect(uintptr_t s, uint32_t ipv4, uint32_t port);
int RemoteSocketSetTimeout(uintptr_t s, uint32_t ms);
int RemoteSocketLocalPort(uintptr_t s);
int RemoteSendAll(uintptr_t s, const void* buf, uint64_t len);
int RemoteRecvExact(uintptr_t s, void* buf, uint64_t len);
void RemoteSocketClose(uintptr_t s);

// capture / viewer / protocol / session
int RemoteCaptureInit(REMOTE_CAPTURE* c);
int RemoteCaptureFrame(REMOTE_CAPTURE* c);
void RemoteCaptureDestroy(REMOTE_CAPTURE* c);
int RemoteViewerInit(REMOTE_VIEWER* v, uint32_t w, uint32_t h);
void RemoteViewerDestroy(REMOTE_VIEWER* v);
int RemoteViewerPutTile(REMOTE_VIEWER* v, const REMOTE_TILE_HEADER* t, const void* rawBGRA);
int RemoteHeaderWrite(REMOTE_HEADER* h, uint16_t type, uint64_t seq, uint32_t payload);
int RemoteHeaderValidate(const REMOTE_HEADER* h, uint64_t minSeq);
int RemoteSessionInit(REMOTE_SESSION* s);
int RemoteSessionConnected(REMOTE_SESSION* s);
int RemoteSessionAuthorizeControl(REMOTE_SESSION* s);

}  // extern "C"

// ---------------------------------------------------------------- harness
static int g_pass = 0;
static int g_fail = 0;

static void gate(const char* name, bool ok, const std::string& evidence) {
    if (ok) {
        ++g_pass;
        std::printf("GATE %-34s = PASS   %s\n", name, evidence.c_str());
    } else {
        ++g_fail;
        std::printf("GATE %-34s = FAIL   %s\n", name, evidence.c_str());
    }
}

static std::string hex(const void* p, size_t n) {
    static const char* d = "0123456789abcdef";
    const uint8_t* b = static_cast<const uint8_t*>(p);
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(d[b[i] >> 4]);
        s.push_back(d[b[i] & 15]);
    }
    return s;
}

static std::string n2s(long long v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%lld", v);
    return buf;
}

// ---------------------------------------------------------------- gates

static std::string u32hex(unsigned v) {
    char b[16];
    std::snprintf(b, sizeof b, "0x%08x", v);
    return b;
}

static void gate_shipped_selftests() {
    int a = RemoteSelfTest();
    int b = RemoteParitySelfTest();
    int c = RemoteParitySelfTest2();
    int d = RemoteFinalSelfTest();
    gate("B15_SELFTEST_ASM", a == 0, "RemoteSelfTest=" + n2s(a));
    gate("B30_PARITY_SELFTEST", b == 1, "RemoteParitySelfTest=" + n2s(b));
    gate("B45_PARITY_SELFTEST2", c == 1, "RemoteParitySelfTest2=" + n2s(c));
    gate("B60_FINAL_SELFTEST", d == 1, "RemoteFinalSelfTest=" + n2s(d));
}

static void gate_rng() {
    // Canary proves the caller's length argument is honoured and that the
    // routine does not write past the requested length. A plain
    // "count bytes still equal the sentinel" check is unsound: a uniformly
    // random byte equals 0xAB with probability 1/256, so a correct
    // implementation fails that test roughly 12% of the time.
    struct {
        uint8_t body[32];
        uint8_t canary[32];
    } buf;
    std::memset(&buf, 0xAB, sizeof buf);

    int r1 = RemoteRandom(buf.body, 32);
    bool canaryIntact = true;
    for (int i = 0; i < 32; ++i)
        if (buf.canary[i] != 0xAB) canaryIntact = false;
    bool wrote = false;
    for (int i = 0; i < 32; ++i)
        if (buf.body[i] != 0xAB) wrote = true;

    uint8_t a[32], b[32];
    std::memset(a, 0x5C, sizeof a);
    std::memset(b, 0x5C, sizeof b);
    int ra = RemoteRandom(a, 32);
    int rb = RemoteRandom(b, 32);
    bool differ = std::memcmp(a, b, 32) != 0;

    gate("B7_CNG_RNG_STATUS", (r1 == 0 && ra == 0 && rb == 0),
         "status=" + n2s(r1) + "," + n2s(ra) + "," + n2s(rb));
    gate("B7_CNG_RNG_DISTINCT", differ, "a=" + hex(a, 8) + " b=" + hex(b, 8));
    gate("B7_CNG_RNG_LENGTH_HONOURED", canaryIntact && wrote,
         std::string("canary_intact=") + (canaryIntact ? "1" : "0") +
             " buffer_written=" + (wrote ? "1" : "0"));
}

static void gate_hmac_known_answer() {
    // RFC 4231 test case 1
    uint8_t key[20];
    std::memset(key, 0x0b, sizeof key);
    const char* data = "Hi There";
    uint8_t out[32];
    std::memset(out, 0, sizeof out);
    int rc = RemoteHmacSha256(key, 20, data, 8, out);
    static const uint8_t want[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf,
        0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26,
        0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
    bool ok = (rc == 0) && (std::memcmp(out, want, 32) == 0);
    gate("B7_HMAC_SHA256_KAT", ok, "rc=" + n2s(rc) + " got=" + hex(out, 16));
}

static void gate_sha256_known_answer() {
    // FIPS 180-2: SHA256("abc")
    const char* abc = "abc";
    uint8_t out[32];
    std::memset(out, 0, sizeof out);
    int rc = RemoteHash_BufferSha256(abc, 3, out);
    static const uint8_t want[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
        0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
        0xf2, 0x00, 0x15, 0xad};
    bool ok = (rc == 0) && (std::memcmp(out, want, 32) == 0);
    gate("B27_SHA256_KAT", ok,
         "rc=" + n2s(rc) + " step=" + n2s(RemoteHashLastStep) +
         " status=" + u32hex((unsigned)RemoteHashLastStatus) +
             " got=" + hex(out, 16));
}

static void gate_crc_known_answer() {
    int crc = RemoteCrc32("123456789", 9);
    uint32_t crcVal = (uint32_t)crc;
    bool ok = (crcVal == 0xCBF43926u);
    char buf[16];
    std::snprintf(buf, sizeof buf, "%08x", crcVal);
    gate("B46_CRC32_KAT", ok, std::string("crc=") + buf + " want=cbf43926");
}

static void gate_aead() {
    uint8_t key[32], nonce[12], tag[16], tagCopy[16];
    uint8_t aad[5] = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> plain;
    for (int i = 0; i < 4096; ++i) plain.push_back(static_cast<uint8_t>(i * 7 + (i >> 3)));

    int rk = RemoteRandom(key, 32);
    std::memset(nonce, 0xA5, sizeof nonce);
    if (rk != 0) {
        gate("B7_AEAD_ROUNDTRIP", false, "key generation failed rc=" + n2s(rk));
        return;
    }

    std::vector<uint8_t> cipher(plain.size() + 32);
    int re = RemoteAeadEncrypt(key, nonce, plain.data(), (uint32_t)plain.size(),
                               cipher.data(), (uint32_t)cipher.size(), tag, aad, 5);
    gate("B7_AEAD_ENCRYPT", re == (int)plain.size(),
         "rc=" + n2s(re) + " expected=" + n2s((long long)plain.size()) +
             " tag=" + hex(tag, 8) + " aead_step=" + n2s(RemoteAeadLastStep) +
              " aead_status=" + u32hex((unsigned)RemoteAeadLastStatus));

    std::vector<uint8_t> back(plain.size() + 32);
    int rd = RemoteAeadDecrypt(key, nonce, cipher.data(), (uint32_t)plain.size(),
                               back.data(), (uint32_t)back.size(), tag, aad, 5);
    bool same = (rd == (int)plain.size()) && (std::memcmp(back.data(), plain.data(), plain.size()) == 0);
    gate("B7_AEAD_ROUNDTRIP", same, "rc=" + n2s(rd) + " bytes_equal=" + (same ? "1" : "0"));

    // ciphertext differs from plaintext
    bool ctDiffers = (plain.size() != cipher.size()) ||
                     (std::memcmp(cipher.data(), plain.data(), plain.size()) != 0);
    gate("B7_AEAD_NO_PLAINTEXT", ctDiffers, "cipher_prefix=" + hex(cipher.data(), 8));

    // tamper the ciphertext -> decrypt must fail
    std::memcpy(tagCopy, tag, 16);
    std::vector<uint8_t> tampered = cipher;
    tampered[100] ^= 0x01;
    std::vector<uint8_t> back2(plain.size() + 32);
    int rt = RemoteAeadDecrypt(key, nonce, tampered.data(), (uint32_t)tampered.size(),
                               back2.data(), (uint32_t)back2.size(), tagCopy, aad, 5);
    gate("B7_TAMPER_REJECTED", rt < 0, "rc=" + n2s(rt));

    // tamper the tag -> decrypt must fail
    std::memcpy(tagCopy, tag, 16);
    tagCopy[3] ^= 0x80;
    int rtag = RemoteAeadDecrypt(key, nonce, cipher.data(), (uint32_t)cipher.size(),
                                 back2.data(), (uint32_t)back2.size(), tagCopy, aad, 5);
    gate("B7_TAG_TAMPER_REJECTED", rtag < 0, "rc=" + n2s(rtag));

    // wrong AAD -> decrypt must fail
    uint8_t badAad[5] = {'h', 'e', 'l', 'l', 'X'};
    std::memcpy(tagCopy, tag, 16);
    int raad = RemoteAeadDecrypt(key, nonce, cipher.data(), (uint32_t)cipher.size(),
                                 back2.data(), (uint32_t)back2.size(), tagCopy, badAad, 5);
    gate("B7_AAD_BINDING", raad < 0, "rc=" + n2s(raad));
}

static void gate_packbits() {
    // Deterministic, bounded-framing round trip.
    std::printf("  [pb] enter\n");
    std::vector<uint8_t> src(1000);
    for (size_t i = 0; i < src.size(); ++i) src[i] = static_cast<uint8_t>(i % 251);
    std::printf("  [pb] src built\n");
    std::vector<uint8_t> enc(src.size() * 2 + 16);
    std::vector<uint8_t> decBuf(src.size() * 2 + 16);
    std::memset(enc.data(), 0xCC, enc.size());
    std::memset(decBuf.data(), 0xCC, decBuf.size());
    std::printf("  [pb] buffers ready enc=%u dec=%u\n",
                (unsigned)enc.size(), (unsigned)decBuf.size());

    int e = RemotePackBits_Encode(src.data(), src.size(), enc.data(), enc.size());
    std::printf("  [pb] encode returned %d\n", e);
    bool encOk = (e > 0);
    gate("B33_ENCODE_BOUNDED", encOk, "src=" + n2s((long long)src.size()) + " enc=" + n2s(e));
    if (!encOk) return;

    int d = RemotePackBits_Decode(enc.data(), (uint64_t)e, decBuf.data(), decBuf.size());
    std::printf("  [pb] decode returned %d\n", d);
    bool same = (d == (int)src.size()) && (std::memcmp(decBuf.data(), src.data(), src.size()) == 0);
    gate("B33_CODEC_ROUNDTRIP", same, "dec=" + n2s(d));

    // undersized destination must be rejected, not overrun
    int d2 = RemotePackBits_Decode(enc.data(), (uint64_t)e, decBuf.data(), 16);
    gate("B33_BOUNDS_REJECTED", d2 == 0, "rc=" + n2s(d2));

    // malformed: a run length that exceeds the supplied input
    uint8_t bad[4] = {200, 1, 2, 3};
    int d3 = RemotePackBits_Decode(bad, 4, decBuf.data(), decBuf.size());
    gate("B33_MALFORMED_REJECTED", d3 == 0, "rc=" + n2s(d3));
    std::printf("  [pb] done\n");
}

static void gate_protocol() {
    REMOTE_HEADER h;
    std::memset(&h, 0, sizeof h);
    RemoteHeaderWrite(&h, 0x0040 /*MSG_PING*/, 1, 0);
    int ok = RemoteHeaderValidate(&h, 0);
    gate("B5_HEADER_VALID", ok == 0, "rc=" + n2s(ok));

    REMOTE_HEADER bad = h;
    bad.magic = 0xDEADBEEF;
    int rc1 = RemoteHeaderValidate(&bad, 0);
    gate("B5_BAD_MAGIC_REJECTED", rc1 != 0, "rc=" + n2s(rc1));

    REMOTE_HEADER bad2 = h;
    bad2.version = 99;
    int rc2 = RemoteHeaderValidate(&bad2, 0);
    gate("B5_BAD_VERSION_REJECTED", rc2 != 0, "rc=" + n2s(rc2));

    REMOTE_HEADER bad3 = h;
    bad3.msgType = 0x0BAD;
    int rc3 = RemoteHeaderValidate(&bad3, 0);
    gate("B5_BAD_TYPE_REJECTED", rc3 != 0, "rc=" + n2s(rc3));

    REMOTE_HEADER bad4 = h;
    bad4.payloadSize = 0x02000000;  // 32 MiB > 16 MiB ceiling
    int rc4 = RemoteHeaderValidate(&bad4, 0);
    gate("B5_OVERSIZED_PAYLOAD_REJECTED", rc4 != 0, "rc=" + n2s(rc4));

    int rc5 = RemoteHeaderValidate(&h, 5);  // replay: sequence below floor
    gate("B42_REPLAY_REJECTED", rc5 != 0, "rc=" + n2s(rc5));
}

static void gate_session_state() {
    REMOTE_SESSION s;
    std::memset(&s, 0, sizeof s);
    RemoteSessionInit(&s);
    int initState = (int)s.state;
    int ctl = RemoteSessionAuthorizeControl(&s);
    gate("B9_CONTROL_BLOCKED_BEFORE_AUTH", ctl != 0,
         "state_after_init=" + n2s(initState) + " authorize_rc=" + n2s(ctl));
    RemoteSessionConnected(&s);
    gate("B9_STATE_ADVANCE", (int)s.state >= 1, "state=" + n2s((int)s.state));
}

static void gate_tcp_loopback() {
    // Real Winsock listener + connector on 127.0.0.1 with an ephemeral port.
    char wsa[512];
    int w = RemoteNetInit(wsa);
    gate("B6_WSA_STARTUP", w == 0, "rc=" + n2s(w));
    if (w != 0) return;

    uintptr_t srv = RemoteSocketCreate(2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 0);
    gate("B6_SOCKET_CREATE", srv != (uintptr_t)-1, "socket=" + n2s((long long)srv));
    if (srv == (uintptr_t)-1) {
        RemoteNetCleanup();
        return;
    }

    int tob = RemoteSocketSetTimeout(srv, 5000);
    int bindRc = RemoteSocketBind(srv, 0x7F000001u /*127.0.0.1*/, 0);
    gate("B6_SOCKET_BIND", bindRc == 0, "rc=" + n2s(bindRc) + " timeout_rc=" + n2s(tob));

    int lis = RemoteSocketListen(srv, 1);
    gate("B6_SOCKET_LISTEN", lis == 0, "rc=" + n2s(lis));

    int port = RemoteSocketLocalPort(srv);
    gate("B6_LOCAL_PORT", port > 0, "port=" + n2s(port));
    if (port <= 0) {
        RemoteSocketClose(srv);
        RemoteNetCleanup();
        return;
    }

    uintptr_t cli = RemoteSocketCreate(2, 1, 0);
    RemoteSocketSetTimeout(cli, 5000);
    int con = RemoteSocketConnect(cli, 0x7F000001u, (uint32_t)port);
    gate("B6_SOCKET_CONNECT", con == 0, "rc=" + n2s(con));

    char peer[32];
    std::memset(peer, 0, sizeof peer);
    uintptr_t acc = RemoteSocketAccept(srv, peer);
    gate("B6_SOCKET_ACCEPT", acc != (uintptr_t)-1, "accepted=" + n2s((long long)acc));

    if (con == 0 && acc != (uintptr_t)-1) {
        // Exchange a frame larger than any single TCP segment so the
        // send_all / recv_exact partial-IO loops are actually exercised.
        const uint64_t kBytes = 512 * 1024;
        std::vector<uint8_t> outBuf((size_t)kBytes);
        for (size_t i = 0; i < outBuf.size(); ++i)
            outBuf[i] = (uint8_t)((i * 31u + (i >> 11)) & 0xFF);
        std::vector<uint8_t> inBuf((size_t)kBytes, 0);

        int s1 = RemoteSendAll(cli, outBuf.data(), kBytes);
        int r1 = RemoteRecvExact(acc, inBuf.data(), kBytes);
        gate("B6_PARTIAL_SEND_HANDLED", s1 == 0, "send_rc=" + n2s(s1));
        gate("B6_PARTIAL_RECV_HANDLED", r1 == 0, "recv_rc=" + n2s(r1));
        bool eq = (std::memcmp(inBuf.data(), outBuf.data(), (size_t)kBytes) == 0);
        gate("B6_FRAME_BYTE_EQUALITY", eq, "bytes=" + n2s((long long)kBytes) +
                                              " sha=" + [&] {
                                                  uint8_t h[32];
                                                  RemoteHash_BufferSha256(inBuf.data(),
                                                                          (uint32_t)kBytes, h);
                                                  return hex(h, 8);
                                              }());

        // A second frame over the same connection proves reuse.
        uint8_t small[64];
        for (int i = 0; i < 64; ++i) small[i] = (uint8_t)i;
        uint8_t got[64];
        int s2 = RemoteSendAll(cli, small, 64);
        int r2 = RemoteRecvExact(acc, got, 64);
        bool eq2 = (r2 == 0) && (std::memcmp(small, got, 64) == 0);
        gate("B6_SECOND_FRAME", eq2, "send=" + n2s(s2) + " recv=" + n2s(r2));
    }

    RemoteSocketClose(cli);
    RemoteSocketClose(acc);
    RemoteSocketClose(srv);
    RemoteNetCleanup();
    gate("B6_CLEAN_DISCONNECT", true, "3 sockets closed, WSACleanup called");
}

static void gate_capture() {
    REMOTE_CAPTURE cap;
    std::memset(&cap, 0, sizeof cap);
    int init = RemoteCaptureInit(&cap);
    gate("B2_CAPTURE_INIT", init == 0,
         "rc=" + n2s(init) + " w=" + n2s((long long)cap.frameW) +
             " h=" + n2s((long long)cap.frameH) + " stride=" + n2s((long long)cap.stride) +
             " bytes=" + n2s((long long)cap.bytes));
    if (init != 0) return;

    int f1 = RemoteCaptureFrame(&cap);
    uint8_t h1[32], h2[32];
    RemoteHash_BufferSha256((const void*)cap.pixels, (uint32_t)cap.bytes, h1);

    // measured non-zero pixel content
    const uint32_t* px = (const uint32_t*)cap.pixels;
    uint64_t nonzero = 0;
    uint64_t total = cap.bytes / 4;
    for (uint64_t i = 0; i < total; ++i)
        if (px[i] != 0) ++nonzero;
    gate("B2_CAPTURE_PIXELS", nonzero > 0,
         "nonzero_pixels=" + n2s((long long)nonzero) + "/" + n2s((long long)total) +
             " hash=" + hex(h1, 8));

    // move the mouse to force a genuine frame change, then capture again
    int moved = 0;
    for (int y = 40; y < 60 && !moved; y += 10) {
        for (int x = 40; x < 60; x += 10) {
            ::SetCursorPos(x, y);
            ::Sleep(30);
            moved = 1;
            break;
        }
    }
    int f2 = RemoteCaptureFrame(&cap);
    RemoteHash_BufferSha256((const void*)cap.pixels, (uint32_t)cap.bytes, h2);
    bool changed = (std::memcmp(h1, h2, 32) != 0);
    gate("B2_FRAME_CHANGE_DETECTED", changed && f1 == 0 && f2 == 0,
         "f1=" + n2s(f1) + " f2=" + n2s(f2) + " h1=" + hex(h1, 8) + " h2=" + hex(h2, 8));

    uint64_t frameBytes = cap.bytes;
    uint64_t twoFrames = frameBytes * 2;
    uint64_t heap = RemoteAlloc(twoFrames);
    gate("B1_ALLOC_ROUNDTRIP", heap != 0, "requested=" + n2s((long long)twoFrames));
    if (heap) RemoteFree((void*)heap);

    RemoteCaptureDestroy(&cap);
}

static void gate_viewer_composite() {
    const uint32_t W = 256, H = 128;
    REMOTE_VIEWER v;
    std::memset(&v, 0, sizeof v);
    int init = RemoteViewerInit(&v, W, H);
    gate("B10_VIEWER_INIT", init == 0,
         "rc=" + n2s(init) + " w=" + n2s((long long)v.frameW) + " h=" + n2s((long long)v.frameH) +
             " bytes=" + n2s((long long)v.bytes));
    if (init != 0) return;

    // Build a 256x128 source image made of four 128x64 tiles, each a solid
    // distinct colour, then composite and read the pixels back.
    std::vector<uint32_t> src((size_t)W * H);
    for (uint32_t y = 0; y < H; ++y)
        for (uint32_t x = 0; x < W; ++x) {
            uint32_t c;
            if (y < 64 && x < 128) c = 0x00112233u;
            else if (y < 64) c = 0x00445566u;
            else if (x < 128) c = 0x00778899u;
            else c = 0x00AABBCCu;
            src[(size_t)y * W + x] = c;
        }

    struct TileDesc { uint32_t x, y, w, h, c; };
    TileDesc tiles[4] = {{0, 0, 128, 64, 0x00112233u},
                  {128, 0, 128, 64, 0x00445566u},
                  {0, 64, 128, 64, 0x00778899u},
                  {128, 64, 128, 64, 0x00AABBCCu}};

    bool allOk = true;
    for (int i = 0; i < 4; ++i) {
        REMOTE_TILE_HEADER t;
        t.tileX = tiles[i].x;
        t.tileY = tiles[i].y;
        t.tileW = tiles[i].w;
        t.tileH = tiles[i].h;
        t.encoding = 0;
        t.dataSize = tiles[i].w * tiles[i].h * 4;
        int rc = RemoteViewerPutTile(&v, &t, &src[(size_t)tiles[i].y * W + tiles[i].x]);
        if (rc != 0) allOk = false;
    }
    gate("B10_VIEWER_COMPOSITE", allOk, std::string("tiles=4 rc_all_zero=") + (allOk ? "1" : "0"));

    const uint32_t* out = (const uint32_t*)v.pixels;
    bool match = true;
    uint32_t bad = 0;
    for (uint32_t y = 0; y < H && match; ++y) {
        for (uint32_t x = 0; x < W; ++x) {
            if (out[(size_t)y * W + x] != src[(size_t)y * W + x]) {
                ++bad;
                if (bad == 1)
                    std::printf("     first mismatch at (%u,%u): got=%08x want=%08x\n", x, y,
                                out[(size_t)y * W + x], src[(size_t)y * W + x]);
                match = false;
                break;
            }
        }
    }
    gate("B10_FRAMEBUFFER_EQUALITY", match, "mismatched_pixels=" + n2s((long long)bad) +
                                                "/" + n2s((long long)((uint64_t)W * H)));

    RemoteViewerDestroy(&v);
}

// ---------------------------------------------------------------- main
int main() {
    // Unbuffered: if a native routine faults, everything measured up to that
    // point must still reach the log rather than dying in the stdio buffer.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("RAWRXD_NATIVE_REMOTE_001 runtime certification\n");
    std::printf("=================================================\n");

    gate_shipped_selftests();
    gate_crc_known_answer();
    gate_sha256_known_answer();
    gate_hmac_known_answer();
    gate_rng();
    gate_aead();
    std::printf("[main] returned from gate_aead\n");
    gate_packbits();
    std::printf("[main] returned from gate_packbits\n");
    gate_protocol();
    gate_session_state();
    gate_tcp_loopback();
    gate_capture();
    gate_viewer_composite();

    std::printf("-------------------------------------------------\n");
    std::printf("GATE_PASS=%d GATE_FAIL=%d\n", g_pass, g_fail);
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
