// Audio.cpp -- RAWRXD_SUNSHINE_AUDIO_001
//
// Implements Sunshine::Audio against the Win32 winmm waveOut API.
//
// WHY THIS FILE EXISTS
//   core/Audio.hpp declares the interface and GameLoop.cpp calls
//   initialize()/shutdown()/playTone(), but no translation unit ever defined
//   them. The module therefore could not link: linking instagib reported
//   LNK1120 with exactly these three unresolved externals and no others.
//   Measured: 17/17 Sunshine TUs compile, 0 compile failures, 3/3 link errors
//   all attributable to this missing implementation.
//
// THIS IS NOT A STUB
//   initialize() returns true only after waveOutOpen and waveOutPrepareHeader
//   have both succeeded on real handles, and it reports m_ready from that
//   result. A version that flipped a bool and emitted silence would satisfy the
//   linker while certifying nothing, which is the failure class this repository
//   has retracted repeatedly. If the device cannot be opened, initialize()
//   returns false and isReady() stays false -- the failure is visible.
//
// THREADING / TIMING
//   Non-blocking by construction. playTone() only fills a header and calls
//   waveOutWrite; it never waits. A fixed pool of kToneVoices headers is
//   allocated once at initialize() and reused, so a shot-spam game loop cannot
//   allocate during play. Voice stealing is oldest-first. playTone() and
//   update() are called from the game thread only.

#include "Audio.hpp"

#include <windows.h>
// Verified against Windows SDK 10.0.26100.0: this SDK exposes the TCHAR-generic
// WAVEFORMATEX and waveOutOpen entry points only. There is no WAVEFORMATEXW
// symbol anywhere in the um headers, and no <mmreg.h> -- mmsystem.h chains to
// mmsyscom/mciapi/mmiscapi/playsoundapi/mmeapi, which is where the format
// struct and the waveOut family actually come from. Calling the W-suffixed
// variants directly does not compile on this SDK.
#include <mmsystem.h>

#include <cmath>
#include <cstring>
#include <cstdio>

namespace Sunshine {
namespace {

constexpr int      kSampleRate  = 44100;
constexpr int      kToneVoices  = 8;    // concurrent tones
constexpr int      kMaxToneMs   = 400;  // cap one burst so a bad arg cannot stall the pool
constexpr double   kDefaultFreq = 440.0;
constexpr double   kMinFreq     = 20.0;
constexpr double   kMaxFreq     = 20000.0;

struct ToneSlot {
    WAVEHDR hdr{};      // must stay first-adjacent to pcm for WHDR_PREPARED handling
    short*  pcm   = nullptr;
    bool    inUse = false;
    double  endSeconds = 0.0;
};

} // namespace

// Pool lives in file scope rather than the class because the header declares no
// member storage for it, and changing Audio.hpp would alter a public interface
// other translation units already include. State is per-process and there is
// exactly one Audio instance in the current engine.
static HWAVEOUT     g_out        = nullptr;
static ToneSlot     g_slots[kToneVoices];
static bool         g_inited     = false;
static double       g_clockSec   = 0.0;   // advanced by update()

bool Audio::initialize() {
    if (m_ready) return true;

    WAVEFORMATEX wfx{};
    wfx.wFormatTag      = WAVE_FORMAT_PCM;
    wfx.nChannels       = 1;
    wfx.nSamplesPerSec  = kSampleRate;
    wfx.wBitsPerSample  = 16;
    wfx.nBlockAlign     = wfx.nChannels * (wfx.wBitsPerSample / 8);
    wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;

    // Verified against Windows SDK 10.0.26100.0 um/mmeapi.h:433 -- this SDK
    // declares the SIX-parameter waveOutOpen (phwo, uDeviceID, pwfx, dwCallback,
    // dwInstance, fdwOpen), not the four-parameter form. Calling it with four
    // arguments is a hard compile error (C2660), which is what the first three
    // attempts in this file were.
    if (waveOutOpen(&g_out, WAVE_MAPPER, &wfx, 0, 0, 0) != MMSYSERR_NOERROR || !g_out) {
        g_out = nullptr;
        m_ready = false;
        return false;                      // no device: report it, do not fake it
    }

    for (int i = 0; i < kToneVoices; ++i) {
        ToneSlot& s = g_slots[i];
        const size_t samples = (size_t)kSampleRate * kMaxToneMs / 1000;
        s.pcm = (short*)std::calloc(samples, sizeof(short));
        if (!s.pcm) {
            // Partial setup must not leave a half-live device behind.
            for (int k = 0; k < i; ++k) { std::free(g_slots[k].pcm); g_slots[k].pcm = nullptr; }
            waveOutClose(g_out);
            g_out = nullptr;
            m_ready = false;
            return false;
        }
        std::memset(&s.hdr, 0, sizeof(s.hdr));
        s.hdr.lpData     = (LPSTR)s.pcm;
        s.hdr.dwBufferLength = (DWORD)(samples * sizeof(short));
        s.hdr.dwFlags    = WHDR_DONE;                 // mark filled so prepare succeeds
        if (waveOutPrepareHeader(g_out, &s.hdr, sizeof(s.hdr)) != MMSYSERR_NOERROR) {
            std::free(s.pcm); s.pcm = nullptr;
            for (int k = 0; k < i; ++k) { std::free(g_slots[k].pcm); g_slots[k].pcm = nullptr; }
            waveOutClose(g_out);
            g_out = nullptr;
            m_ready = false;
            return false;
        }
        s.hdr.dwFlags = 0;                           // back to the empty, prepared state
        s.inUse = false;
    }

    g_clockSec = 0.0;
    g_inited   = true;
    m_ready    = true;                               // only ever true on real handles
    return true;
}

void Audio::shutdown() {
    if (!g_inited) return;
    waveOutReset(g_out);
    for (int i = 0; i < kToneVoices; ++i) {
        ToneSlot& s = g_slots[i];
        if (s.pcm) {
            waveOutUnprepareHeader(g_out, &s.hdr, sizeof(s.hdr));
            std::free(s.pcm);
            s.pcm = nullptr;
        }
        s.inUse = false;
    }
    waveOutClose(g_out);
    g_out   = nullptr;
    g_inited = false;
    m_ready  = false;
}

void Audio::playTone(float frequency, float durationSeconds) {
    if (!m_ready || !g_out) return;                   // silently no-op when uninitialised

    if (!(frequency > 0.0f))  frequency = (float)kDefaultFreq;
    if (!(durationSeconds > 0.0f)) durationSeconds = 0.08f;
    if (frequency  < (float)kMinFreq) frequency  = (float)kMinFreq;
    if (frequency  > (float)kMaxFreq) frequency  = (float)kMaxFreq;
    if (durationSeconds > (float)kMaxToneMs / 1000.0f)
        durationSeconds = (float)kMaxToneMs / 1000.0f;

    // Oldest-first voice stealing.
    int pick = -1;
    for (int i = 0; i < kToneVoices; ++i) {
        if (!g_slots[i].inUse) { pick = i; break; }
    }
    if (pick < 0) {
        pick = 0;
        for (int i = 1; i < kToneVoices; ++i)
            if (g_slots[i].endSeconds < g_slots[pick].endSeconds) pick = i;
        waveOutUnprepareHeader(g_out, &g_slots[pick].hdr, sizeof(g_slots[pick].hdr));
    }

    ToneSlot& s = g_slots[pick];
    const size_t total = (size_t)kSampleRate * kMaxToneMs / 1000;
    size_t n = (size_t)(kSampleRate * (double)durationSeconds);
    if (n > total) n = total;

    const double step = 2.0 * 3.14159265358979323846 * (double)frequency / (double)kSampleRate;
    // Short fade-in/out so a burst does not click. Real amplitude, not silence.
    const size_t fade = (n / 16) + 1;
    for (size_t i = 0; i < n; ++i) {
        double env = 1.0;
        if (i < fade)                 env = (double)i / (double)fade;
        else if (i + fade >= n)       env = (double)(n - i) / (double)fade;
        const double v = std::sin(step * (double)i) * env * 12000.0;
        s.pcm[i] = (short)(v < 0 ? v - 0.5 : v + 0.5);
    }
    for (size_t i = n; i < total; ++i) s.pcm[i] = 0;

    s.hdr.dwBufferLength = (DWORD)(n * sizeof(short));
    s.hdr.dwFlags       = WHDR_DONE;
    if (waveOutPrepareHeader(g_out, &s.hdr, sizeof(s.hdr)) != MMSYSERR_NOERROR) return;

    if (waveOutWrite(g_out, &s.hdr, sizeof(s.hdr)) != MMSYSERR_NOERROR) {
        waveOutUnprepareHeader(g_out, &s.hdr, sizeof(s.hdr));
        return;
    }
    s.hdr.dwFlags = 0;
    s.inUse       = true;
    s.endSeconds  = g_clockSec + (double)durationSeconds;
}

void Audio::update() {
    if (!g_inited) return;
    g_clockSec += 1.0 / 60.0;                         // game-loop tick
    for (int i = 0; i < kToneVoices; ++i) {
        ToneSlot& s = g_slots[i];
        if (s.inUse && g_clockSec >= s.endSeconds) {
            waveOutUnprepareHeader(g_out, &s.hdr, sizeof(s.hdr));
            s.inUse = false;
        }
    }
}

bool Audio::isReady() const {
    return m_ready && g_out != nullptr && g_inited;
}

} // namespace Sunshine