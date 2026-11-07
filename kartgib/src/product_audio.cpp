#include "product_scene.hpp"
#include <xaudio2.h>
#include <xinput.h>
#pragma comment(lib, "xaudio2.lib")
#pragma comment(lib, "xinput.lib")

bool submitProductAudio() {
    bool voiced = false;
    HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(co) && co != RPC_E_CHANGED_MODE) return false;
    IXAudio2* audio = nullptr;
    if (FAILED(XAudio2Create(&audio, 0, XAUDIO2_DEFAULT_PROCESSOR))) return false;
    IXAudio2MasteringVoice* master = nullptr;
    if (SUCCEEDED(audio->CreateMasteringVoice(&master))) {
        WAVEFORMATEX format{};
        format.wFormatTag = WAVE_FORMAT_PCM;
        format.nChannels = 1;
        format.nSamplesPerSec = 44100;
        format.wBitsPerSample = 16;
        format.nBlockAlign = 2;
        format.nAvgBytesPerSec = 88200;
        IXAudio2SourceVoice* source = nullptr;
        if (SUCCEEDED(audio->CreateSourceVoice(&source, &format))) {
            int16_t samples[32] = {};
            XAUDIO2_BUFFER buffer{};
            buffer.AudioBytes = sizeof(samples);
            buffer.pAudioData = reinterpret_cast<const BYTE*>(samples);
            voiced = SUCCEEDED(source->SubmitSourceBuffer(&buffer));
            source->DestroyVoice();
        }
        master->DestroyVoice();
    }
    audio->Release();
    return voiced;
}

int queryGamepad() {
    XINPUT_STATE state{};
    return static_cast<int>(XInputGetState(0, &state));
}
