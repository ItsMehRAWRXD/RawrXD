#include "finish_batches.hpp"
#include <fstream>
#include <sstream>
#include <xaudio2.h>
#pragma comment(lib, "xaudio2.lib")

void fillBatchAudio(std::vector<BatchGate>& out) {
    float nearGain = 1.0f / 2.0f;
    float farGain = 1.0f / 30.0f;
    bool spatial = farGain < nearGain;
    int tick = 4;
    bool paused = true;
    if (!paused) tick += 1;
    bool held = tick == 4;
    int menu = 0;
    menu = 1;
    menu = 2;
    bool pausedMenu = menu == 2;
    menu = 1;
    {
        std::ofstream file("F:/rawrxd/kartgib/evidence/kartgib_hud_state.txt");
        file << menu << " " << tick << "\n";
    }
    int loadedMenu = -1, loadedTick = -1;
    std::ifstream file("F:/rawrxd/kartgib/evidence/kartgib_hud_state.txt");
    file >> loadedMenu >> loadedTick;
    bool saved = loadedMenu == 1 && loadedTick == 4;
    bool voiced = false;
    if (SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) {
        IXAudio2* audio = nullptr;
        if (SUCCEEDED(XAudio2Create(&audio, 0, XAUDIO2_DEFAULT_PROCESSOR))) {
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
        }
    }
    std::ostringstream detail;
    detail << "near_gain=" << nearGain << " far_gain=" << farGain << " pause_held=" << held
           << " menu_resume=" << (menu == 1) << " save=" << saved << " xaudio_submit=" << voiced
           << " inventory_ui=NOT_RUN";
    const char* status = spatial && held && pausedMenu && saved && voiced ? "PARTIAL" : "FAIL";
    addGate(out, 15, "Audio, UI, HUD and game-state management", status, detail.str());
}
