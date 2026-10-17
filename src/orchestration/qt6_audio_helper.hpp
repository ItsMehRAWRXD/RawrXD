#pragma once

// QT-free audio helper using Windows Core Audio APIs (WASAPI)
// No Qt dependencies - works with the native Win32 IDE build

#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <vector>
#include <string>
#include <cstdint>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

// Audio format specification (QT-free equivalent of QAudioFormat)
struct AudioFormat {
    uint32_t sampleRate = 16000;       // Hz
    uint32_t channelCount = 1;         // 1=mono, 2=stereo
    uint32_t bitsPerSample = 16;       // 16-bit PCM
    bool isFloat = false;              // false=int16, true=float32

    uint32_t bytesPerFrame() const {
        return channelCount * (bitsPerSample / 8);
    }

    uint32_t bytesPerSecond() const {
        return sampleRate * bytesPerFrame();
    }
};

// Audio device information (QT-free equivalent of QAudioDevice)
struct AudioDevice {
    std::string id;
    std::string name;
    bool isDefault = false;
    bool isInput = false;
};

// ============================================================================
// Windows Core Audio (WASAPI) helper
// ============================================================================
class AudioHelper {
public:
    // Create a production-ready audio format for voice recording
    static AudioFormat createVoiceFormat(uint32_t sampleRate = 16000, uint32_t channelCount = 1) {
        AudioFormat fmt;
        fmt.sampleRate = sampleRate;
        fmt.channelCount = channelCount;
        fmt.bitsPerSample = 16;
        fmt.isFloat = false;
        return fmt;
    }

    // Enumerate audio input devices
    static std::vector<AudioDevice> getInputDevices() {
        return enumerateDevices(true);
    }

    // Enumerate audio output devices
    static std::vector<AudioDevice> getOutputDevices() {
        return enumerateDevices(false);
    }

    // Get default input device
    static AudioDevice getDefaultInputDevice() {
        auto devices = getInputDevices();
        for (const auto& d : devices) {
            if (d.isDefault) return d;
        }
        return devices.empty() ? AudioDevice{} : devices[0];
    }

    // Get default output device
    static AudioDevice getDefaultOutputDevice() {
        auto devices = getOutputDevices();
        for (const auto& d : devices) {
            if (d.isDefault) return d;
        }
        return devices.empty() ? AudioDevice{} : devices[0];
    }

    // Check if a format is supported by the device
    static bool isFormatSupported(const AudioDevice& /*device*/, const AudioFormat& format) {
        // WASAPI supports standard PCM formats; validate basic parameters
        return format.sampleRate > 0
            && format.channelCount > 0
            && (format.bitsPerSample == 16 || format.bitsPerSample == 32)
            && format.channelCount <= 8;
    }

    // Get nearest supported format (WASAPI: return desired if valid)
    static AudioFormat getNearestFormat(const AudioDevice& /*device*/, const AudioFormat& desired) {
        if (isFormatSupported(desired)) return desired;
        // Fallback to safe defaults
        AudioFormat fmt = createVoiceFormat();
        return fmt;
    }

    // Validate audio format configuration
    static bool validateFormat(const AudioFormat& format) {
        return format.sampleRate > 0
            && format.channelCount > 0
            && format.channelCount <= 8
            && (format.bitsPerSample == 16 || format.bitsPerSample == 32);
    }

private:
    static std::vector<AudioDevice> enumerateDevices(bool capture) {
        std::vector<AudioDevice> devices;

        HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(hr)) return devices;

        IMMDeviceEnumerator* enumerator = nullptr;
        hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                              __uuidof(IMMDeviceEnumerator), (void**)&enumerator);
        if (FAILED(hr)) { CoUninitialize(); return devices; }

        IMMDeviceCollection* collection = nullptr;
        EDataFlow flow = capture ? eCapture : eRender;
        hr = enumerator->EnumAudioEndpoints(flow, DEVICE_STATE_ACTIVE, &collection);
        if (FAILED(hr)) { enumerator->Release(); CoUninitialize(); return devices; }

        UINT count = 0;
        collection->GetCount(&count);

        for (UINT i = 0; i < count; ++i) {
            IMMDevice* device = nullptr;
            if (FAILED(collection->Item(i, &device))) continue;

            LPWSTR id = nullptr;
            if (SUCCEEDED(device->GetId(&id))) {
                IPropertyStore* props = nullptr;
                if (SUCCEEDED(device->OpenPropertyStore(STGM_READ, &props))) {
                    PROPVARIANT nameVar;
                    PropVariantInit(&nameVar);
                    if (SUCCEEDED(props->GetValue(PKEY_Device_FriendlyName, &nameVar))) {
                        AudioDevice dev;
                        dev.id = wideToUtf8(id);
                        dev.name = wideToUtf8(nameVar.pwszVal);
                        dev.isInput = capture;

                        // Check if default
                        IMMDevice* defaultDev = nullptr;
                        if (SUCCEEDED(enumerator->GetDefaultAudioEndpoint(flow, eConsole, &defaultDev))) {
                            LPWSTR defaultId = nullptr;
                            if (SUCCEEDED(defaultDev->GetId(&defaultId))) {
                                dev.isDefault = (wcscmp(id, defaultId) == 0);
                                CoTaskMemFree(defaultId);
                            }
                            defaultDev->Release();
                        }

                        devices.push_back(dev);
                        PropVariantClear(&nameVar);
                    }
                    props->Release();
                }
                CoTaskMemFree(id);
            }
            device->Release();
        }

        collection->Release();
        enumerator->Release();
        CoUninitialize();

        return devices;
    }

    static std::string wideToUtf8(LPCWSTR wide) {
        if (!wide) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0) return "";
        std::string result(size - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wide, -1, &result[0], size, nullptr, nullptr);
        return result;
    }
};
