#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include <cstddef>

namespace RawrXD::IPC::Chat {
    enum class ChatMessageType : uint16_t {
        Error = 0,
        Request = 1,
        Response = 2
    };

    struct MessageSegmenter {
        bool Begin(ChatMessageType type, const std::string& payload) { return true; }
        bool HasNext() const { return false; }
        bool NextPrefixedWireBlob(std::vector<uint8_t>& prefixed) { return true; }
    };

    struct MessageReceiver {
        void Reset() {}
        void AppendStreamBytes(const std::vector<uint8_t>& chunk) {}
        bool TryPopLogicalMessage(ChatMessageType* msgType, std::string* payload) { return false; }
    };

    constexpr size_t WIRE_FRAME_PREFIX_SIZE = 8;
    constexpr size_t MAX_PIPE_FRAME_BYTES = 65536;
}

namespace RawrXD::ExtensionHost {

    constexpr const wchar_t* kDefaultPipeName = L"\\.\pipe\RawrXDExtensionHost";

    using LogicalMessageHandler = std::function<void(RawrXD::IPC::Chat::ChatMessageType, const std::string&)>;

    class ExtensionHostIpcBridge {
    public:
        ExtensionHostIpcBridge();
        explicit ExtensionHostIpcBridge(const wchar_t* pipeName);
        ~ExtensionHostIpcBridge();

        bool AttachServerHandle(HANDLE pipeHandle);
        bool ConnectAsClient(const wchar_t* pipeName = nullptr, DWORD waitMs = 5000);
        void Disconnect();

        void SetMessageHandler(LogicalMessageHandler handler);
        void PollIncomingTraffic();

        bool WriteMessage(uint16_t msgType, const uint8_t* payload, uint32_t payloadLen);
        bool WriteLogicalMessage(RawrXD::IPC::Chat::ChatMessageType type, const std::string& logicalPayload);
        bool WritePrefixedWireBlob(const uint8_t* data, size_t size);

    private:
        void DrainAvailableBytes();
        void DispatchLogicalMessages();
        void HandlePipeFailure();
        bool WriteAll(const uint8_t* data, DWORD size);

        std::wstring m_pipeName;
        HANDLE m_pipeHandle;
        bool m_ownsHandle;
        RawrXD::IPC::Chat::MessageReceiver m_receiver;
        LogicalMessageHandler m_onLogicalMessage;
    };
}
