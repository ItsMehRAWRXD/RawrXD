#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

namespace Deep2Rom::Network {

    class NetworkStreamingServer {
    public:
        NetworkStreamingServer(int port = 8085) : m_port(port), m_listen(INVALID_SOCKET), m_client(INVALID_SOCKET), m_running(false) {}
        ~NetworkStreamingServer() { stop(); }

        bool start() {
            WSADATA wsa;
            if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
            m_listen = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = ::htons(static_cast<USHORT>(m_port));

            if (::bind(m_listen, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) return false;
            if (::listen(m_listen, SOMAXCONN) == SOCKET_ERROR) return false;

            m_running = true;
            m_worker = std::thread([this]() {
                while (m_running) {
                    SOCKET sock = ::accept(m_listen, nullptr, nullptr);
                    if (sock != INVALID_SOCKET) {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        if (m_client != INVALID_SOCKET) ::closesocket(m_client);
                        m_client = sock;
                        std::cout << "[Network] Client interface linked to streaming socket pipeline port.\n";
                    }
                }
            });
            return true;
        }

        void broadcast_token(const std::string& token) {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_client != INVALID_SOCKET) {
                ::send(m_client, token.c_str(), static_cast<int>(token.length()), 0);
            }
        }

        void stop() {
            m_running = false;
            if (m_listen != INVALID_SOCKET) ::closesocket(m_listen);
            if (m_client != INVALID_SOCKET) ::closesocket(m_client);
            if (m_worker.joinable()) m_worker.join();
            ::WSACleanup();
        }

    private:
        int m_port;
        SOCKET m_listen;
        SOCKET m_client;
        std::thread m_worker;
        std::mutex  m_mutex;
        std::atomic<bool> m_running;
    };
}