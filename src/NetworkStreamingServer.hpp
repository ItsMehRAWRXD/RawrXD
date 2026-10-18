#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

namespace Deep2Engine::Network {

    class NetworkStreamingServer {
    public:
        NetworkStreamingServer(int port = 8085)
            : m_port(port), m_listen_socket(INVALID_SOCKET), m_client_socket(INVALID_SOCKET),
              m_is_running(false) {}

        ~NetworkStreamingServer() {
            stop_server();
        }

        bool start_server() {
            WSADATA wsa_data;
            if (::WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
                std::cerr << "[-] WinSock2 Initialization failed.\n";
                return false;
            }

            m_listen_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (m_listen_socket == INVALID_SOCKET) {
                ::WSACleanup();
                return false;
            }

            sockaddr_in server_addr{};
            server_addr.sin_family = AF_INET;
            server_addr.sin_addr.s_addr = INADDR_ANY;
            server_addr.sin_port = ::htons(static_cast<USHORT>(m_port));

            if (::bind(m_listen_socket, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
                ::closesocket(m_listen_socket);
                ::WSACleanup();
                return false;
            }

            if (::listen(m_listen_socket, SOMAXCONN) == SOCKET_ERROR) {
                ::closesocket(m_listen_socket);
                ::WSACleanup();
                return false;
            }

            m_is_running = true;
            m_accept_thread = std::thread(&NetworkStreamingServer::accept_loop, this);
            std::cout << "[✓] Streaming server listening on port " << m_port << "\n";
            return true;
        }

        void stream_token_fragment(const std::string& fragment) {
            std::lock_guard<std::mutex> lock(m_send_mutex);
            if (m_client_socket != INVALID_SOCKET && !fragment.empty()) {
                ::send(m_client_socket, fragment.c_str(), static_cast<int>(fragment.length()), 0);
            }
        }

        void stop_server() {
            m_is_running = false;
            if (m_listen_socket != INVALID_SOCKET) ::closesocket(m_listen_socket);
            if (m_client_socket != INVALID_SOCKET) ::closesocket(m_client_socket);
            if (m_accept_thread.joinable()) m_accept_thread.join();
            ::WSACleanup();
        }

        [[nodiscard]] bool has_active_client() const { return m_client_socket != INVALID_SOCKET; }

    private:
        void accept_loop() {
            while (m_is_running) {
                SOCKET client = ::accept(m_listen_socket, nullptr, nullptr);
                if (client != INVALID_SOCKET) {
                    std::lock_guard<std::mutex> lock(m_send_mutex);
                    if (m_client_socket != INVALID_SOCKET) {
                        ::closesocket(m_client_socket); // Drop stale client
                    }
                    m_client_socket = client;
                    std::cout << "[+] Client application attached to streaming socket.\n";
                }
            }
        }

        int m_port;
        SOCKET m_listen_socket;
        SOCKET m_client_socket;
        std::thread m_accept_thread;
        std::atomic<bool> m_is_running;
        std::mutex m_send_mutex;
    };
}
