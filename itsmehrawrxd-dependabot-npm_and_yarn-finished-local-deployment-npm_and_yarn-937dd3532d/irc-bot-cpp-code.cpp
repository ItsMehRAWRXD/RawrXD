#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <regex>
#include <map>
#include <queue>
#include <mutex>
#include <condition_variable>

class IRCBot {
private:
    std::string server;
    int port;
    std::vector<std::string> channels;
    std::string nick;
    std::string username;
    std::string realname;
    std::string password;
    
    int socket_fd;
    bool connected;
    bool channels_joined;
    std::queue<std::string> message_queue;
    int reconnect_attempts;
    int max_reconnect_attempts;
    std::chrono::steady_clock::time_point last_message_time;
    int rate_limit_delay;
    
    std::mutex message_mutex;
    std::condition_variable message_cv;
    std::thread message_thread;
    bool running;

public:
    IRCBot(const std::string& server = "irc.rizon.net", 
           int port = 6667,
           const std::vector<std::string>& channels = {"#rawr"},
           const std::string& nick = "RawrZBot",
           const std::string& username = "bibbles11",
           const std::string& realname = "RawrZ Security Platform Monitor",
           const std::string& password = "bibbles11")
        : server(server), port(port), channels(channels), nick(nick), 
          username(username), realname(realname), password(password),
          socket_fd(-1), connected(false), channels_joined(false),
          reconnect_attempts(0), max_reconnect_attempts(5),
          rate_limit_delay(500), running(true) {
        
        last_message_time = std::chrono::steady_clock::now();
        message_thread = std::thread(&IRCBot::messageProcessor, this);
        connect();
    }
    
    ~IRCBot() {
        running = false;
        message_cv.notify_all();
        if (message_thread.joinable()) {
            message_thread.join();
        }
        disconnect();
    }

private:
    void connect() {
        struct sockaddr_in server_addr;
        struct hostent *host_info;
        
        // Create socket
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            std::cerr << "[BOT] Failed to create socket" << std::endl;
            reconnect();
            return;
        }
        
        // Get server info
        host_info = gethostbyname(server.c_str());
        if (host_info == nullptr) {
            std::cerr << "[BOT] Failed to resolve host: " << server << std::endl;
            close(socket_fd);
            reconnect();
            return;
        }
        
        // Setup server address
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        memcpy(&server_addr.sin_addr, host_info->h_addr_list[0], host_info->h_length);
        
        // Connect to server
        if (::connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "[BOT] Failed to connect to " << server << ":" << port << std::endl;
            close(socket_fd);
            reconnect();
            return;
        }
        
        std::cout << "[BOT] Connected to IRC server: " << server << ":" << port << std::endl;
        connected = true;
        channels_joined = false;
        reconnect_attempts = 0;
        
        // Send IRC registration
        sendRaw("NICK " + nick);
        sendRaw("USER " + username + " 0 * :" + realname);
        
        // Process queued messages
        std::lock_guard<std::mutex> lock(message_mutex);
        while (!message_queue.empty()) {
            std::string message = message_queue.front();
            message_queue.pop();
            sendToIRC(message);
        }
        
        // Start receiving data
        std::thread(&IRCBot::receiveData, this).detach();
    }
    
    void receiveData() {
        char buffer[4096];
        std::string line;
        
        while (connected && running) {
            int bytes_received = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                if (bytes_received == 0) {
                    std::cout << "[BOT] IRC connection closed by server" << std::endl;
                } else {
                    std::cerr << "[BOT] IRC connection error" << std::endl;
                }
                connected = false;
                reconnect();
                break;
            }
            
            buffer[bytes_received] = '\0';
            line += buffer;
            
            // Process complete lines
            size_t pos = 0;
            while ((pos = line.find("\r\n")) != std::string::npos) {
                std::string complete_line = line.substr(0, pos);
                line.erase(0, pos + 2);
                
                if (!complete_line.empty()) {
                    handleIRCLine(complete_line);
                }
            }
        }
    }
    
    void handleIRCLine(const std::string& line) {
        // Handle PING
        if (line.substr(0, 4) == "PING") {
            std::string server_name = line.substr(5);
            sendRaw("PONG " + server_name);
            return;
        }
        
        // Handle authentication
        if (line.find("NickServ") != std::string::npos && line.find("IDENTIFY") != std::string::npos) {
            sendRaw("PRIVMSG NickServ :IDENTIFY " + password);
            std::cout << "[BOT] IRC: Identifying with NickServ" << std::endl;
            return;
        }
        
        // Try to identify after MOTD
        if (line.find("376") != std::string::npos || line.find("End of /MOTD command") != std::string::npos) {
            std::cout << "[BOT] IRC: MOTD received, attempting NickServ identification" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            sendRaw("PRIVMSG NickServ :IDENTIFY " + password);
            std::cout << "[BOT] IRC: Sending NickServ identify command" << std::endl;
        }
        
        // Handle successful authentication
        if (line.find("You are now identified") != std::string::npos || 
            line.find("Password accepted") != std::string::npos ||
            line.find("You are successfully identified") != std::string::npos) {
            std::cout << "[BOT] IRC: Successfully authenticated" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            for (const auto& channel : channels) {
                sendRaw("JOIN " + channel);
                std::cout << "[BOT] IRC: Joining channel " << channel << std::endl;
            }
            return;
        }
        
        // Handle MOTD end (fallback for channels that don't require auth)
        if (line.find("End of /MOTD command") != std::string::npos || line.find("376") != std::string::npos) {
            if (!channels_joined) {
                std::cout << "[BOT] IRC: MOTD received, joining channels" << std::endl;
                channels_joined = true;
                std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                for (const auto& channel : channels) {
                    sendRaw("JOIN " + channel);
                    std::cout << "[BOT] IRC: Joining channel " << channel << std::endl;
                }
            }
            return;
        }
        
        // Handle channel messages
        handleChannelMessage(line);
    }
    
    void handleChannelMessage(const std::string& line) {
        std::regex message_regex(R"(:([^!]+)![^@]+@[^ ]+ PRIVMSG ([^ ]+) :(.+))");
        std::smatch match;
        
        if (std::regex_match(line, match, message_regex)) {
            std::string nick_sender = match[1].str();
            std::string channel = match[2].str();
            std::string message = match[3].str();
            
            if (message.substr(0, 1) == "!") {
                handleCommand(nick_sender, channel, message);
            }
        }
    }
    
    void handleCommand(const std::string& nick, const std::string& channel, const std::string& message) {
        std::istringstream iss(message);
        std::vector<std::string> args;
        std::string arg;
        
        while (iss >> arg) {
            args.push_back(arg);
        }
        
        if (args.empty()) return;
        
        std::string command = args[0];
        std::transform(command.begin(), command.end(), command.begin(), ::tolower);
        
        if (command == "!status") {
            sendSystemStatus(nick);
        } else if (command == "!help") {
            sendHelp(nick, args.size() > 1 ? args[1] : "");
        } else if (command == "!ping") {
            sendToIRC(nick + ": Pong! RawrZ Security Platform is online and ready.");
        } else if (command == "!version") {
            sendToIRC(nick + ": RawrZ Security Platform v1.0.0 - Native C++ IRC Bot");
        } else if (command == "!info") {
            sendToIRC(nick + ": RawrZ Security Platform - Advanced Security Tools");
            sendToIRC(nick + ": Features: Encryption, Stealth, Anti-Analysis, Reverse Engineering");
            sendToIRC(nick + ": Native C++ implementation for maximum performance");
        } else if (command == "!commands") {
            sendToIRC(nick + ": Available commands: !status, !help, !ping, !version, !info, !commands");
        } else {
            sendToIRC(nick + ": Unknown command. Use !help for available commands.");
        }
    }
    
    void sendSystemStatus(const std::string& nick) {
        sendToIRC(nick + ": [STATUS] RawrZ Security Platform - Native C++ IRC Bot");
        sendToIRC(nick + ": [STATUS] System Health: Online and Operational");
        sendToIRC(nick + ": [STATUS] Connection: Connected to " + server + ":" + std::to_string(port));
        sendToIRC(nick + ": [STATUS] Channels: " + std::to_string(channels.size()) + " active");
        sendToIRC(nick + ": [STATUS] Uptime: Active and monitoring");
    }
    
    void sendHelp(const std::string& nick, const std::string& category) {
        if (category.empty()) {
            sendToIRC(nick + ": [BOT] RawrZ Security Platform - Native C++ IRC Bot");
            sendToIRC(nick + ": [CORE] !status, !help, !ping, !version, !info, !commands");
            sendToIRC(nick + ": [HELP] Use !help <category> for detailed information");
        } else {
            sendToIRC(nick + ": [HELP] Category: " + category);
            sendToIRC(nick + ": [HELP] This is a native C++ implementation of the RawrZ IRC Bot");
            sendToIRC(nick + ": [HELP] For full features, use the web interface at http://localhost:3000");
        }
    }
    
    void sendToIRC(const std::string& message) {
        if (!connected || socket_fd < 0) {
            std::lock_guard<std::mutex> lock(message_mutex);
            message_queue.push(message);
            return;
        }
        
        // Rate limiting
        auto now = std::chrono::steady_clock::now();
        auto time_since_last = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_message_time).count();
        
        if (time_since_last < rate_limit_delay) {
            std::this_thread::sleep_for(std::chrono::milliseconds(rate_limit_delay - time_since_last));
        }
        
        last_message_time = std::chrono::steady_clock::now();
        
        for (const auto& channel : channels) {
            sendRaw("PRIVMSG " + channel + " :" + message);
        }
    }
    
    void sendRaw(const std::string& command) {
        if (connected && socket_fd >= 0) {
            std::string full_command = command + "\r\n";
            send(socket_fd, full_command.c_str(), full_command.length(), 0);
        }
    }
    
    void messageProcessor() {
        while (running) {
            std::unique_lock<std::mutex> lock(message_mutex);
            message_cv.wait(lock, [this] { return !message_queue.empty() || !running; });
            
            while (!message_queue.empty() && connected) {
                std::string message = message_queue.front();
                message_queue.pop();
                lock.unlock();
                
                sendToIRC(message);
                
                lock.lock();
            }
        }
    }
    
    void reconnect() {
        if (reconnect_attempts >= max_reconnect_attempts) {
            std::cerr << "[BOT] Max reconnection attempts reached, giving up" << std::endl;
            return;
        }
        
        reconnect_attempts++;
        int delay = std::min(1000 * (1 << reconnect_attempts), 30000);
        
        std::cout << "[BOT] Reconnecting to IRC in " << delay << "ms (attempt " 
                  << reconnect_attempts << "/" << max_reconnect_attempts << ")" << std::endl;
        
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        connect();
    }
    
    void disconnect() {
        if (connected && socket_fd >= 0) {
            sendToIRC("[BOT] RawrZ Monitor disconnecting...");
            sendRaw("QUIT :RawrZ Security Platform Monitor shutting down");
            close(socket_fd);
            connected = false;
        }
    }
};

int main() {
    std::cout << "RawrZ Security Platform - Native C++ IRC Bot" << std::endl;
    std::cout << "Connecting to irc.rizon.net #rawr..." << std::endl;
    
    IRCBot bot("irc.rizon.net", 6667, {"#rawr"}, "RawrZBot", "bibbles11", 
               "RawrZ Security Platform Monitor", "bibbles11");
    
    // Keep the bot running
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return 0;
}
