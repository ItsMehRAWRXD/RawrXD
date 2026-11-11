// Notification Center - Qt-free implementation
#include <iostream>
#include <string>
#include <vector>

struct Notification {
    std::string title;
    std::string message;
};

class NotificationCenter {
public:
    NotificationCenter() = default;
    
    void showNotification(const std::string& title, const std::string& msg) {
        Notification n{title, msg};
        m_notifications.push_back(n);
        std::cout << "[" << title << "] " << msg << std::endl;
    }
    
private:
    std::vector<Notification> m_notifications;
};

int main() {
    NotificationCenter center;
    center.showNotification("Test", "Hello");
    return 0;
}
