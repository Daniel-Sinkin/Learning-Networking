#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

using std::print, std::println;

using CommunicationType = int;

enum class AddressFamily : int {
    IPv4 = AF_INET,
    IPv6 = AF_INET6
};

enum class SocketType : int {
    TCP = SOCK_STREAM,
    UDP = SOCK_DGRAM
};

enum class SocketProtocol : int {
    Default = 0,
    TCP = IPPROTO_TCP,
    UDP = IPPROTO_UDP
};

enum class SockOptLevel : int {
    Socket = SOL_SOCKET,
    IP = IPPROTO_IP,
    TCP = IPPROTO_TCP,
};

enum class SockOptName : int {
    ReuseAddr = SO_REUSEADDR,
    ReusePort = SO_REUSEPORT,
    KeepAlive = SO_KEEPALIVE,
};

constexpr int default_backlog = 32;
constexpr int port = 12345;

int load_port_from_dotenv(const char *filename = ".env") {
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Could not open " << filename << "; falling back to 12345\n";
        return 12345;
    }

    std::string line;
    while (std::getline(file, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        // basic trim
        key.erase(0, key.find_first_not_of(" \t\"")); // ltrim
        key.erase(key.find_last_not_of(" \t\"") + 1); // rtrim
        value.erase(0, value.find_first_not_of(" \t\""));
        value.erase(value.find_last_not_of(" \t\"") + 1);

        if (key == "port") return std::stoi(value);
    }
    std::cerr << "No 'port' key in " << filename << "; using 12345 as a fallback.\n";
    return 12345;
}

void handle_client(int client_fd) {
    println("handle_client({})", client_fd);
    std::this_thread::sleep_for(std::chrono::seconds(2));

    int num = 1 + std::rand() % 10;
    std::string response = std::to_string(num);
    println("sending response {}", response);

    send(client_fd, response.c_str(), response.size(), 0);
    close(client_fd);
}

int main() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    int port = load_port_from_dotenv();

    int server_fd = socket(
        static_cast<int>(AddressFamily::IPv4),
        static_cast<int>(SocketType::TCP),
        static_cast<int>(SocketProtocol::TCP));

    int yes = 1;
    setsockopt(
        server_fd,
        static_cast<int>(SockOptLevel::Socket),
        static_cast<int>(SockOptName::ReuseAddr),
        &yes,
        sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = static_cast<int>(AddressFamily::IPv4);
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));

    listen(server_fd, 32);

    println("Server listening on port {}", port);

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            std::perror("accept");
            continue;
        }
        std::thread(handle_client, client_fd).detach();
    }
}
