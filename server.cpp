#include <cerrno>
#include <chrono>
#include <mutex>
#include <optional>
#include <print>
#include <ranges>
#include <shared_mutex>
#include <stack>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

using std::print, std::println;
using std::views::iota;

using namespace std::chrono_literals;

enum class Domain : int {
    IPv4 = AF_INET,
    // IPv6 = AF_INET6, // Not supported
};
enum class SocketType : int {
    Stream = SOCK_STREAM,
    Datagram = SOCK_DGRAM,
};
enum class Protocol : int {
    Default = 0,
};

inline std::string to_string(Domain d) {
    switch (d) {
    case Domain::IPv4:
        return "IPv4";
    }
    return "UnknownDomain";
}
inline std::string to_string(SocketType t) {
    switch (t) {
    case SocketType::Stream:
        return "Stream";
    case SocketType::Datagram:
        return "Datagram";
    }
    return "UnknownSocketType";
}
inline std::string to_string(Protocol p) {
    switch (p) {
    case Protocol::Default:
        return "Default";
    }
    return "UnknownProtocol";
}

template <>
struct std::formatter<Domain> : std::formatter<std::string> {
    auto format(Domain d, format_context &ctx) const {
        return std::formatter<std::string>::format(to_string(d), ctx);
    }
};

template <>
struct std::formatter<SocketType> : std::formatter<std::string> {
    auto format(SocketType s, format_context &ctx) const {
        return std::formatter<std::string>::format(to_string(s), ctx);
    }
};

template <>
struct std::formatter<Protocol> : std::formatter<std::string> {
    auto format(Protocol p, format_context &ctx) const {
        return std::formatter<std::string>::format(to_string(p), ctx);
    }
};

namespace mynet {
constexpr int INVALID_FD = -1;
constexpr int SYSCALL_ERR = -1;

using FileDescriptor = int;
using Port = uint16_t;

Port port = 12345;

class Socket {
public:
    Socket(int domain, int socket_type, int protocol)
        : Socket(
              static_cast<Domain>(domain),
              static_cast<SocketType>(socket_type),
              static_cast<Protocol>(protocol)) {}
    Socket(Domain domain_, SocketType socket_type_, Protocol protocol_)
        : domain(domain_),
          socket_type(socket_type_),
          protocol(protocol_),
          fd(::socket(
              static_cast<int>(domain_),
              static_cast<int>(socket_type_),
              static_cast<int>(protocol_))) {
        println("Creating socket with domain='{}',socket_type='{}',protocol='{}'", domain_, socket_type_, protocol_);
        if (fd == INVALID_FD) {
            throw std::system_error(errno, std::system_category(), "socket()");
        }
        println("Socket created with FD = {}", fd);
    }
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;

    Socket(Socket &&other) noexcept
        : fd(std::exchange(other.fd, INVALID_FD)),
          domain(other.domain),
          socket_type(other.socket_type),
          protocol(other.protocol) {}
    Socket &operator=(Socket &&other) noexcept {
        if (this != &other) {
            if (fd != INVALID_FD) ::close(fd);
            fd = std::exchange(other.fd, INVALID_FD);
            domain = other.domain;
            socket_type = other.socket_type;
            protocol = other.protocol;
        }
        return *this;
    }

    ~Socket() {
        if (fd != INVALID_FD) {
            println("Closing socket with FD = {}", fd);
            if (::close(fd) == SYSCALL_ERR) {
                println(
                    "Destructor error: close() failed: {}",
                    std::system_error(errno, std::system_category(), "close()").what());
            }
        }
    }

    [[nodiscard]]
    FileDescriptor get_fd() const {
        return fd;
    }

    void bind(const std::string &ip_address, Port port) {
        if (domain != Domain::IPv4) throw std::runtime_error("Only IPv4 supported for now!");

        int yes = 1;
        // Makes port reusable on quick restart
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == SYSCALL_ERR) {
            throw std::system_error(errno, std::system_category(), "setsockopt(SO_REUSEADDR)");
        }

        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = static_cast<sa_family_t>(domain);
        addr.sin_port = htons(port);

        if (::inet_pton(static_cast<int>(domain), ip_address.c_str(), &addr.sin_addr) <= 0) {
            throw std::system_error(errno, std::system_category(), "inet_pton()");
        }

        if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SYSCALL_ERR) {
            throw std::system_error(errno, std::system_category(), "bind()");
        }
        is_bound = true;
    }

    void listen(int backlog = SOMAXCONN) {
        if (!is_bound) throw std::runtime_error("Trying to listen before socket invoked bind()");
        if (is_listening) throw std::runtime_error("Already listening");

        if (socket_type != SocketType::Stream) {
            throw std::runtime_error("listen() only valid for SOCK_STREAM sockets");
        }
        if (::listen(fd, backlog) == SYSCALL_ERR) {
            throw std::system_error(errno, std::system_category(), "listen()");
        }
        println("Listening on FD = {} with backlog = {}", fd, backlog);
        is_listening = true;
    }

    [[nodiscard]]
    Socket accept() const {
        if (!is_listening) throw std::runtime_error("Can't invoke accept() before listen()");

        sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        std::memset(&client_addr, 0, sizeof(client_addr));

        int client_fd = ::accept(fd, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);
        if (client_fd == INVALID_FD) throw std::system_error(errno, std::system_category(), "accept()");
        println("Accepted new connection, FD = {}", client_fd);
        return Socket(client_fd, domain, socket_type, protocol);
    }

    [[nodiscard]]
    std::string receive(std::size_t max = 4096) const {
        std::string buf(max, '\0');
        ssize_t n = ::recv(fd, buf.data(), max, 0);
        if (n == SYSCALL_ERR) throw std::system_error(errno, std::system_category(), "recv()");
        buf.resize(n);
        println("Received message: {}", buf);
        return buf;
    }

    void send_all(const std::string &msg) const {
        println("Sending message: {}", msg);
        const char *p = msg.data();
        std::size_t left = msg.size();
        while (left > 0) {
            ssize_t n = ::send(fd, p, left, 0);
            if (n == SYSCALL_ERR) throw std::system_error(errno, std::system_category(), "send()");
            left -= n;
            p += n;
        }
    }

private:
    FileDescriptor fd{INVALID_FD};
    Domain domain;
    SocketType socket_type;
    Protocol protocol;
    bool is_bound{false};
    bool is_listening{false};

    // Gets created in accept
    Socket(FileDescriptor fd_, Domain domain_, SocketType socket_type_, Protocol protocol_)
        : fd{fd_},
          domain{domain_},
          socket_type{socket_type_},
          protocol{protocol_},
          is_bound{true},
          is_listening{false} {
        println("Creating socket from accept() with FD='{}'", fd);
    }
};

template <typename T>
class LockedStack {
public:
    LockedStack() = default;

    void push(T fd) {
        std::unique_lock _{mutex};
        fds.push(std::move(fd));
    }

    [[nodiscard]]
    std::optional<T> pop() {
        std::unique_lock _{mutex};
        if (fds.empty()) return std::nullopt;
        auto elem = std::optional<T>{std::move(fds.top())};
        fds.pop();
        return elem;
    }

    [[nodiscard]]
    size_t size() const {
        std::shared_lock _{mutex};
        return fds.size();
    }

    [[nodiscard]]
    bool empty() const {
        std::shared_lock _{mutex};
        return fds.size() == 0;
    }

private:
    std::stack<T> fds;
    mutable std::shared_mutex mutex;
};
} // namespace mynet

void _worker_task_handle_client(mynet::Socket &client, int i) {
    while (true) {
        println("[{}] Got fd {} to process.", i, client.get_fd());
        auto data = client.receive();
        if (data.empty() || data == "\r\n") break;
        client.send_all(data);
    }
}

void worker_task(mynet::LockedStack<mynet::Socket> &client_stack, int i) {
    while (true) {
        auto client_ = client_stack.pop();
        if (client_ != std::nullopt) {
            mynet::Socket client = std::move(*client_);
            _worker_task_handle_client(client, i);
            println("[{}] Finished processeing the client.", i);
        }
        std::this_thread::sleep_for(200ms);
    }
}

int main() {
    mynet::LockedStack<mynet::Socket> client_stack;
    constexpr size_t n_workers = 32;
    std::array<std::thread, n_workers> workers;
    for (int i : iota(0zu, n_workers)) {
        workers[i] = std::thread{
            [&client_stack, i] {
                worker_task(client_stack, static_cast<int>(i));
            }};
    }

    println("Initiating server");
    try {
        mynet::Socket server(Domain::IPv4, SocketType::Stream, Protocol::Default);
        server.bind("127.0.0.1", mynet::port);
        server.listen();

        while (true) {
            client_stack.push(server.accept());
        }
    } catch (const std::system_error &e) {
        println("Error: {} ({})", e.what(), e.code().message());
    }

    for (auto &worker : workers) {
        worker.join();
    }
}