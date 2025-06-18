#include <cerrno>
#include <print>
#include <system_error>

#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

using std::print, std::println;

enum class Domain : int {
    IPv4 = AF_INET,
    // IPv6 = AF_INET6,
};
enum class SocketType : int {
    Stream = SOCK_STREAM,
    Datagram = SOCK_DGRAM,
};
enum class Protocol : int {
    Default = 0,
};

constexpr int INVALID_FD = -1;
constexpr int SYSCALL_ERR = -1;

using FileDescriptor = int;
using Port = uint16_t;

class MySocket {
public:
    MySocket(int domain, int socket_type, int protocol)
        : MySocket(
              static_cast<Domain>(domain),
              static_cast<SocketType>(socket_type),
              static_cast<Protocol>(protocol)) {}
    MySocket(Domain domain_, SocketType socket_type_, Protocol protocol_)
        : domain(domain_),
          socket_type(socket_type_),
          protocol(protocol_),
          fd(::socket(
              static_cast<int>(domain),
              static_cast<int>(socket_type),
              static_cast<int>(protocol))) {
        if (fd == INVALID_FD) {
            throw std::system_error(errno, std::system_category(), "socket()");
        }
        println("Socket created with FD = {}", fd);
    }

    ~MySocket() {
        if (fd != INVALID_FD) {
            println("Closing socket with FD = {}", fd);
            if (::close(fd) == SYSCALL_ERR) {
                println(
                    "Destructor error: close() failed: {}",
                    std::system_error(errno, std::system_category(), "close()").what());
            }
        }
    }

    void bind(const std::string &ip_address, Port port) {
        // TODO
    }

    FileDescriptor get_fd() const { return fd; }

private:
    FileDescriptor fd;
    Domain domain;
    SocketType socket_type;
    Protocol protocol;
};

int main() {
    try {
        MySocket s(Domain::IPv4, SocketType::Stream, Protocol::Default);
    } catch (const std::system_error &e) {
        println("Error: {} ({})", e.what(), e.code().message());
        return EXIT_FAILURE;
    }
}