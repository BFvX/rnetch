#include "tcp_relay.h"
#include <array>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>

namespace rnetch::tcp_relay {
namespace {

constexpr auto poll_interval = std::chrono::milliseconds(5);
constexpr auto accept_timeout = std::chrono::seconds(10);
constexpr std::size_t buffer_bytes = 32 * 1024;

[[noreturn]] void socket_failure(const char* operation, int error = WSAGetLastError()) {
    throw std::runtime_error(std::string(operation) + " failed (Winsock "
        + std::to_string(error) + ")");
}

int address_length(int family) {
    if (family == AF_INET) {
        return sizeof(sockaddr_in);
    }
    if (family == AF_INET6) {
        return sizeof(sockaddr_in6);
    }
    throw std::runtime_error("Unsupported TCP redirect address family");
}

bool mapped(const IN6_ADDR& address) {
    const unsigned char prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    return std::memcmp(&address, prefix, sizeof(prefix)) == 0;
}

bool all_zero(const unsigned char* bytes, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

sockaddr_storage bind_address(const sockaddr_storage& original) {
    sockaddr_storage bound{};
    if (original.ss_family == AF_INET) {
        sockaddr_in address{};
        std::memcpy(&address, &original, sizeof(address));
        address.sin_port = 0;
        if (address.sin_addr.s_addr == INADDR_ANY) {
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
        std::memcpy(&bound, &address, sizeof(address));
    } else if (original.ss_family == AF_INET6) {
        sockaddr_in6 address{};
        std::memcpy(&address, &original, sizeof(address));
        address.sin6_port = 0;
        auto* bytes = reinterpret_cast<unsigned char*>(&address.sin6_addr);
        if (all_zero(bytes, 16)) {
            bytes[15] = 1;
        } else if (mapped(address.sin6_addr) && all_zero(bytes + 12, 4)) {
            bytes[12] = 127;
            bytes[15] = 1;
        }
        std::memcpy(&bound, &address, sizeof(address));
    } else {
        throw std::runtime_error("Unsupported TCP redirect address family");
    }
    return bound;
}

struct PeerAddress {
    int family = AF_UNSPEC;
    std::array<unsigned char, 16> ip{};
    unsigned short port = 0;
    unsigned long scope = 0;
    bool wildcard = false;
};

PeerAddress peer_address(const sockaddr_storage& storage) {
    PeerAddress result;
    if (storage.ss_family == AF_INET) {
        sockaddr_in address{};
        std::memcpy(&address, &storage, sizeof(address));
        result.family = AF_INET;
        std::memcpy(result.ip.data(), &address.sin_addr, 4);
        result.port = address.sin_port;
        result.wildcard = all_zero(result.ip.data(), 4);
    } else if (storage.ss_family == AF_INET6) {
        sockaddr_in6 address{};
        std::memcpy(&address, &storage, sizeof(address));
        result.family = mapped(address.sin6_addr) ? AF_INET : AF_INET6;
        const auto* bytes = reinterpret_cast<const unsigned char*>(&address.sin6_addr);
        std::memcpy(result.ip.data(), bytes + (result.family == AF_INET ? 12 : 0),
            result.family == AF_INET ? 4 : 16);
        result.port = address.sin6_port;
        result.scope = result.family == AF_INET6 ? address.sin6_scope_id : 0;
        result.wildcard = all_zero(result.ip.data(), result.ip.size());
    }
    return result;
}

bool expected_peer(const PeerAddress& peer, const PeerAddress& expected) {
    if (peer.family == AF_UNSPEC || expected.family == AF_UNSPEC) {
        return false;
    }
    if (expected.port != 0 && peer.port != expected.port) {
        return false;
    }
    return expected.wildcard || (peer.family == expected.family && peer.ip == expected.ip
        && (expected.scope == 0 || peer.scope == expected.scope));
}

void make_nonblocking(SOCKET socket) {
    u_long enabled = 1;
    if (ioctlsocket(socket, FIONBIO, &enabled) == SOCKET_ERROR) {
        socket_failure("Set TCP socket nonblocking");
    }
}

bool would_retry(int error) {
    return error == WSAEWOULDBLOCK || error == WSAEINTR;
}

struct ShutdownGuard {
    SOCKET application;
    SOCKET proxy;
    ~ShutdownGuard() {
        shutdown(application, SD_BOTH);
        shutdown(proxy, SD_BOTH);
    }
};

struct Direction {
    std::array<char, buffer_bytes> buffer{};
    int begin = 0;
    int end = 0;
    bool eof = false;
    bool write_closed = false;

    bool pump(SOCKET input, SOCKET output, std::atomic<unsigned long long>& transferred) {
        if (write_closed) {
            return false;
        }
        bool progress = false;
        if (begin == end && !eof) {
            int count = recv(input, buffer.data(), static_cast<int>(buffer.size()), 0);
            if (count == 0) {
                eof = true;
                progress = true;
            } else if (count > 0) {
                begin = 0;
                end = count;
                progress = true;
            } else {
                int error = WSAGetLastError();
                if (!would_retry(error)) {
                    socket_failure("Receive relayed TCP data", error);
                }
            }
        }
        if (begin < end) {
            int count = send(output, buffer.data() + begin, end - begin, 0);
            if (count == 0) {
                throw std::runtime_error("Send relayed TCP data made no progress");
            }
            if (count > 0) {
                begin += count;
                transferred.fetch_add(static_cast<unsigned long long>(count),
                    std::memory_order_relaxed);
                progress = true;
            } else {
                int error = WSAGetLastError();
                if (!would_retry(error)) {
                    socket_failure("Send relayed TCP data", error);
                }
            }
        }
        if (eof && begin == end) {
            if (shutdown(output, SD_SEND) == SOCKET_ERROR) {
                socket_failure("Half-close relayed TCP output");
            }
            write_closed = true;
        }
        return progress;
    }
};

} // namespace

Listener listen(const sockaddr_storage& original_local) {
    Listener listener;
    listener.address = bind_address(original_local);
    listener.socket = utils::SocketHandle(WSASocketW(listener.address.ss_family, SOCK_STREAM,
        IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
    SOCKET socket = listener.socket.get();
    if (socket == INVALID_SOCKET) {
        socket_failure("Create TCP redirect listener");
    }
    if (listener.address.ss_family == AF_INET6) {
        DWORD v6_only = 0;
        if (setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY,
                reinterpret_cast<const char*>(&v6_only), sizeof(v6_only)) == SOCKET_ERROR) {
            socket_failure("Enable mapped IPv6 TCP redirection");
        }
    }
    make_nonblocking(socket);
    if (bind(socket, reinterpret_cast<const sockaddr*>(&listener.address),
            address_length(listener.address.ss_family)) == SOCKET_ERROR) {
        socket_failure("Bind TCP redirect listener");
    }
    if (::listen(socket, SOMAXCONN) == SOCKET_ERROR) {
        socket_failure("Listen for TCP redirection");
    }
    int length = sizeof(listener.address);
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&listener.address), &length) == SOCKET_ERROR) {
        socket_failure("Read TCP redirect listener address");
    }
    return listener;
}

utils::SocketHandle accept(SOCKET listener, const sockaddr_storage& expected,
    const std::function<bool()>& stopped) {
    make_nonblocking(listener);
    const PeerAddress expected_address = peer_address(expected);
    if (expected_address.family == AF_UNSPEC) {
        throw std::runtime_error("Unsupported expected TCP peer address family");
    }
    const auto deadline = std::chrono::steady_clock::now() + accept_timeout;
    while (!stopped()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            throw std::runtime_error("Timed out waiting for redirected TCP connection");
        }
        sockaddr_storage peer{};
        int peer_length = sizeof(peer);
        utils::SocketHandle application(::accept(listener, reinterpret_cast<sockaddr*>(&peer),
            &peer_length));
        if (application.get() != INVALID_SOCKET) {
            if (expected_peer(peer_address(peer), expected_address)) {
                return application;
            }
            shutdown(application.get(), SD_BOTH);
        } else {
            int error = WSAGetLastError();
            if (!would_retry(error)) {
                socket_failure("Accept redirected TCP connection", error);
            }
            std::this_thread::sleep_for(poll_interval);
        }
    }
    return utils::SocketHandle();
}

void relay(SOCKET application, SOCKET proxy, const std::function<bool()>& stopped,
    std::atomic<unsigned long long>& up, std::atomic<unsigned long long>& down) {
    ShutdownGuard shutdown_guard{application, proxy};
    for (SOCKET socket : {application, proxy}) {
        make_nonblocking(socket);
        BOOL enabled = TRUE;
        if (setsockopt(socket, IPPROTO_TCP, TCP_NODELAY,
                reinterpret_cast<const char*>(&enabled), sizeof(enabled)) == SOCKET_ERROR) {
            socket_failure("Disable TCP relay Nagle buffering");
        }
    }
    Direction upload;
    Direction download;
    while (!stopped() && !(upload.write_closed && download.write_closed)) {
        bool up_progress = upload.pump(application, proxy, up);
        bool down_progress = download.pump(proxy, application, down);
        if (!up_progress && !down_progress) {
            std::this_thread::sleep_for(poll_interval);
        }
    }
}

} // namespace rnetch::tcp_relay
