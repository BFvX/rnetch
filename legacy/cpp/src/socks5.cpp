#include "socks5.h"
#include "proxy_process.h"
#include "utils/logger.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

namespace rnetch::socks5 {
namespace {
using Clock = std::chrono::steady_clock;
using Bytes = std::vector<unsigned char>;
constexpr auto io_timeout = std::chrono::seconds(5);
constexpr auto poll_interval = std::chrono::milliseconds(100);
rnetch::utils::Logger g_socks5_logger;

struct Deadline {
    Clock::time_point until = Clock::now() + io_timeout;
    const CancelCheck& cancelled;

    bool expired() const {
        if (cancelled && cancelled()) {
            WSASetLastError(WSAEINTR);
            return true;
        }
        if (Clock::now() >= until) {
            WSASetLastError(WSAETIMEDOUT);
            return true;
        }
        return false;
    }
};

bool failure(const char* stage, int error = WSAGetLastError()) {
    const auto message = std::string(stage) + " failed (Winsock " + std::to_string(error) + ")";
    g_socks5_logger.log(message);
    std::cerr << message << std::endl;
    WSASetLastError(error);
    return false;
}

struct Socket {
    SOCKET value = INVALID_SOCKET;
    ~Socket() {
        const int error = WSAGetLastError();
        if (value != INVALID_SOCKET) closesocket(value);
        WSASetLastError(error);
    }
};

// Public SOCKS helpers accept and return blocking sockets. The temporary mode
// permits exact I/O with one absolute deadline even if a peer trickles bytes.
struct NonblockingScope {
    SOCKET socket;
    bool active = false;

    explicit NonblockingScope(SOCKET value) : socket(value) {
        u_long mode = 1;
        active = ioctlsocket(socket, FIONBIO, &mode) == 0;
    }
    bool restore() {
        if (!active) return false;
        u_long mode = 0;
        if (ioctlsocket(socket, FIONBIO, &mode) != 0) return false;
        active = false;
        return true;
    }
    ~NonblockingScope() {
        const int error = WSAGetLastError();
        if (active) {
            u_long mode = 0;
            ioctlsocket(socket, FIONBIO, &mode);
        }
        WSASetLastError(error);
    }
};

bool wait_socket(SOCKET socket, bool writing, const Deadline& deadline) {
    while (!deadline.expired()) {
        fd_set ready;
        fd_set errors;
        FD_ZERO(&ready);
        FD_ZERO(&errors);
        FD_SET(socket, &ready);
        FD_SET(socket, &errors);
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline.until - Clock::now());
        const auto micros = std::min(remaining, std::chrono::duration_cast<std::chrono::microseconds>(poll_interval)).count();
        if (micros <= 0) continue;
        timeval timeout = {0, static_cast<long>(micros)};
        const int selected = select(0, writing ? nullptr : &ready, writing ? &ready : nullptr, &errors, &timeout);
        if (selected == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR) continue;
            return false;
        }
        if (selected == 0) continue;
        if (FD_ISSET(socket, &errors)) {
            int error = 0;
            int size = sizeof(error);
            if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) != 0) return false;
            WSASetLastError(error != 0 ? error : WSAECONNABORTED);
            return false;
        }
        return true;
    }
    return false;
}

bool send_all(SOCKET socket, const unsigned char* bytes, size_t size, const Deadline& deadline) {
    while (size > 0) {
        if (!wait_socket(socket, true, deadline)) return false;
        const int sent = send(socket, reinterpret_cast<const char*>(bytes), static_cast<int>(size), 0);
        if (sent == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINTR) continue;
            return false;
        }
        if (sent == 0) { WSASetLastError(WSAECONNRESET); return false; }
        bytes += sent;
        size -= static_cast<size_t>(sent);
    }
    return true;
}

bool recv_exact(SOCKET socket, void* output, size_t size, const Deadline& deadline) {
    auto* bytes = static_cast<unsigned char*>(output);
    while (size > 0) {
        if (!wait_socket(socket, false, deadline)) return false;
        const int received = recv(socket, reinterpret_cast<char*>(bytes), static_cast<int>(size), 0);
        if (received == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINTR) continue;
            return false;
        }
        if (received == 0) { WSASetLastError(WSAECONNRESET); return false; }
        bytes += received;
        size -= static_cast<size_t>(received);
    }
    return true;
}

struct Address {
    SOCKADDR_IN6 storage{};
    int length = 0;
};

bool normalize_address(const sockaddr* source, size_t length, Address& address) {
    address = {};
    if (source->sa_family == AF_INET && length >= sizeof(sockaddr_in)) {
        address.length = sizeof(sockaddr_in);
        std::memcpy(&address.storage, source, sizeof(sockaddr_in));
        return true;
    }
    if (source->sa_family == AF_INET6 && length >= sizeof(sockaddr_in6)) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(source);
        if (IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr)) {
            sockaddr_in ipv4{};
            ipv4.sin_family = AF_INET;
            ipv4.sin_port = ipv6->sin6_port;
            std::memcpy(&ipv4.sin_addr, ipv6->sin6_addr.u.Byte + 12, 4);
            address.length = sizeof(ipv4);
            std::memcpy(&address.storage, &ipv4, sizeof(ipv4));
        } else {
            address.length = sizeof(sockaddr_in6);
            address.storage = *ipv6;
        }
        return true;
    }
    WSASetLastError(WSAEAFNOSUPPORT);
    return false;
}

bool utf8_to_wide(const std::string& input, std::wstring& output) {
    if (input.empty() || input.find('\0') != std::string::npos || input.size() > INT_MAX) {
        WSASetLastError(WSAEINVAL);
        return false;
    }
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (size == 0) { WSASetLastError(WSAEINVAL); return false; }
    output.resize(static_cast<size_t>(size));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), output.data(), size) == size;
}

// GetAddrInfoExW can complete after cancellation. The callback owns a reference
// to this heap state, its buffers and one Winsock startup until completion. It
// never owns a forwarding socket or driver reference and never calls the logger.
struct ResolveContext : OVERLAPPED {
    std::atomic<unsigned> references{1};
    std::atomic<int> result_code{WSA_IO_PENDING};
    PADDRINFOEXW result = nullptr;
    HANDLE cancel_handle = nullptr;
    HANDLE completed = nullptr;
    bool owns_winsock = false;
    std::wstring host;
    std::wstring port;
    ADDRINFOEXW hints{};

    ResolveContext() : OVERLAPPED{} {}
    ~ResolveContext() {
        const int error = WSAGetLastError();
        if (result) FreeAddrInfoExW(result);
        if (completed) CloseHandle(completed);
        if (owns_winsock) WSACleanup();
        WSASetLastError(error);
    }
    void release() noexcept {
        if (references.fetch_sub(1, std::memory_order_acq_rel) == 1) delete this;
    }
};

void CALLBACK resolved(DWORD error, DWORD, OVERLAPPED* overlapped) noexcept {
    auto* context = static_cast<ResolveContext*>(overlapped);
    context->result_code.store(static_cast<int>(error), std::memory_order_release);
    SetEvent(context->completed);
    context->release();
}

bool resolve_addresses(const std::string& host, const std::string& port, int type, const Deadline& deadline, std::vector<Address>& addresses) {
    const auto release = [](ResolveContext* context) { context->release(); };
    std::unique_ptr<ResolveContext, decltype(release)> context(new ResolveContext, release);
    if (!utf8_to_wide(host, context->host) || !utf8_to_wide(port, context->port) || deadline.expired()) return false;
    WSADATA data{};
    const int startup = WSAStartup(MAKEWORD(2, 2), &data);
    if (startup != 0) { WSASetLastError(startup); return false; }
    context->owns_winsock = true;
    context->completed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!context->completed) { WSASetLastError(WSA_NOT_ENOUGH_MEMORY); return false; }
    context->hints.ai_family = AF_UNSPEC;
    context->hints.ai_socktype = type;
    context->hints.ai_protocol = type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
    context->hints.ai_flags = AI_NUMERICSERV;
    context->references.fetch_add(1, std::memory_order_relaxed);
    const int result = GetAddrInfoExW(context->host.c_str(), context->port.c_str(), NS_DNS, nullptr,
        &context->hints, &context->result, nullptr, context.get(), resolved, &context->cancel_handle);
    if (result != WSA_IO_PENDING) resolved(static_cast<DWORD>(result), 0, context.get());
    while (WaitForSingleObject(context->completed, 0) != WAIT_OBJECT_0) {
        if (deadline.expired()) {
            const int error = WSAGetLastError();
            GetAddrInfoExCancel(&context->cancel_handle);
            WSASetLastError(error);
            return false;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline.until - Clock::now());
        const DWORD wait = static_cast<DWORD>(std::max<int64_t>(1, std::min(remaining, poll_interval).count()));
        if (WaitForSingleObject(context->completed, wait) == WAIT_FAILED) {
            GetAddrInfoExCancel(&context->cancel_handle);
            WSASetLastError(WSAEINVAL);
            return false;
        }
    }
    if (deadline.expired()) return false;
    const int error = context->result_code.load(std::memory_order_acquire);
    if (error != 0) { WSASetLastError(error); return false; }
    for (auto* item = context->result; item; item = item->ai_next) {
        Address address;
        if (item->ai_addr && normalize_address(item->ai_addr, item->ai_addrlen, address)) addresses.push_back(address);
    }
    if (addresses.empty()) { WSASetLastError(WSAHOST_NOT_FOUND); return false; }
    return true;
}

struct Reply {
    Address address;
    std::string domain;
    unsigned short port = 0; // Network byte order.
};

bool read_reply(SOCKET client, const Deadline& deadline, Reply& reply) {
    unsigned char header[4]{};
    if (!recv_exact(client, header, sizeof(header), deadline)) return false;
    if (header[0] != 5 || header[2] != 0) { WSASetLastError(WSAEINVAL); return false; }
    if (header[1] != 0) {
        const int errors[] = {0, WSAECONNABORTED, WSAEACCES, WSAENETUNREACH, WSAEHOSTUNREACH,
            WSAECONNREFUSED, WSAETIMEDOUT, WSAEOPNOTSUPP, WSAEAFNOSUPPORT};
        WSASetLastError(header[1] < sizeof(errors) / sizeof(errors[0]) ? errors[header[1]] : WSAECONNABORTED);
        return false;
    }
    if (header[3] == 1) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        if (!recv_exact(client, &address.sin_addr, 4, deadline) || !recv_exact(client, &address.sin_port, 2, deadline)) return false;
        reply.port = address.sin_port;
        return normalize_address(reinterpret_cast<sockaddr*>(&address), sizeof(address), reply.address);
    }
    if (header[3] == 4) {
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        if (!recv_exact(client, &address.sin6_addr, 16, deadline) || !recv_exact(client, &address.sin6_port, 2, deadline)) return false;
        reply.port = address.sin6_port;
        return normalize_address(reinterpret_cast<sockaddr*>(&address), sizeof(address), reply.address);
    }
    if (header[3] == 3) {
        unsigned char length = 0;
        if (!recv_exact(client, &length, 1, deadline)) return false;
        if (length == 0) { WSASetLastError(WSAEINVAL); return false; }
        reply.domain.resize(length);
        if (!recv_exact(client, reply.domain.data(), length, deadline) || !recv_exact(client, &reply.port, 2, deadline)) return false;
        if (reply.domain.find('\0') != std::string::npos) { WSASetLastError(WSAEINVAL); return false; }
        return true;
    }
    WSASetLastError(WSAEAFNOSUPPORT);
    return false;
}

Bytes command(unsigned char code, const Address& address) {
    Bytes request{5, code, 0};
    if (address.storage.sin6_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address.storage);
        request.push_back(1);
        const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv4->sin_addr);
        request.insert(request.end(), bytes, bytes + 4);
        bytes = reinterpret_cast<const unsigned char*>(&ipv4->sin_port);
        request.insert(request.end(), bytes, bytes + 2);
    } else {
        request.push_back(4);
        const auto* bytes = reinterpret_cast<const unsigned char*>(&address.storage.sin6_addr);
        request.insert(request.end(), bytes, bytes + 16);
        bytes = reinterpret_cast<const unsigned char*>(&address.storage.sin6_port);
        request.insert(request.end(), bytes, bytes + 2);
    }
    return request;
}
} // namespace

void init_logger(const std::string& path) { g_socks5_logger.openFile(path); }
void close_logger() { g_socks5_logger.close(); }

SOCKET connect(const std::string& host, const std::string& port, const CancelCheck& cancelled) {
    const Deadline deadline{Clock::now() + io_timeout, cancelled};
    std::vector<Address> addresses;
    if (!resolve_addresses(host, port, SOCK_STREAM, deadline, addresses)) {
        failure("Resolve SOCKS5 endpoint");
        return INVALID_SOCKET;
    }
    int last_error = WSAECONNREFUSED;
    for (size_t index = 0; index < addresses.size(); ++index) {
        const auto& address = addresses[index];
        if (deadline.expired()) { last_error = WSAGetLastError(); break; }
        // Do not let an unreachable first IPv6 address consume the full budget
        // before a usable IPv4 fallback can be attempted (or vice versa).
        const auto now = Clock::now();
        const auto remaining = std::max(Clock::duration::zero(), deadline.until - now);
        const Deadline attempt{now + remaining / static_cast<int64_t>(addresses.size() - index), cancelled};
        Socket client{socket(address.storage.sin6_family, SOCK_STREAM, IPPROTO_TCP)};
        if (client.value == INVALID_SOCKET) { last_error = WSAGetLastError(); continue; }
        NonblockingScope nonblocking(client.value);
        if (!nonblocking.active) { last_error = WSAGetLastError(); continue; }
        if (::connect(client.value, reinterpret_cast<const sockaddr*>(&address.storage), address.length) == SOCKET_ERROR) {
            last_error = WSAGetLastError();
            if (last_error != WSAEWOULDBLOCK && last_error != WSAEINPROGRESS) continue;
            if (!wait_socket(client.value, true, attempt)) { last_error = WSAGetLastError(); continue; }
            int error_size = sizeof(last_error);
            if (getsockopt(client.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&last_error), &error_size) != 0) {
                last_error = WSAGetLastError();
                continue;
            }
            if (last_error != 0) continue;
        }
        if (!nonblocking.restore()) { last_error = WSAGetLastError(); continue; }
        if (!proxy_process::register_connection(client.value)) {
            failure("Identify local SOCKS5 server process");
            return INVALID_SOCKET;
        }
        const SOCKET connected = client.value;
        client.value = INVALID_SOCKET;
        return connected;
    }
    failure("Connect to SOCKS5 endpoint", last_error);
    return INVALID_SOCKET;
}

bool handshake(SOCKET client, const std::string& username, const std::string& password, const CancelCheck& cancelled) {
    if (username.empty() != password.empty() || username.size() > 255 || password.size() > 255) {
        return failure("SOCKS5 credential validation", WSAEINVAL);
    }
    const Deadline deadline{Clock::now() + io_timeout, cancelled};
    NonblockingScope nonblocking(client);
    if (!nonblocking.active) return failure("Enable bounded SOCKS5 handshake");
    const unsigned char method = username.empty() ? 0 : 2;
    const unsigned char greeting[] = {5, 1, method};
    unsigned char response[2]{};
    if (!send_all(client, greeting, sizeof(greeting), deadline) || !recv_exact(client, response, sizeof(response), deadline)) return failure("SOCKS5 greeting");
    if (response[0] != 5 || response[1] != method) return failure("SOCKS5 offered-method validation", WSAEACCES);
    if (method == 2) {
        Bytes authentication{1, static_cast<unsigned char>(username.size())};
        authentication.insert(authentication.end(), username.begin(), username.end());
        authentication.push_back(static_cast<unsigned char>(password.size()));
        authentication.insert(authentication.end(), password.begin(), password.end());
        if (!send_all(client, authentication.data(), authentication.size(), deadline) || !recv_exact(client, response, sizeof(response), deadline)) return failure("SOCKS5 authentication");
        if (response[0] != 1 || response[1] != 0) return failure("SOCKS5 authentication response", WSAEACCES);
    }
    return nonblocking.restore() || failure("Restore SOCKS5 socket mode");
}

bool connect_remote(SOCKET client, sockaddr* remote_addr, const CancelCheck& cancelled) {
    if (!remote_addr) return failure("SOCKS5 destination validation", WSAEFAULT);
    Address destination;
    const size_t size = remote_addr->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (!normalize_address(remote_addr, size, destination)) return failure("SOCKS5 destination validation");
    const Deadline deadline{Clock::now() + io_timeout, cancelled};
    NonblockingScope nonblocking(client);
    if (!nonblocking.active) return failure("Enable bounded SOCKS5 CONNECT");
    const auto request = command(1, destination);
    Reply reply;
    if (!send_all(client, request.data(), request.size(), deadline) || !read_reply(client, deadline, reply)) return failure("SOCKS5 CONNECT");
    // Only the declared address and port have been consumed. Any server-first
    // application bytes coalesced with this reply remain queued for tcp_worker.
    return nonblocking.restore() || failure("Restore SOCKS5 socket mode");
}

bool udp_associate(SOCKET client, SOCKADDR_IN6& remote_addr, const CancelCheck& cancelled) {
    remote_addr = {};
    const Deadline deadline{Clock::now() + io_timeout, cancelled};
    sockaddr_in6 peer_storage{};
    int peer_length = sizeof(peer_storage);
    if (getpeername(client, reinterpret_cast<sockaddr*>(&peer_storage), &peer_length) != 0) return failure("SOCKS5 UDP peer lookup");
    Address peer;
    if (!normalize_address(reinterpret_cast<sockaddr*>(&peer_storage), static_cast<size_t>(peer_length), peer)) return failure("SOCKS5 UDP peer validation");
    Address wildcard;
    wildcard.storage.sin6_family = peer.storage.sin6_family;
    NonblockingScope nonblocking(client);
    if (!nonblocking.active) return failure("Enable bounded SOCKS5 UDP ASSOCIATE");
    const auto request = command(3, wildcard);
    Reply reply;
    if (!send_all(client, request.data(), request.size(), deadline) || !read_reply(client, deadline, reply)) return failure("SOCKS5 UDP ASSOCIATE");
    if (reply.port == 0) return failure("SOCKS5 UDP relay port validation", WSAEINVAL);
    if (!reply.domain.empty()) {
        std::vector<Address> addresses;
        if (!resolve_addresses(reply.domain, std::to_string(ntohs(reply.port)), SOCK_DGRAM, deadline, addresses)) return failure("Resolve SOCKS5 UDP relay");
        const auto matching = std::find_if(addresses.begin(), addresses.end(), [&](const Address& address) {
            return address.storage.sin6_family == peer.storage.sin6_family;
        });
        reply.address = matching == addresses.end() ? addresses.front() : *matching;
    }
    const bool unspecified = reply.address.storage.sin6_family == AF_INET
        ? reinterpret_cast<const sockaddr_in*>(&reply.address.storage)->sin_addr.s_addr == INADDR_ANY
        : IN6_IS_ADDR_UNSPECIFIED(&reply.address.storage.sin6_addr) != 0;
    if (unspecified) reply.address = peer;
    // Both sockaddr variants store the network-order port in the same member
    // position, but write through the correct family to keep the contract clear.
    if (reply.address.storage.sin6_family == AF_INET) reinterpret_cast<sockaddr_in*>(&reply.address.storage)->sin_port = reply.port;
    else reply.address.storage.sin6_port = reply.port;
    if (!nonblocking.restore()) return failure("Restore SOCKS5 socket mode");
    remote_addr = reply.address.storage;
    return true;
}
} // namespace rnetch::socks5
