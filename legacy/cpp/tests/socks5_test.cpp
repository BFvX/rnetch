#include "../src/socks5.h"
#include <atomic>
#include <chrono>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
using Bytes = std::vector<unsigned char>;
using Clock = std::chrono::steady_clock;

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct Socket {
    SOCKET value = INVALID_SOCKET;
    explicit Socket(SOCKET socket = INVALID_SOCKET) : value(socket) {}
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
};

void timeout(SOCKET socket, DWORD milliseconds = 2500) {
    check(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&milliseconds), sizeof(milliseconds)) == 0, "Set receive timeout");
    check(setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&milliseconds), sizeof(milliseconds)) == 0, "Set send timeout");
}

Bytes read_bytes(SOCKET socket, size_t size) {
    Bytes bytes(size);
    size_t offset = 0;
    while (offset < size) {
        const int received = recv(socket, reinterpret_cast<char*>(bytes.data() + offset), static_cast<int>(size - offset), 0);
        check(received > 0, "Mock exact read failed");
        offset += static_cast<size_t>(received);
    }
    return bytes;
}

void write_bytes(SOCKET socket, const Bytes& bytes, bool fragmented = false) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        const auto size = fragmented ? size_t{1} : bytes.size() - offset;
        const int sent = send(socket, reinterpret_cast<const char*>(bytes.data() + offset), static_cast<int>(size), 0);
        check(sent > 0, "Mock exact write failed");
        offset += static_cast<size_t>(sent);
        if (fragmented) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

struct MockServer {
    Socket listener;
    std::thread worker;
    std::exception_ptr error;
    unsigned short port = 0;
    int family;

    explicit MockServer(std::function<void(SOCKET)> handler, int requested_family = AF_INET)
        : listener(socket(requested_family, SOCK_STREAM, IPPROTO_TCP)), family(requested_family) {
        check(listener.value != INVALID_SOCKET, "Create loopback listener");
        sockaddr_in6 storage{};
        int size = 0;
        if (family == AF_INET) {
            auto* address = reinterpret_cast<sockaddr_in*>(&storage);
            address->sin_family = AF_INET;
            address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            size = sizeof(sockaddr_in);
        } else {
            storage.sin6_family = AF_INET6;
            storage.sin6_addr = in6addr_loopback;
            size = sizeof(sockaddr_in6);
        }
        check(bind(listener.value, reinterpret_cast<sockaddr*>(&storage), size) == 0, "Bind loopback listener");
        check(getsockname(listener.value, reinterpret_cast<sockaddr*>(&storage), &size) == 0, "Read listener port");
        port = ntohs(storage.sin6_port);
        check(listen(listener.value, 1) == 0, "Listen on loopback");
        worker = std::thread([this, handler = std::move(handler)] {
            try {
                fd_set readable;
                FD_ZERO(&readable);
                FD_SET(listener.value, &readable);
                timeval wait{3, 0};
                check(select(0, &readable, nullptr, nullptr, &wait) == 1, "Mock accept timeout");
                Socket peer(accept(listener.value, nullptr, nullptr));
                check(peer.value != INVALID_SOCKET, "Accept mock client");
                timeout(peer.value);
                const BOOL enabled = TRUE;
                setsockopt(peer.value, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&enabled), sizeof(enabled));
                handler(peer.value);
            } catch (...) { error = std::current_exception(); }
        });
    }

    ~MockServer() { if (worker.joinable()) worker.join(); }
    void finish() {
        if (worker.joinable()) worker.join();
        if (error) std::rethrow_exception(error);
    }
    SOCKET connect_client(const char* override_host = nullptr) const {
        const auto client = rnetch::socks5::connect(override_host ? override_host : family == AF_INET ? "127.0.0.1" : "::1", std::to_string(port));
        check(client != INVALID_SOCKET, "Connect to mock proxy");
        timeout(client);
        return client;
    }
};

Bytes read_command(SOCKET peer, unsigned char command) {
    auto request = read_bytes(peer, 4);
    check(request[0] == 5 && request[1] == command && request[2] == 0, "Unexpected SOCKS5 request header");
    size_t size = 0;
    if (request[3] == 1) size = 6;
    else if (request[3] == 4) size = 18;
    else throw std::runtime_error("Unexpected request address family");
    const auto tail = read_bytes(peer, size);
    request.insert(request.end(), tail.begin(), tail.end());
    return request;
}

void hello(SOCKET peer, unsigned char method = 0) {
    check(read_bytes(peer, 3) == Bytes({5, 1, method}), "Unexpected authentication offer");
    write_bytes(peer, {5, method}, true);
}

sockaddr_in destination() {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(443);
    check(inet_pton(AF_INET, "198.51.100.20", &address.sin_addr) == 1, "Parse test destination");
    return address;
}

Bytes ipv6_reply(const char* host, unsigned short port) {
    Bytes response{5, 0, 0, 4};
    in6_addr address{};
    check(inet_pton(AF_INET6, host, &address) == 1, "Parse IPv6 reply");
    const auto* bytes = reinterpret_cast<const unsigned char*>(&address);
    response.insert(response.end(), bytes, bytes + 16);
    response.push_back(static_cast<unsigned char>(port >> 8));
    response.push_back(static_cast<unsigned char>(port & 255));
    return response;
}

void fragmented_handshake_and_connect() {
    MockServer server([](SOCKET peer) {
        hello(peer);
        read_command(peer, 1);
        write_bytes(peer, {5, 0, 0, 1, 127, 0, 0, 1, 0, 80}, true);
        write_bytes(peer, {'O', 'K'});
    });
    Socket client(server.connect_client("localhost")); // Try both localhost families.
    check(rnetch::socks5::handshake(client.value, "", ""), "Fragmented greeting should succeed");
    auto target = destination();
    check(rnetch::socks5::connect_remote(client.value, reinterpret_cast<sockaddr*>(&target)), "Fragmented CONNECT should succeed");
    check(read_bytes(client.value, 2) == Bytes({'O', 'K'}), "Application bytes missing");
    server.finish();
}

void coalesced_server_first() {
    const std::vector<Bytes> replies = {
        {5, 0, 0, 1, 127, 0, 0, 1, 0, 80},
        ipv6_reply("::1", 80),
        {5, 0, 0, 3, 3, 'f', 'o', 'o', 0, 80}
    };
    const Bytes payload{'s', 'e', 'r', 'v', 'e', 'r', '-', 'f', 'i', 'r', 's', 't', 0, 255};
    for (const auto& reply : replies) {
        MockServer server([reply, payload](SOCKET peer) {
            read_command(peer, 1);
            auto response = reply;
            response.insert(response.end(), payload.begin(), payload.end());
            write_bytes(peer, response); // One write contains the complete reply and payload.
        });
        Socket client(server.connect_client());
        auto target = destination();
        check(rnetch::socks5::connect_remote(client.value, reinterpret_cast<sockaddr*>(&target)), "CONNECT reply should succeed");
        check(read_bytes(client.value, payload.size()) == payload, "SOCKS5 reply parser consumed server-first application bytes");
        server.finish();
    }
}

void rejects_authentication_downgrade_and_bad_versions() {
    const std::vector<Bytes> choices{{5, 0}, {4, 2}, {5, 255}};
    for (const auto& choice : choices) {
        MockServer server([choice](SOCKET peer) {
            check(read_bytes(peer, 3) == Bytes({5, 1, 2}), "Credentials must offer only username/password");
            write_bytes(peer, choice, true);
        });
        Socket client(server.connect_client());
        check(!rnetch::socks5::handshake(client.value, "user", "pass"), "Rejected or downgraded authentication must fail");
        server.finish();
    }
    MockServer unoffered([](SOCKET peer) {
        check(read_bytes(peer, 3) == Bytes({5, 1, 0}), "Anonymous greeting expected");
        write_bytes(peer, {5, 2});
    });
    Socket client(unoffered.connect_client());
    check(!rnetch::socks5::handshake(client.value, "", ""), "Unoffered method must fail");
    unoffered.finish();
    for (const auto& response : std::vector<Bytes>{{1, 1}, {5, 0}}) {
        MockServer rejected([response](SOCKET peer) {
            hello(peer, 2);
            check(read_bytes(peer, 11) == Bytes({1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'}), "Authentication request framing");
            write_bytes(peer, response, true);
        });
        Socket authenticated(rejected.connect_client());
        check(!rnetch::socks5::handshake(authenticated.value, "user", "pass"), "Authentication failure/version must be checked");
        rejected.finish();
    }
}

void validates_credential_lengths_without_overflow() {
    check(!rnetch::socks5::handshake(INVALID_SOCKET, "user", ""), "Partial credentials must fail before network I/O");
    check(!rnetch::socks5::handshake(INVALID_SOCKET, std::string(256, 'u'), "p"), "Oversized username must fail");
    check(!rnetch::socks5::handshake(INVALID_SOCKET, "u", std::string(256, 'p')), "Oversized password must fail");
    MockServer server([](SOCKET peer) {
        hello(peer, 2);
        const auto request = read_bytes(peer, 513);
        check(request[0] == 1 && request[1] == 255 && request[257] == 255, "Maximum authentication field framing");
        for (size_t index = 2; index < 257; ++index) check(request[index] == 'u', "Username was truncated");
        for (size_t index = 258; index < 513; ++index) check(request[index] == 'p', "Password was truncated");
        write_bytes(peer, {1, 0}, true);
    });
    Socket client(server.connect_client());
    check(rnetch::socks5::handshake(client.value, std::string(255, 'u'), std::string(255, 'p')), "255-byte credentials must be safe");
    server.finish();
}

void rejects_truncated_and_invalid_command_replies() {
    std::vector<Bytes> replies{
        {4, 0, 0, 1, 0, 0, 0, 0, 0, 80},
        {5, 0, 1, 1, 0, 0, 0, 0, 0, 80},
        {5, 5, 0, 1, 0, 0, 0, 0, 0, 80},
        {5, 0, 0, 3, 0},
        {5, 0, 0, 2}
    };
    auto ipv6 = ipv6_reply("::1", 80);
    replies.emplace_back(ipv6.begin(), ipv6.begin() + 10);
    replies.emplace_back(ipv6.begin(), ipv6.end() - 1);
    for (const auto& reply : replies) {
        for (const bool udp : {false, true}) {
            MockServer server([reply, udp](SOCKET peer) {
                read_command(peer, udp ? 3 : 1);
                write_bytes(peer, reply);
                shutdown(peer, SD_SEND);
            });
            Socket client(server.connect_client());
            auto target = destination();
            SOCKADDR_IN6 relay{};
            const bool ok = udp ? rnetch::socks5::udp_associate(client.value, relay)
                : rnetch::socks5::connect_remote(client.value, reinterpret_cast<sockaddr*>(&target));
            check(!ok, "Malformed/truncated reply must fail");
            if (udp) check(relay.sin6_family == 0, "A failed UDP reply must not expose a partial address");
            server.finish();
        }
    }
}

void normalizes_mapped_ipv4_destinations() {
    MockServer server([](SOCKET peer) {
        const auto request = read_command(peer, 1);
        check(request == Bytes({5, 1, 0, 1, 198, 51, 100, 20, 1, 187}), "Mapped IPv4 destination must use ATYP IPv4");
        write_bytes(peer, {5, 0, 0, 1, 0, 0, 0, 0, 0, 0});
    });
    Socket client(server.connect_client());
    sockaddr_in6 target{};
    target.sin6_family = AF_INET6;
    target.sin6_port = htons(443);
    check(inet_pton(AF_INET6, "::ffff:198.51.100.20", &target.sin6_addr) == 1, "Parse mapped destination");
    check(rnetch::socks5::connect_remote(client.value, reinterpret_cast<sockaddr*>(&target)), "Mapped destination CONNECT");
    server.finish();
}

void udp_relay_addresses_and_peer_fallback() {
    const std::vector<Bytes> replies{
        {5, 0, 0, 1, 0, 0, 0, 0, 0x7d, 0x7b},
        ipv6_reply("::", 32123),
        ipv6_reply("::ffff:127.0.0.1", 32123),
        {5, 0, 0, 3, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x7d, 0x7b}
    };
    for (const auto& reply : replies) {
        MockServer server([reply](SOCKET peer) { read_command(peer, 3); write_bytes(peer, reply, true); });
        Socket client(server.connect_client());
        SOCKADDR_IN6 relay{};
        check(rnetch::socks5::udp_associate(client.value, relay), "UDP relay reply must parse");
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&relay);
        check(ipv4->sin_family == AF_INET && ipv4->sin_addr.s_addr == htonl(INADDR_LOOPBACK), "UDP relay must resolve/normalize to IPv4 TCP peer");
        check(ntohs(ipv4->sin_port) == 32123, "UDP relay port must survive unspecified-peer substitution");
        server.finish();
    }
    MockServer zero_port([](SOCKET peer) { read_command(peer, 3); write_bytes(peer, {5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); });
    Socket invalid(zero_port.connect_client());
    SOCKADDR_IN6 relay{};
    check(!rnetch::socks5::udp_associate(invalid.value, relay), "Zero UDP relay port must fail");
    zero_port.finish();
    MockServer ipv6([](SOCKET peer) { read_command(peer, 3); write_bytes(peer, ipv6_reply("::1", 32123), true); });
    Socket client(ipv6.connect_client());
    check(rnetch::socks5::udp_associate(client.value, relay), "IPv6 relay reply must parse");
    check(relay.sin6_family == AF_INET6 && IN6_IS_ADDR_LOOPBACK(&relay.sin6_addr) && ntohs(relay.sin6_port) == 32123, "IPv6 relay address mismatch");
    ipv6.finish();
}

void ipv6_proxy_connection() {
    MockServer server([](SOCKET peer) {
        hello(peer);
        const auto request = read_command(peer, 3);
        check(request[3] == 4, "IPv6 control should request IPv6 wildcard UDP association");
        write_bytes(peer, ipv6_reply("::", 32123), true);
    }, AF_INET6);
    Socket client(server.connect_client());
    check(rnetch::socks5::handshake(client.value, "", ""), "IPv6 proxy greeting");
    SOCKADDR_IN6 relay{};
    check(rnetch::socks5::udp_associate(client.value, relay), "IPv6 proxy association");
    check(relay.sin6_family == AF_INET6 && IN6_IS_ADDR_LOOPBACK(&relay.sin6_addr) && ntohs(relay.sin6_port) == 32123, "IPv6 unspecified relay must use TCP peer and relay port");
    server.finish();
}

void cancellation_and_absolute_handshake_deadline() {
    for (const bool cancel_early : {true, false}) {
        MockServer server([](SOCKET peer) {
            read_bytes(peer, 3);
            timeout(peer, 7000);
            char byte = 0;
            check(recv(peer, &byte, 1, 0) == 0, "Client must close after bounded handshake failure");
        });
        {
            Socket client(server.connect_client());
            const auto started = Clock::now();
            const auto cancelled = [=] { return cancel_early && Clock::now() - started >= std::chrono::milliseconds(120); };
            check(!rnetch::socks5::handshake(client.value, "", "", cancelled), "Unresponsive SOCKS5 server must not hang forever");
            const auto elapsed = Clock::now() - started;
            check(WSAGetLastError() == (cancel_early ? WSAEINTR : WSAETIMEDOUT), "Bounded handshake error code");
            check(elapsed < (cancel_early ? std::chrono::seconds(1) : std::chrono::seconds(6)), "Handshake exceeded its deadline");
            if (!cancel_early) check(elapsed >= std::chrono::milliseconds(4500), "Unexpected premature handshake timeout");
        }
        server.finish();
    }
    check(rnetch::socks5::connect("127.0.0.1", "1", [] { return true; }) == INVALID_SOCKET && WSAGetLastError() == WSAEINTR, "Already-cancelled connect must not perform network I/O");
}
} // namespace

int main() {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
    const std::vector<std::pair<const char*, std::function<void()>>> tests{
        {"fragmented handshake and CONNECT", fragmented_handshake_and_connect},
        {"coalesced server-first payload for all reply address types", coalesced_server_first},
        {"authentication rejection and version validation", rejects_authentication_downgrade_and_bad_versions},
        {"credential limits and maximum 513-byte authentication", validates_credential_lengths_without_overflow},
        {"truncated IPv6 and invalid command replies", rejects_truncated_and_invalid_command_replies},
        {"mapped IPv4 destination normalization", normalizes_mapped_ipv4_destinations},
        {"UDP relay families, DNS, and unspecified peer fallback", udp_relay_addresses_and_peer_fallback},
        {"IPv6 loopback proxy connection", ipv6_proxy_connection},
        {"cancellation and five-second absolute handshake deadline", cancellation_and_absolute_handshake_deadline}
    };
    int failed = 0;
    for (const auto& test : tests) {
        try { test.second(); std::cout << "PASS: " << test.first << '\n'; }
        catch (const std::exception& error) { ++failed; std::cerr << "FAIL: " << test.first << ": " << error.what() << '\n'; }
    }
    WSACleanup();
    std::cout << tests.size() - static_cast<size_t>(failed) << '/' << tests.size() << " local SOCKS5 tests passed (no driver loaded)\n";
    return failed == 0 ? 0 : 1;
}
