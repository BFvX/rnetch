#include "../src/tcp_relay.h"
#include <array>
#include <chrono>
#include <cstring>
#include <exception>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using rnetch::utils::SocketHandle;
namespace relay = rnetch::tcp_relay;
using Clock = std::chrono::steady_clock;

void require(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

void check_socket(int value, const char* message) {
    if (value == SOCKET_ERROR) {
        throw std::runtime_error(std::string(message) + " (Winsock "
            + std::to_string(WSAGetLastError()) + ")");
    }
}

struct Winsock {
    Winsock() {
        WSADATA data{};
        require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Initialize test Winsock");
    }
    ~Winsock() { WSACleanup(); }
};

sockaddr_storage address(int family, const char* ip, unsigned short port = 0) {
    sockaddr_storage result{};
    if (family == AF_INET) {
        sockaddr_in value{};
        value.sin_family = AF_INET;
        value.sin_port = htons(port);
        require(InetPtonA(AF_INET, ip, &value.sin_addr) == 1, "Parse test IPv4");
        std::memcpy(&result, &value, sizeof(value));
    } else {
        sockaddr_in6 value{};
        value.sin6_family = AF_INET6;
        value.sin6_port = htons(port);
        require(InetPtonA(AF_INET6, ip, &value.sin6_addr) == 1, "Parse test IPv6");
        std::memcpy(&result, &value, sizeof(value));
    }
    return result;
}

unsigned short port(const sockaddr_storage& value) {
    if (value.ss_family == AF_INET) {
        sockaddr_in parsed{};
        std::memcpy(&parsed, &value, sizeof(parsed));
        return ntohs(parsed.sin_port);
    }
    sockaddr_in6 parsed{};
    std::memcpy(&parsed, &value, sizeof(parsed));
    return ntohs(parsed.sin6_port);
}

sockaddr_storage local_address(SOCKET socket) {
    sockaddr_storage result{};
    int length = sizeof(result);
    check_socket(getsockname(socket, reinterpret_cast<sockaddr*>(&result), &length),
        "Read test socket local address");
    return result;
}

std::string address_string(const sockaddr_storage& target) {
    char ip[INET6_ADDRSTRLEN]{};
    if (target.ss_family == AF_INET) {
        sockaddr_in value{};
        std::memcpy(&value, &target, sizeof(value));
        require(InetNtopA(AF_INET, &value.sin_addr, ip, sizeof(ip)) != nullptr,
            "Format IPv4 test destination");
        return std::string(ip) + ":" + std::to_string(port(target));
    }
    sockaddr_in6 value{};
    std::memcpy(&value, &target, sizeof(value));
    require(InetNtopA(AF_INET6, &value.sin6_addr, ip, sizeof(ip)) != nullptr,
        "Format IPv6 test destination");
    return "[" + std::string(ip) + "]:" + std::to_string(port(target));
}

void blocking_with_timeout(SOCKET socket) {
    u_long disabled = 0;
    check_socket(ioctlsocket(socket, FIONBIO, &disabled), "Set test socket blocking");
    DWORD timeout = 2000;
    for (int option : {SO_RCVTIMEO, SO_SNDTIMEO}) {
        check_socket(setsockopt(socket, SOL_SOCKET, option,
            reinterpret_cast<const char*>(&timeout), sizeof(timeout)), "Set test timeout");
    }
}

SocketHandle connect_to(const sockaddr_storage& target) {
    SocketHandle socket(WSASocketW(target.ss_family, SOCK_STREAM, IPPROTO_TCP,
        nullptr, 0, WSA_FLAG_OVERLAPPED));
    require(socket.get() != INVALID_SOCKET, "Create test client");
    if (target.ss_family == AF_INET6) {
        DWORD v6_only = 0;
        check_socket(setsockopt(socket.get(), IPPROTO_IPV6, IPV6_V6ONLY,
            reinterpret_cast<const char*>(&v6_only), sizeof(v6_only)), "Set dual-stack test client");
    }
    blocking_with_timeout(socket.get());
    const std::string operation = "Connect test client to " + address_string(target);
    check_socket(connect(socket.get(), reinterpret_cast<const sockaddr*>(&target),
        target.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)), operation.c_str());
    return socket;
}

struct Pair {
    SocketHandle client;
    SocketHandle server;
};

Pair pair() {
    auto listener = relay::listen(address(AF_INET, "127.0.0.1"));
    auto client = connect_to(listener.address);
    auto server = relay::accept(listener.socket.get(), local_address(client.get()), [] { return false; });
    require(server.get() != INVALID_SOCKET, "Accept test socket pair");
    blocking_with_timeout(server.get());
    return {std::move(client), std::move(server)};
}

void send_all(SOCKET socket, const std::vector<char>& bytes) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
        int count = send(socket, bytes.data() + sent, static_cast<int>(bytes.size() - sent), 0);
        check_socket(count, "Send test bytes");
        require(count > 0, "Test send made no progress");
        sent += static_cast<std::size_t>(count);
    }
}

std::vector<char> receive_exact(SOCKET socket, std::size_t size) {
    std::vector<char> bytes(size);
    std::size_t received = 0;
    while (received < bytes.size()) {
        int count = recv(socket, bytes.data() + received, static_cast<int>(bytes.size() - received), 0);
        check_socket(count, "Receive exact test bytes");
        require(count > 0, "Unexpected test EOF");
        received += static_cast<std::size_t>(count);
    }
    return bytes;
}

std::vector<char> receive_to_eof(SOCKET socket) {
    std::vector<char> bytes;
    std::array<char, 16384> buffer{};
    for (;;) {
        int count = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
        check_socket(count, "Receive test data through EOF");
        if (count == 0) {
            return bytes;
        }
        bytes.insert(bytes.end(), buffer.data(), buffer.data() + count);
    }
}

class RelayWorker {
public:
    std::atomic<unsigned long long> up{0};
    std::atomic<unsigned long long> down{0};

    RelayWorker(SOCKET application, SOCKET proxy)
        : worker_([this, application, proxy] {
            try {
                const auto deadline = Clock::now() + std::chrono::seconds(5);
                relay::relay(application, proxy, [this, deadline] {
                    return stopped_.load(std::memory_order_acquire) || Clock::now() >= deadline;
                }, up, down);
            } catch (...) {
                error_ = std::current_exception();
            }
        }) {}

    ~RelayWorker() {
        stopped_.store(true, std::memory_order_release);
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    void finish(bool cancel = false) {
        if (cancel) {
            stopped_.store(true, std::memory_order_release);
        }
        worker_.join();
        if (error_) {
            std::rethrow_exception(error_);
        }
    }

private:
    std::atomic_bool stopped_{false};
    std::exception_ptr error_;
    std::thread worker_;
};

void listener_family(const sockaddr_storage& source) {
    auto listener = relay::listen(source);
    require(listener.address.ss_family == source.ss_family, "Listener must preserve address family");
    require(port(listener.address) != 0, "Listener must receive an ephemeral port");
    auto client = connect_to(listener.address);
    auto peer = local_address(client.get());
    auto accepted = relay::accept(listener.socket.get(), peer, [] { return false; });
    require(accepted.get() != INVALID_SOCKET, "Accept client in original address family");
    sockaddr_storage accepted_address = local_address(accepted.get());
    require(accepted_address.ss_family == source.ss_family, "Accepted socket must preserve family");
    blocking_with_timeout(accepted.get());
    const std::vector<char> payload{'m', 'a', 'p'};
    send_all(client.get(), payload);
    require(receive_exact(accepted.get(), payload.size()) == payload, "Listener must pass payload bytes");
}

void listener_ipv4() {
    listener_family(address(AF_INET, "0.0.0.0", 12345));
}

void listener_ipv6() {
    listener_family(address(AF_INET6, "::", 12345));
}

void listener_mapped_ipv6() {
    listener_family(address(AF_INET6, "::ffff:0.0.0.0", 12345));
}

void listener_preserves_explicit_ip() {
    for (const auto& source : {address(AF_INET, "127.0.0.2"), address(AF_INET6, "::ffff:127.0.0.2")}) {
        auto listener = relay::listen(source);
        auto expected = source;
        if (source.ss_family == AF_INET) {
            sockaddr_in value{};
            std::memcpy(&value, &source, sizeof(value));
            value.sin_port = htons(port(listener.address));
            std::memcpy(&expected, &value, sizeof(value));
        } else {
            sockaddr_in6 value{};
            std::memcpy(&value, &source, sizeof(value));
            value.sin6_port = htons(port(listener.address));
            std::memcpy(&expected, &value, sizeof(value));
        }
        require(std::memcmp(&listener.address, &expected,
            source.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)) == 0,
            "Listener must bind original explicit local IP");
    }
}

void accepts_only_expected_source_port() {
    auto listener = relay::listen(address(AF_INET, "127.0.0.1"));
    auto other = connect_to(listener.address);
    auto expected = connect_to(listener.address);
    auto accepted = relay::accept(listener.socket.get(), local_address(expected.get()), [] { return false; });
    require(accepted.get() != INVALID_SOCKET, "Accept expected client after rejecting wrong source port");
    sockaddr_storage peer{};
    int length = sizeof(peer);
    check_socket(getpeername(accepted.get(), reinterpret_cast<sockaddr*>(&peer), &length), "Read accepted peer");
    require(port(peer) == port(local_address(expected.get())), "Accepted source port must match");
    char byte = 0;
    int count = recv(other.get(), &byte, 1, 0);
    require(count == 0 || (count == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET),
        "Rejected client must be disconnected");
}

void accepts_wildcard_ip_and_mapped_source() {
    auto listener = relay::listen(address(AF_INET6, "::ffff:0.0.0.0"));
    auto destination = address(AF_INET, "127.0.0.1", port(listener.address));
    auto client = connect_to(destination);
    auto expected = address(AF_INET6, "::ffff:0.0.0.0", port(local_address(client.get())));
    auto accepted = relay::accept(listener.socket.get(), expected, [] { return false; });
    require(accepted.get() != INVALID_SOCKET, "Accept normalized IPv4 peer with mapped wildcard expectation");
}

void accept_cancels() {
    auto listener = relay::listen(address(AF_INET, "0.0.0.0"));
    const auto start = Clock::now();
    auto accepted = relay::accept(listener.socket.get(), address(AF_INET, "0.0.0.0"), [&] {
        return Clock::now() - start >= std::chrono::milliseconds(20);
    });
    require(accepted.get() == INVALID_SOCKET, "Cancelled accept must return an empty socket");
    require(Clock::now() - start < std::chrono::seconds(1), "Accept cancellation must be prompt");
}

void server_first_and_client_half_close() {
    auto local = pair();
    auto remote = pair();
    RelayWorker worker(local.server.get(), remote.client.get());
    std::vector<char> upload(200000);
    std::vector<char> download(180000);
    for (std::size_t i = 0; i < upload.size(); ++i) {
        upload[i] = static_cast<char>(i % 251);
    }
    for (std::size_t i = 0; i < download.size(); ++i) {
        download[i] = static_cast<char>(i % 239);
    }
    const std::vector<char> greeting{'r', 'e', 'a', 'd', 'y'};
    auto server = std::async(std::launch::async, [&] {
        send_all(remote.server.get(), greeting);
        require(receive_to_eof(remote.server.get()) == upload, "Preserve upload payload and client half-close");
        send_all(remote.server.get(), download);
        check_socket(shutdown(remote.server.get(), SD_SEND), "Half-close test server");
    });
    require(receive_exact(local.client.get(), greeting.size()) == greeting, "Preserve server-first bytes");
    send_all(local.client.get(), upload);
    check_socket(shutdown(local.client.get(), SD_SEND), "Half-close test client");
    require(receive_to_eof(local.client.get()) == download, "Preserve download payload after client EOF");
    server.get();
    worker.finish();
    require(worker.up.load() == upload.size(), "Count actual relayed upload bytes");
    require(worker.down.load() == greeting.size() + download.size(), "Count actual relayed download bytes");
}

void server_half_close_keeps_upload_open() {
    auto local = pair();
    auto remote = pair();
    RelayWorker worker(local.server.get(), remote.client.get());
    const std::vector<char> response{'d', 'o', 'n', 'e'};
    const std::vector<char> request{'s', 't', 'i', 'l', 'l', ' ', 's', 'e', 'n', 'd', 'i', 'n', 'g'};
    send_all(remote.server.get(), response);
    check_socket(shutdown(remote.server.get(), SD_SEND), "Half-close server first");
    require(receive_to_eof(local.client.get()) == response, "Forward server half-close");
    send_all(local.client.get(), request);
    check_socket(shutdown(local.client.get(), SD_SEND), "Half-close remaining upload");
    require(receive_to_eof(remote.server.get()) == request, "Keep upload alive after server half-close");
    worker.finish();
}

void cancels_idle_and_backpressured_relay() {
    for (bool backpressure : {false, true}) {
        auto local = pair();
        auto remote = pair();
        if (backpressure) {
            int size = 1024;
            check_socket(setsockopt(remote.client.get(), SOL_SOCKET, SO_SNDBUF,
                reinterpret_cast<const char*>(&size), sizeof(size)), "Limit proxy send buffer");
            check_socket(setsockopt(remote.server.get(), SOL_SOCKET, SO_RCVBUF,
                reinterpret_cast<const char*>(&size), sizeof(size)), "Limit server receive buffer");
        }
        RelayWorker worker(local.server.get(), remote.client.get());
        if (backpressure) {
            u_long enabled = 1;
            check_socket(ioctlsocket(local.client.get(), FIONBIO, &enabled), "Make stress client nonblocking");
            const std::array<char, 32768> bytes{};
            for (int i = 0; i < 512; ++i) {
                int count = send(local.client.get(), bytes.data(), static_cast<int>(bytes.size()), 0);
                if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
                    break;
                }
                check_socket(count, "Write backpressure test data");
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        const auto start = Clock::now();
        worker.finish(true);
        require(Clock::now() - start < std::chrono::seconds(1), "Relay cancellation must remain prompt");
    }
}

bool run_test(const char* name, void (*test)()) {
    std::cout << "[ RUN      ] " << name << std::endl;
    try {
        test();
    } catch (const std::exception& error) {
        std::cerr << "[   FAILED ] " << name << ": " << error.what() << std::endl;
        return false;
    }
    std::cout << "[       OK ] " << name << std::endl;
    return true;
}

} // namespace

int main() {
    try {
        Winsock winsock;
        const std::pair<const char*, void (*)()> cases[] = {
            {"listener_ipv4", listener_ipv4},
            {"listener_ipv6", listener_ipv6},
            {"listener_mapped_ipv6", listener_mapped_ipv6},
            {"listener_preserves_explicit_ip", listener_preserves_explicit_ip},
            {"accepts_only_expected_source_port", accepts_only_expected_source_port},
            {"accepts_wildcard_ip_and_mapped_source", accepts_wildcard_ip_and_mapped_source},
            {"accept_cancels", accept_cancels},
            {"server_first_and_client_half_close", server_first_and_client_half_close},
            {"server_half_close_keeps_upload_open", server_half_close_keeps_upload_open},
            {"cancels_idle_and_backpressured_relay", cancels_idle_and_backpressured_relay},
        };
        size_t passed = 0;
        for (const auto& test : cases) {
            if (run_test(test.first, test.second)) ++passed;
        }
        std::cout << passed << "/" << std::size(cases)
            << " TCP relay tests passed (loopback only; no driver loaded)\n";
        return passed == std::size(cases) ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "TCP relay test failed: " << error.what() << '\n';
        return 1;
    }
}
