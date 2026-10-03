// Standalone driver-free regression. Compile this TU with socks5.cpp and
// ws2_32.lib; the implementation is included to test its private framing/cache.
#define _C_API
#define _NFAPI_STATIC_LIB
#include "../src/udp_relay.cpp"
#include <exception>
#include <iostream>

namespace udp = rnetch::udp_relay;
namespace {
struct Received {
    ENDPOINT_ID id;
    udp::Address source;
    std::vector<char> payload;
    std::vector<char> options;
};
std::mutex results_mutex;
std::vector<Received> received_packets;
size_t bypassed_packets = 0;
std::atomic_size_t queue_warnings{0};

void expect(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

template <class Predicate>
void wait_for(Predicate ready, const char* message) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!ready()) {
        expect(std::chrono::steady_clock::now() < until, message);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

udp::Address address(const char* ip, unsigned short port, bool v6 = false) {
    udp::Address result;
    if (v6) {
        auto& peer = reinterpret_cast<sockaddr_in6&>(result.value);
        peer.sin6_family = AF_INET6;
        peer.sin6_port = htons(port);
        expect(inet_pton(AF_INET6, ip, &peer.sin6_addr) == 1, "Invalid test IPv6 address");
        result.length = sizeof(peer);
    } else {
        auto& peer = reinterpret_cast<sockaddr_in&>(result.value);
        peer.sin_family = AF_INET;
        peer.sin_port = htons(port);
        expect(inet_pton(AF_INET, ip, &peer.sin_addr) == 1, "Invalid test IPv4 address");
        result.length = sizeof(peer);
    }
    return result;
}

std::vector<char> options(char tag, size_t size = 1) {
    std::vector<char> result(std::max(offsetof(NF_UDP_OPTIONS, options) + size, sizeof(NF_UDP_OPTIONS)), tag);
    auto* value = reinterpret_cast<PNF_UDP_OPTIONS>(result.data());
    value->flags = static_cast<unsigned char>(tag);
    value->optionsLength = static_cast<long>(size);
    return result;
}

const unsigned char* raw(const udp::Address& value) {
    return reinterpret_cast<const unsigned char*>(&value.value);
}

void framing_and_routes() {
    const auto v4 = address("8.8.8.8", 53);
    const auto mapped = address("::ffff:8.8.8.8", 53, true);
    const auto v6 = address("2001:4860:4860::8888", 53, true);
    udp::Packet packet{mapped, std::vector<char>(12000, 'q'), {}};
    const auto frame = udp::encode(packet);
    expect(frame.size() == 12010 && frame[3] == 1, "Mapped destination must use IPv4 SOCKS framing");
    udp::Address decoded;
    size_t offset = 0;
    expect(udp::decode(frame.data(), frame.size(), decoded, offset), "Valid large UDP frame rejected");
    expect(udp::same_peer(decoded, v4) && offset == 10, "IPv4 UDP frame address mismatch");
    for (size_t byte = 0; byte < 3; ++byte) {
        auto invalid = frame;
        invalid[byte] = 1;
        expect(!udp::decode(invalid.data(), invalid.size(), decoded, offset), "RSV/FRAG must be zero");
    }
    for (size_t length = 0; length < 10; ++length) {
        expect(!udp::decode(frame.data(), length, decoded, offset), "Truncated UDP frame accepted");
    }
    packet.destination = v6;
    packet.payload.clear();
    const auto empty = udp::encode(packet);
    expect(udp::decode(empty.data(), empty.size(), decoded, offset) && offset == 22 &&
           udp::same_peer(decoded, v6), "IPv6/empty datagram framing failed");

    auto original = options('a', 4);
    std::vector<char> copy;
    expect(udp::copy_options(reinterpret_cast<PNF_UDP_OPTIONS>(original.data()), copy), "Valid options rejected");
    original.back() = 'x';
    expect(copy.back() == 'a', "Options were not deep-copied");
    auto* header = reinterpret_cast<PNF_UDP_OPTIONS>(original.data());
    header->optionsLength = -1;
    expect(!udp::copy_options(header, copy), "Negative options length accepted");
    header->optionsLength = static_cast<long>(udp::max_options_bytes + 1);
    expect(!udp::copy_options(header, copy), "Oversized options length accepted");

    udp::Routes routes;
    routes.remember(mapped, options('a'));
    routes.remember(v6, options('b'));
    auto source = v4;
    auto* route = routes.reply(source);
    expect(route && route->options.back() == 'a' && source.value.ss_family == AF_INET6,
           "Reply must use its own route options and restore mapped IPv6");
    expect(udp::same_peer(source, v4), "Mapped reply address changed");
    routes.remember(v4, options('c'));
    expect(routes.entries.size() == 2, "Mapped and IPv4 route keys must deduplicate");
    for (unsigned short port = 1; port < 300; ++port) routes.remember(address("1.1.1.1", port), options('d'));
    expect(routes.entries.size() == udp::max_routes, "Route count is not bounded");
    routes.remember(address("9.9.9.9", 53), options('e', udp::max_options_bytes - 8));
    expect(routes.bytes <= udp::max_options_bytes && routes.entries.size() == 1, "Route byte budget is not bounded");
}

void timeout(SOCKET socket) {
    const DWORD milliseconds = 5000;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&milliseconds), sizeof(milliseconds));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&milliseconds), sizeof(milliseconds));
}

void read_exact(SOCKET socket, char* data, size_t length) {
    while (length) {
        const int count = recv(socket, data, static_cast<int>(length), 0);
        expect(count > 0, "Mock SOCKS control read failed");
        data += count;
        length -= static_cast<size_t>(count);
    }
}

void write_exact(SOCKET socket, const char* data, size_t length) {
    while (length) {
        const int count = ::send(socket, data, static_cast<int>(length), 0);
        expect(count > 0, "Mock SOCKS control write failed");
        data += count;
        length -= static_cast<size_t>(count);
    }
}

SOCKET bound_socket(int type) {
    const SOCKET result = ::socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
    expect(result != INVALID_SOCKET, "Cannot create loopback test socket");
    const auto local = address("127.0.0.1", 0);
    if (bind(result, reinterpret_cast<const sockaddr*>(&local.value), local.length) != 0) {
        closesocket(result);
        throw std::runtime_error("Cannot bind loopback test socket");
    }
    timeout(result);
    return result;
}

unsigned short port_of(SOCKET socket) {
    sockaddr_in local{};
    int length = sizeof(local);
    expect(getsockname(socket, reinterpret_cast<sockaddr*>(&local), &length) == 0, "Cannot read loopback test port");
    return ntohs(local.sin_port);
}

rnetch::utils::SocketHandle handshake(SOCKET listener, unsigned short udp_port) {
    fd_set reads;
    FD_ZERO(&reads);
    FD_SET(listener, &reads);
    timeval wait{5, 0};
    expect(select(0, &reads, nullptr, nullptr, &wait) == 1, "SOCKS worker did not reconnect");
    rnetch::utils::SocketHandle control(accept(listener, nullptr, nullptr));
    expect(control.get() != INVALID_SOCKET, "Cannot accept SOCKS test connection");
    timeout(control.get());
    char hello[3];
    read_exact(control.get(), hello, sizeof(hello));
    expect(hello[0] == 5 && hello[1] == 1 && hello[2] == 0, "Unexpected SOCKS greeting");
    const char reply[2] = {5, 0};
    write_exact(control.get(), reply, sizeof(reply));
    char request[10];
    read_exact(control.get(), request, sizeof(request));
    expect(request[0] == 5 && request[1] == 3 && request[2] == 0 && request[3] == 1,
           "Expected actual UDP ASSOCIATE request");
    char associated[10] = {5, 0, 0, 1, 127, 0, 0, 1, 0, 0};
    const auto network_port = htons(udp_port);
    std::memcpy(associated + 8, &network_port, 2);
    write_exact(control.get(), associated, sizeof(associated));
    return control;
}

struct WirePacket {
    std::vector<char> bytes;
    sockaddr_storage sender{};
    int sender_length = sizeof(sender);
};

WirePacket read_datagram(SOCKET socket) {
    WirePacket result;
    result.bytes.resize(65535);
    const int count = recvfrom(socket, result.bytes.data(), static_cast<int>(result.bytes.size()), 0,
                               reinterpret_cast<sockaddr*>(&result.sender), &result.sender_length);
    expect(count >= 0, "Mock UDP relay did not receive a datagram");
    result.bytes.resize(static_cast<size_t>(count));
    return result;
}

void echo(SOCKET socket, const WirePacket& packet) {
    expect(sendto(socket, packet.bytes.data(), static_cast<int>(packet.bytes.size()), 0,
                  reinterpret_cast<const sockaddr*>(&packet.sender), packet.sender_length) ==
               static_cast<int>(packet.bytes.size()), "Mock UDP relay echo failed");
}

void integration() {
    rnetch::utils::SocketHandle listener(bound_socket(SOCK_STREAM));
    rnetch::utils::SocketHandle relay(bound_socket(SOCK_DGRAM));
    expect(listen(listener.get(), 4) == 0, "Cannot listen for mock SOCKS connections");
    std::atomic_bool stopping{false};
    std::atomic<unsigned long long> up{0}, down{0};
    udp::configure("127.0.0.1", std::to_string(port_of(listener.get())), "", "", stopping, up, down);
    std::exception_ptr remote_error;
    std::atomic_bool remote_done{false};
    std::thread remote([&] {
        try {
            auto control = handshake(listener.get(), port_of(relay.get()));
            const auto first = read_datagram(relay.get());
            const auto second = read_datagram(relay.get());
            expect(first.bytes.size() == 12010 && first.bytes[3] == 1, "Large mapped UDP packet was truncated");
            expect(second.bytes.size() == 11, "Second UDP packet length changed");
            // Reply to the first peer after the second send; using one global
            // options buffer would incorrectly attach the second peer's data.
            echo(relay.get(), first);
            echo(relay.get(), second);
            wait_for([&] {
                std::lock_guard<std::mutex> guard(results_mutex);
                return received_packets.size() >= 2 || stopping.load();
            }, "First UDP replies were not consumed");
            control.close();
            auto reconnected = handshake(listener.get(), port_of(relay.get()));
            const auto retry = read_datagram(relay.get());
            expect(retry.bytes.size() == 15, "Retry datagram was not forwarded");
            echo(relay.get(), retry);
            remote_done = true;
            while (!stopping.load()) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } catch (...) {
            remote_error = std::current_exception();
            remote_done = true;
        }
    });
    try {
        NF_UDP_CONN_INFO info{};
        info.ip_family = AF_INET6;
        udp::created(42, &info);
        const auto mapped = address("::ffff:8.8.8.8", 53, true);
        const auto second = address("9.9.9.9", 443);
        auto first_options = options('a', 4);
        auto second_options = options('b', 4);
        const std::vector<char> large(12000, 'q');
        udp::send(42, raw(mapped), large.data(), static_cast<int>(large.size()),
                  reinterpret_cast<PNF_UDP_OPTIONS>(first_options.data()));
        std::fill(first_options.begin() + 8, first_options.end(), 'x');
        udp::send(42, raw(second), "z", 1, reinterpret_cast<PNF_UDP_OPTIONS>(second_options.data()));
        wait_for([&] {
            std::lock_guard<std::mutex> guard(results_mutex);
            return received_packets.size() >= 2 || remote_done.load();
        }, "No UDP injected reply");
        {
            std::lock_guard<std::mutex> guard(results_mutex);
            expect(received_packets.size() == 2, "SOCKS UDP relay failed before replies");
            expect(received_packets[0].source.value.ss_family == AF_INET6 &&
                   received_packets[0].payload == large && received_packets[0].options.back() == 'a',
                   "Mapped family, large payload or per-peer options corrupted");
            expect(received_packets[1].options.back() == 'b', "Second peer options corrupted");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        udp::send(42, raw(second), "retry", 5, reinterpret_cast<PNF_UDP_OPTIONS>(second_options.data()));
        wait_for([&] {
            std::lock_guard<std::mutex> guard(results_mutex);
            return received_packets.size() >= 3 || remote_done.load();
        }, "UDP did not recover after control close");
        // Give the worker time to consume a reply queued immediately before the
        // test proxy's successful completion/close notification.
        wait_for([&] {
            std::lock_guard<std::mutex> guard(results_mutex);
            return received_packets.size() >= 3;
        }, "Recovered UDP association did not inject reply");
        wait_for([&] { return up.load() == 12006 && down.load() == 12006; }, "UDP payload counters incorrect");

        const auto private_mapped = address("::ffff:127.0.0.1", 1000, true);
        udp::send(42, raw(private_mapped), "local", 5, nullptr);
        udp::send(99, raw(second), "unknown", 7, nullptr);
        expect(bypassed_packets == 2, "Private mapped and unknown endpoint traffic must bypass");
        const auto before = std::chrono::steady_clock::now();
        udp::closed(42);
        expect(std::chrono::steady_clock::now() - before < std::chrono::milliseconds(100),
               "SDK close callback waited for a worker");
        stopping = true;
        udp::stop();
        expect(std::chrono::steady_clock::now() - before < std::chrono::milliseconds(500),
               "UDP worker shutdown did not cancel promptly");
        udp::reap();
    } catch (...) {
        stopping = true;
        udp::stop();
        remote.join();
        if (remote_error) std::rethrow_exception(remote_error);
        throw;
    }
    remote.join();
    if (remote_error) std::rethrow_exception(remote_error);
}

void cancellation_and_queue_bounds() {
    rnetch::utils::SocketHandle listener(bound_socket(SOCK_STREAM));
    expect(listen(listener.get(), 4) == 0, "Cannot listen for cancellation test");
    std::atomic_bool stopping{false};
    std::atomic<unsigned long long> up{0}, down{0};
    const auto previous_warnings = queue_warnings.load();
    udp::configure("127.0.0.1", std::to_string(port_of(listener.get())), "", "", stopping, up, down);
    std::atomic_int handshakes{0};
    std::exception_ptr remote_error;
    std::atomic_bool remote_done{false};
    std::thread remote([&] {
        try {
            std::vector<rnetch::utils::SocketHandle> controls;
            for (int index = 0; index < 2; ++index) {
                fd_set reads;
                FD_ZERO(&reads);
                FD_SET(listener.get(), &reads);
                timeval limit{5, 0};
                expect(select(0, &reads, nullptr, nullptr, &limit) == 1, "No cancellation test client");
                controls.emplace_back(accept(listener.get(), nullptr, nullptr));
                expect(controls.back().get() != INVALID_SOCKET, "Cannot accept cancellation client");
                timeout(controls.back().get());
                char hello[3];
                read_exact(controls.back().get(), hello, sizeof(hello));
                ++handshakes;
            }
            // Deliberately withhold the greeting reply. Both SOCKS handshakes
            // must end because of cancellation, rather than their 5s deadline.
            for (const auto& control : controls) {
                char ignored;
                expect(recv(control.get(), &ignored, 1, 0) == 0, "Cancelled control was not closed");
            }
        } catch (...) { remote_error = std::current_exception(); }
        remote_done = true;
    });
    try {
        NF_UDP_CONN_INFO info{};
        info.ip_family = AF_INET;
        const auto destination = address("8.8.8.8", 53);
        udp::created(7, &info);
        udp::send(7, raw(destination), "x", 1, nullptr);
        wait_for([&] { return handshakes.load() >= 1 || remote_done.load(); }, "First handshake did not start");
        for (int count = 0; count < 300; ++count) udp::send(7, raw(destination), "x", 1, nullptr);
        {
            const auto runtime = udp::current();
            std::lock_guard<std::mutex> guard(runtime->mutex);
            const auto session = runtime->sessions.at(7);
            std::lock_guard<std::mutex> queue_guard(session->mutex);
            expect(session->packets.size() == udp::max_packets, "UDP callback queue exceeds 256 packets");
        }
        udp::created(8, &info);
        udp::send(8, raw(destination), "x", 1, nullptr);
        wait_for([&] { return handshakes.load() >= 2 || remote_done.load(); }, "Second handshake did not start");
        auto large_options = options('m', 128 * 1024);
        const std::vector<char> large_packet(65500, 'p');
        for (int count = 0; count < 100; ++count) {
            udp::send(8, raw(destination), large_packet.data(), static_cast<int>(large_packet.size()),
                      reinterpret_cast<PNF_UDP_OPTIONS>(large_options.data()));
        }
        {
            const auto runtime = udp::current();
            std::lock_guard<std::mutex> guard(runtime->mutex);
            const auto session = runtime->sessions.at(8);
            std::lock_guard<std::mutex> queue_guard(session->mutex);
            expect(session->queued_bytes <= udp::max_queue_bytes && session->packets.size() < 100,
                   "UDP callback queue exceeds byte budget");
            expect(session->queued_bytes + large_packet.size() + large_options.size() > udp::max_queue_bytes,
                   "Queue did not reach the expected byte limit");
        }
        const auto start = std::chrono::steady_clock::now();
        udp::closed(7);
        udp::closed(8);
        expect(std::chrono::steady_clock::now() - start < std::chrono::milliseconds(100),
               "Close callback blocked on SOCKS handshake");
        stopping = true;
        udp::stop();
        expect(std::chrono::steady_clock::now() - start < std::chrono::milliseconds(500),
               "Cancelled UDP handshake waited for its deadline");
        expect(queue_warnings.load() == previous_warnings + 2,
               "Queue overflow must warn only once for each endpoint");
    } catch (...) {
        stopping = true;
        udp::stop();
        remote.join();
        if (remote_error) std::rethrow_exception(remote_error);
        throw;
    }
    remote.join();
    if (remote_error) std::rethrow_exception(remote_error);
}
} // namespace

bool is_private_or_local_address(const sockaddr_storage& value) {
    if (value.ss_family == AF_INET) {
        return (ntohl(reinterpret_cast<const sockaddr_in&>(value).sin_addr.s_addr) >> 24) == 127;
    }
    return false;
}
void log_message(const std::string& message) {
    if (message.find("send queue exhausted") != std::string::npos) ++queue_warnings;
}

extern "C" NF_STATUS NFAPI_CC nf_udpPostReceive(ENDPOINT_ID id, const unsigned char* source,
                                                const char* data, int length, PNF_UDP_OPTIONS options) {
    Received result;
    result.id = id;
    expect(udp::read_address(source, result.source), "SDK receive source invalid");
    if (length) result.payload.assign(data, data + length);
    expect(udp::copy_options(options, result.options), "SDK receive options invalid");
    std::lock_guard<std::mutex> guard(results_mutex);
    received_packets.push_back(std::move(result));
    return NF_STATUS_SUCCESS;
}

extern "C" NF_STATUS NFAPI_CC nf_udpPostSend(ENDPOINT_ID, const unsigned char*, const char*, int,
                                             PNF_UDP_OPTIONS) {
    ++bypassed_packets;
    return NF_STATUS_SUCCESS;
}

int main() {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 1;
    try {
        framing_and_routes();
        integration();
        cancellation_and_queue_bounds();
        WSACleanup();
        std::cout << "UDP relay regressions passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        WSACleanup();
        return 1;
    }
}
