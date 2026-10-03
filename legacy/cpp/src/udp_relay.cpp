#include "udp_relay.h"
#include "socks5.h"
#include "utils/socket.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstring>
#include <deque>
#include <iterator>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

bool is_private_or_local_address(const sockaddr_storage& address);
void log_message(const std::string& message);

namespace rnetch::udp_relay {
namespace {
using Clock = std::chrono::steady_clock;
constexpr size_t max_datagram = 65535;
constexpr size_t max_packets = 256;
constexpr size_t max_queue_bytes = 8 * 1024 * 1024;
constexpr size_t max_options_bytes = 2 * 1024 * 1024;
constexpr size_t max_routes = 256;
constexpr size_t max_endpoints = 1024;
constexpr auto poll_interval = std::chrono::milliseconds(10);

struct Address {
    sockaddr_storage value{};
    int length = 0;
};

bool read_address(const unsigned char* source, Address& result) {
    if (!source) return false;
    unsigned short family = 0;
    std::memcpy(&family, source, sizeof(family));
    result = {};
    result.length = family == AF_INET ? sizeof(sockaddr_in)
                  : family == AF_INET6 ? sizeof(sockaddr_in6) : 0;
    if (!result.length) return false;
    std::memcpy(&result.value, source, result.length);
    return true;
}

Address normalized(Address source) {
    if (source.value.ss_family == AF_INET6) {
        const auto& original = reinterpret_cast<const sockaddr_in6&>(source.value);
        if (IN6_IS_ADDR_V4MAPPED(&original.sin6_addr)) {
            sockaddr_in converted{};
            converted.sin_family = AF_INET;
            converted.sin_port = original.sin6_port;
            std::memcpy(&converted.sin_addr, original.sin6_addr.s6_addr + 12, 4);
            source = {};
            source.length = sizeof(converted);
            std::memcpy(&source.value, &converted, sizeof(converted));
        }
    }
    return source;
}

bool same_peer(Address left, Address right) {
    left = normalized(left);
    right = normalized(right);
    if (left.value.ss_family != right.value.ss_family) return false;
    if (left.value.ss_family == AF_INET) {
        const auto& a = reinterpret_cast<const sockaddr_in&>(left.value);
        const auto& b = reinterpret_cast<const sockaddr_in&>(right.value);
        return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
    }
    const auto& a = reinterpret_cast<const sockaddr_in6&>(left.value);
    const auto& b = reinterpret_cast<const sockaddr_in6&>(right.value);
    return a.sin6_port == b.sin6_port && a.sin6_scope_id == b.sin6_scope_id &&
           std::memcmp(&a.sin6_addr, &b.sin6_addr, sizeof(a.sin6_addr)) == 0;
}

bool copy_options(PNF_UDP_OPTIONS source, std::vector<char>& result) {
    constexpr size_t header = offsetof(NF_UDP_OPTIONS, options);
    if (!source) {
        result.assign(sizeof(NF_UDP_OPTIONS), 0);
        return true;
    }
    long length = 0;
    std::memcpy(&length, &source->optionsLength, sizeof(length));
    // Include the fixed header in the allocation/cache budget, and reject a
    // negative length before converting it to an unsigned allocation size.
    if (length < 0 || static_cast<size_t>(length) > max_options_bytes - header) return false;
    const size_t count = header + static_cast<size_t>(length);
    result.assign(std::max(count, sizeof(NF_UDP_OPTIONS)), 0);
    std::memcpy(result.data(), source, count);
    return true;
}

struct Packet {
    Address destination;
    std::vector<char> payload;
    std::vector<char> options;
    size_t bytes() const { return payload.size() + options.size(); }
};

struct Route {
    Address original;
    std::vector<char> options;
};

struct Routes {
    std::deque<Route> entries;
    size_t bytes = 0;

    void remember(Address destination, std::vector<char> options) {
        const auto found = std::find_if(entries.begin(), entries.end(), [&](const Route& route) {
            return same_peer(route.original, destination);
        });
        if (found != entries.end()) {
            bytes -= found->options.size();
            entries.erase(found);
        }
        bytes += options.size();
        entries.push_back({destination, std::move(options)});
        while (entries.size() > max_routes || bytes > max_options_bytes) {
            bytes -= entries.front().options.size();
            entries.pop_front();
        }
    }

    Route* reply(Address& source) {
        if (entries.empty()) return nullptr;
        source = normalized(source);
        const auto found = std::find_if(entries.begin(), entries.end(), [&](const Route& route) {
            return same_peer(route.original, source);
        });
        // Some UDP services respond from another port/address. Prefer an exact
        // route and use the newest route only when the peer is not yet known.
        Route& route = found == entries.end() ? entries.back() : *found;
        if (source.value.ss_family == AF_INET && route.original.value.ss_family == AF_INET6) {
            const auto original = reinterpret_cast<const sockaddr_in&>(source.value);
            sockaddr_in6 converted{};
            converted.sin6_family = AF_INET6;
            converted.sin6_port = original.sin_port;
            converted.sin6_addr.s6_addr[10] = 0xff;
            converted.sin6_addr.s6_addr[11] = 0xff;
            std::memcpy(converted.sin6_addr.s6_addr + 12, &original.sin_addr, 4);
            source = {};
            source.length = sizeof(converted);
            std::memcpy(&source.value, &converted, sizeof(converted));
        }
        return &route;
    }
};

std::vector<char> encode(const Packet& packet) {
    const auto address = normalized(packet.destination);
    std::vector<char> output(3, 0);
    if (address.value.ss_family == AF_INET) {
        const auto& peer = reinterpret_cast<const sockaddr_in&>(address.value);
        output.push_back(1);
        const auto* ip = reinterpret_cast<const char*>(&peer.sin_addr);
        output.insert(output.end(), ip, ip + 4);
        const auto* port = reinterpret_cast<const char*>(&peer.sin_port);
        output.insert(output.end(), port, port + 2);
    } else {
        const auto& peer = reinterpret_cast<const sockaddr_in6&>(address.value);
        output.push_back(4);
        const auto* ip = reinterpret_cast<const char*>(&peer.sin6_addr);
        output.insert(output.end(), ip, ip + 16);
        const auto* port = reinterpret_cast<const char*>(&peer.sin6_port);
        output.insert(output.end(), port, port + 2);
    }
    output.insert(output.end(), packet.payload.begin(), packet.payload.end());
    return output;
}

bool decode(const char* bytes, size_t length, Address& source, size_t& offset) {
    if (length < 4 || bytes[0] || bytes[1] || bytes[2]) return false;
    source = {};
    if (bytes[3] == 1 && length >= 10) {
        auto& peer = reinterpret_cast<sockaddr_in&>(source.value);
        peer.sin_family = AF_INET;
        std::memcpy(&peer.sin_addr, bytes + 4, 4);
        std::memcpy(&peer.sin_port, bytes + 8, 2);
        source.length = sizeof(peer);
        offset = 10;
        return true;
    }
    if (bytes[3] == 4 && length >= 22) {
        auto& peer = reinterpret_cast<sockaddr_in6&>(source.value);
        peer.sin6_family = AF_INET6;
        std::memcpy(&peer.sin6_addr, bytes + 4, 16);
        std::memcpy(&peer.sin6_port, bytes + 20, 2);
        source.length = sizeof(peer);
        offset = 22;
        return true;
    }
    return false;
}

struct Session {
    std::atomic_bool closed{false};
    std::atomic_bool queue_warning_pending{false};
    std::mutex mutex;
    std::condition_variable wake;
    std::deque<Packet> packets;
    size_t queued_bytes = 0;
    bool started = false;
    bool queue_warning_issued = false;
};

void warning(ENDPOINT_ID id, const char* message) noexcept {
    try { log_message("UDP " + std::to_string(id) + ": " + message); }
    catch (...) {} // A failed logger must not escape a worker's final cleanup.
}

void report_queue_warning(ENDPOINT_ID id, Session& session) noexcept {
    if (session.queue_warning_pending.exchange(false)) {
        warning(id, "send queue exhausted; datagrams dropped (further queue warnings suppressed for this endpoint)");
    }
}

struct Worker {
    std::thread thread;
    std::atomic_bool done{false};
};

struct Runtime {
    std::string host, port, user, pass;
    std::atomic_bool* external_stop = nullptr;
    std::atomic<unsigned long long>* uploaded = nullptr;
    std::atomic<unsigned long long>* downloaded = nullptr;
    std::atomic_bool stopping{false};
    std::mutex mutex;
    std::map<ENDPOINT_ID, std::shared_ptr<Session>> sessions;
    std::list<std::shared_ptr<Worker>> workers;
    bool stopped() const { return stopping.load() || external_stop->load(); }
};

std::mutex runtime_mutex;
std::shared_ptr<Runtime> active;

std::shared_ptr<Runtime> current() {
    std::lock_guard<std::mutex> guard(runtime_mutex);
    return active;
}

bool nonblocking(SOCKET socket) {
    u_long enabled = 1;
    return ioctlsocket(socket, FIONBIO, &enabled) == 0;
}

bool retryable(int error) { return error == WSAEWOULDBLOCK || error == WSAEINTR; }

bool take_packet(Session& session, Packet& packet) {
    std::lock_guard<std::mutex> guard(session.mutex);
    if (session.packets.empty()) return false;
    packet = std::move(session.packets.front());
    session.packets.pop_front();
    session.queued_bytes -= packet.bytes();
    return true;
}

void associate(const std::shared_ptr<Runtime>& runtime, ENDPOINT_ID id,
               const std::shared_ptr<Session>& session, Packet first) {
    const auto cancelled = [&] { return runtime->stopped() || session->closed.load(); };
    utils::SocketHandle control(socks5::connect(runtime->host, runtime->port, cancelled));
    if (control.get() == INVALID_SOCKET ||
        !socks5::handshake(control.get(), runtime->user, runtime->pass, cancelled)) {
        throw std::runtime_error("SOCKS5 UDP authentication/connection failed");
    }
    SOCKADDR_IN6 relay{};
    if (!socks5::udp_associate(control.get(), relay, cancelled)) {
        throw std::runtime_error("SOCKS5 UDP ASSOCIATE failed");
    }
    Address destination;
    if (!read_address(reinterpret_cast<const unsigned char*>(&relay), destination)) {
        throw std::runtime_error("SOCKS5 UDP relay has an unsupported address family");
    }
    destination = normalized(destination);
    utils::SocketHandle data(::socket(destination.value.ss_family, SOCK_DGRAM, IPPROTO_UDP));
    if (data.get() == INVALID_SOCKET ||
        ::connect(data.get(), reinterpret_cast<const sockaddr*>(&destination.value), destination.length) != 0 ||
        !nonblocking(data.get()) || !nonblocking(control.get())) {
        throw std::runtime_error("Cannot initialize SOCKS5 UDP relay socket");
    }
    Routes routes;
    Packet pending = std::move(first);
    bool have_pending = true;
    std::array<char, max_datagram> buffer{};
    while (!cancelled()) {
        report_queue_warning(id, *session);
        bool progress = false;
        for (int count = 0; count < 32 && !cancelled(); ++count) {
            if (!have_pending && !take_packet(*session, pending)) break;
            have_pending = true;
            const auto frame = encode(pending);
            const int sent = ::send(data.get(), frame.data(), static_cast<int>(frame.size()), 0);
            if (sent == SOCKET_ERROR) {
                const int error = WSAGetLastError();
                if (retryable(error)) break;
                // A too-large individual datagram must not destroy an otherwise
                // healthy association or cause repeated reconnections.
                if (error != WSAEMSGSIZE) throw std::runtime_error("SOCKS5 UDP send failed");
            } else if (static_cast<size_t>(sent) == frame.size()) {
                runtime->uploaded->fetch_add(static_cast<unsigned long long>(pending.payload.size()));
                routes.remember(pending.destination, std::move(pending.options));
            }
            have_pending = false;
            progress = true;
        }
        for (int count = 0; count < 32 && !cancelled(); ++count) {
            const int received = ::recv(data.get(), buffer.data(), static_cast<int>(buffer.size()), 0);
            if (received == SOCKET_ERROR) {
                const int error = WSAGetLastError();
                if (retryable(error)) break;
                if (error == WSAEMSGSIZE) continue;
                throw std::runtime_error("SOCKS5 UDP receive failed");
            }
            progress = true;
            Address source;
            size_t offset = 0;
            if (!decode(buffer.data(), static_cast<size_t>(received), source, offset)) continue;
            Route* route = routes.reply(source);
            if (!route) continue;
            const int payload_length = received - static_cast<int>(offset);
            if (nf_udpPostReceive(id, reinterpret_cast<const unsigned char*>(&source.value),
                                  buffer.data() + offset, payload_length,
                                  reinterpret_cast<PNF_UDP_OPTIONS>(route->options.data())) != NF_STATUS_SUCCESS) {
                throw std::runtime_error("NetFilter UDP receive injection failed");
            }
            runtime->downloaded->fetch_add(static_cast<unsigned long long>(payload_length));
        }
        char check = 0;
        const int alive = ::recv(control.get(), &check, 1, MSG_PEEK);
        if (alive == 0 || (alive == SOCKET_ERROR && !retryable(WSAGetLastError()))) {
            throw std::runtime_error("SOCKS5 UDP control connection closed");
        }
        if (!progress) {
            std::unique_lock<std::mutex> guard(session->mutex);
            session->wake.wait_for(guard, poll_interval, [&] {
                return cancelled() || (!have_pending && !session->packets.empty());
            });
        }
    }
}

void run(const std::shared_ptr<Runtime>& runtime, ENDPOINT_ID id,
         const std::shared_ptr<Session>& session) {
    const auto cancelled = [&] { return runtime->stopped() || session->closed.load(); };
    auto retry_delay = std::chrono::milliseconds(250);
    while (!cancelled()) {
        report_queue_warning(id, *session);
        Packet first;
        if (!take_packet(*session, first)) {
            std::unique_lock<std::mutex> guard(session->mutex);
            session->wake.wait_for(guard, std::chrono::milliseconds(100), [&] {
                return cancelled() || !session->packets.empty();
            });
            continue;
        }
        const auto started = Clock::now();
        try {
            associate(runtime, id, session, std::move(first));
        } catch (const std::exception& error) {
            if (cancelled()) return;
            log_message("UDP " + std::to_string(id) + ": " + error.what() +
                        "; retrying SOCKS5 on the next datagram");
            if (Clock::now() - started > std::chrono::seconds(5)) retry_delay = std::chrono::milliseconds(250);
            // Discard stale game frames during backoff. Keep the endpoint so a
            // later packet retries instead of permanently disabling filtering.
            const auto deadline = Clock::now() + retry_delay;
            while (!cancelled() && Clock::now() < deadline) {
                std::unique_lock<std::mutex> guard(session->mutex);
                session->packets.clear();
                session->queued_bytes = 0;
                session->wake.wait_for(guard, poll_interval);
            }
            retry_delay = std::min(retry_delay * 2, std::chrono::milliseconds(2000));
        }
    }
}
} // namespace

void configure(const std::string& host, const std::string& port,
               const std::string& user, const std::string& pass,
               std::atomic_bool& stopping,
               std::atomic<unsigned long long>& uploaded,
               std::atomic<unsigned long long>& downloaded) {
    stop();
    auto runtime = std::make_shared<Runtime>();
    runtime->host = host;
    runtime->port = port;
    runtime->user = user;
    runtime->pass = pass;
    runtime->external_stop = &stopping;
    runtime->uploaded = &uploaded;
    runtime->downloaded = &downloaded;
    std::lock_guard<std::mutex> guard(runtime_mutex);
    active = std::move(runtime);
}

void created(ENDPOINT_ID id, PNF_UDP_CONN_INFO info) {
    const auto runtime = current();
    if (!info || !runtime || runtime->stopped()) return;
    std::lock_guard<std::mutex> guard(runtime->mutex);
    if (!runtime->stopped() && runtime->sessions.size() < max_endpoints && !runtime->sessions.count(id)) {
        runtime->sessions.emplace(id, std::make_shared<Session>());
    }
}

void closed(ENDPOINT_ID id) {
    const auto runtime = current();
    if (!runtime) return;
    std::lock_guard<std::mutex> guard(runtime->mutex);
    const auto found = runtime->sessions.find(id);
    if (found != runtime->sessions.end()) {
        found->second->closed = true;
        found->second->wake.notify_all();
        runtime->sessions.erase(found);
    }
}

void receive(ENDPOINT_ID id, const unsigned char* remote, const char* data,
             int length, PNF_UDP_OPTIONS options) {
    const auto runtime = current();
    if (runtime && !runtime->stopped() && remote && length >= 0 &&
        static_cast<size_t>(length) <= max_datagram && (data || !length)) {
        nf_udpPostReceive(id, remote, data, length, options);
    }
}

void send(ENDPOINT_ID id, const unsigned char* remote, const char* data,
          int length, PNF_UDP_OPTIONS options) {
    const auto runtime = current();
    if (!runtime || runtime->stopped() || length < 0 ||
        static_cast<size_t>(length) > max_datagram || (!data && length)) return;
    Packet packet;
    if (!read_address(remote, packet.destination)) return;
    if (is_private_or_local_address(normalized(packet.destination).value)) {
        nf_udpPostSend(id, remote, data, length, options);
        return;
    }
    std::lock_guard<std::mutex> guard(runtime->mutex);
    if (runtime->stopped()) return;
    const auto found = runtime->sessions.find(id);
    if (found == runtime->sessions.end()) {
        nf_udpPostSend(id, remote, data, length, options);
        return;
    }
    const auto& session = found->second;
    if (session->closed.load() || !copy_options(options, packet.options)) return;
    if (length) packet.payload.assign(data, data + length);
    std::lock_guard<std::mutex> queue_guard(session->mutex);
    if (session->packets.size() >= max_packets ||
        packet.bytes() > max_queue_bytes - session->queued_bytes) {
        if (!session->queue_warning_issued) {
            session->queue_warning_issued = true;
            session->queue_warning_pending = true;
        }
        // The worker emits the one-time warning, keeping disk I/O outside SDK
        // callbacks even when an application floods an unavailable proxy.
        return;
    }
    if (!session->started) {
        if (runtime->workers.size() >= max_endpoints) return;
        auto worker = std::make_shared<Worker>();
        runtime->workers.push_back(worker);
        try {
            worker->thread = std::thread([runtime, id, session, worker] {
                try { run(runtime, id, session); }
                catch (const std::exception& error) {
                    session->closed = true;
                    runtime->external_stop->store(true);
                    warning(id, error.what());
                    warning(id, "forwarding worker failed unexpectedly; stopping forwarding");
                } catch (...) {
                    session->closed = true;
                    runtime->external_stop->store(true);
                    warning(id, "forwarding worker failed with an unknown exception; stopping forwarding");
                }
                report_queue_warning(id, *session);
                worker->done = true;
            });
        } catch (...) {
            runtime->workers.pop_back();
            throw;
        }
        session->started = true;
    }
    session->queued_bytes += packet.bytes();
    session->packets.push_back(std::move(packet));
    session->wake.notify_one();
}

void reap() {
    const auto runtime = current();
    if (!runtime) return;
    std::list<std::shared_ptr<Worker>> completed;
    {
        std::lock_guard<std::mutex> guard(runtime->mutex);
        for (auto it = runtime->workers.begin(); it != runtime->workers.end();) {
            const auto next = std::next(it);
            if ((*it)->done.load()) completed.splice(completed.end(), runtime->workers, it);
            it = next;
        }
    }
    for (const auto& worker : completed) if (worker->thread.joinable()) worker->thread.join();
}

void stop() {
    const auto runtime = current();
    if (!runtime) return;
    runtime->stopping = true;
    std::list<std::shared_ptr<Worker>> workers;
    {
        std::lock_guard<std::mutex> guard(runtime->mutex);
        for (const auto& entry : runtime->sessions) {
            entry.second->closed = true;
            entry.second->wake.notify_all();
        }
        runtime->sessions.clear();
        workers.swap(runtime->workers);
    }
    for (const auto& worker : workers) if (worker->thread.joinable()) worker->thread.join();
}

} // namespace rnetch::udp_relay
