#include "rnetch.h"
#include "socks5.h"
#include "driver.h"
#include "tcp_relay.h"
#include "udp_relay.h"
#include "proxy_process.h"
#include <cwctype>
#include <stdexcept>
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <memory>
#include <condition_variable>
#include <cwchar>
#include <algorithm>
#include <array>
#include <deque>
#include <set>
#include <sstream>
#include <cstdint>


// --- Logger (RAII) ---
#include "utils/logger.h"
#include "utils/thread.h"
static rnetch::utils::Logger g_logger;

// Simple thread-safe file logger API kept for compatibility
void log_message(const std::string& message) {
    g_logger.log(message);
}
// --- End Logger ---

// Global variables
static std::string g_socks5_host;
static std::string g_socks5_port;
static std::string g_socks5_user;
static std::string g_socks5_pass;

// Stop flag to signal worker threads to exit
static std::atomic_bool g_stop_flag(false);

// Live telemetry counters. Upload is application -> SOCKS5 proxy; download is proxy -> application.
static std::atomic<unsigned long long> g_tcp_up_bytes(0);
static std::atomic<unsigned long long> g_tcp_down_bytes(0);
static std::atomic<unsigned long long> g_udp_up_bytes(0);
static std::atomic<unsigned long long> g_udp_down_bytes(0);
static std::mutex g_stdout_lock;
static std::shared_ptr<rnetch::utils::ThreadHandle> g_metrics_worker;

// Workers own their sockets. SDK callbacks only copy requests or signal closure;
// the metrics thread reaps completed workers and stop() joins the remainder.
#include "utils/socket.h"
struct TcpSession {
    std::atomic_bool closed{false};
    std::atomic_bool finished{false};
    std::thread worker;
};
static std::mutex g_tcp_context_lock;
static std::map<ENDPOINT_ID, std::shared_ptr<TcpSession>> g_tcp_context;
static std::vector<rnetch::Rule> g_rules;
static constexpr size_t MAX_ENDPOINTS = 1024;
static bool g_wsa_initialized = false;
static bool g_nf_initialized = false;

void reap_tcp_workers() {
    std::vector<std::shared_ptr<TcpSession>> completed;
    {
        std::lock_guard<std::mutex> lock(g_tcp_context_lock);
        for (auto it = g_tcp_context.begin(); it != g_tcp_context.end();) {
            if (it->second->finished.load()) {
                completed.push_back(it->second);
                it = g_tcp_context.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (const auto& session : completed) {
        if (session->worker.joinable()) session->worker.join();
    }
}

void stop_tcp_workers() {
    std::map<ENDPOINT_ID, std::shared_ptr<TcpSession>> workers;
    {
        std::lock_guard<std::mutex> lock(g_tcp_context_lock);
        workers.swap(g_tcp_context);
    }
    for (const auto& entry : workers) {
        if (entry.second->worker.joinable()) entry.second->worker.join();
    }
}

std::wstring normalized_process_path(std::wstring value) {
    for (auto& ch : value) {
        ch = ch == L'/' ? L'\\' : static_cast<wchar_t>(std::towlower(ch));
    }
    return value;
}

bool wildcard_matches(const std::wstring& pattern, const std::wstring& value) {
    size_t p = 0, v = 0, star = std::wstring::npos, retry = 0;
    while (v < value.size()) {
        if (p < pattern.size() && (pattern[p] == L'?' || pattern[p] == value[v])) {
            ++p;
            ++v;
        } else if (p < pattern.size() && pattern[p] == L'*') {
            star = p++;
            retry = v;
        } else if (star != std::wstring::npos) {
            p = star + 1;
            v = ++retry;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == L'*') ++p;
    return p == pattern.size();
}

bool should_proxy(DWORD process_id, bool tcp) {
    if (process_id == GetCurrentProcessId() || rnetch::proxy_process::is_proxy(process_id)) return false;
    wchar_t name[32768] = {};
    if (!nf_getProcessNameW(process_id, name, static_cast<DWORD>(std::size(name)))) return false;
    const auto path = normalized_process_path(name);
    const auto basename = path.substr(path.find_last_of(L'\\') + 1);
    for (const auto& rule : g_rules) {
        if (!(tcp ? rule.accelerate_tcp : rule.accelerate_udp)) continue;
        for (const auto& configured : rule.process_names) {
            const auto pattern = normalized_process_path(configured);
            const auto& candidate = pattern.find(L'\\') == std::wstring::npos ? basename : path;
            if (wildcard_matches(pattern, candidate)) return true;
        }
    }
    return false;
}

void allow_direct_tcp(ENDPOINT_ID id, PNF_TCP_CONN_INFO info) {
    if (info) {
        info->filteringFlag = NF_ALLOW;
    }
    nf_tcpDisableFiltering(id);
}

bool is_private_or_local_ipv4(uint32_t addr_host_order) {
    return (addr_host_order == 0) ||
           ((addr_host_order & 0xff000000UL) == 0x0a000000UL) ||     // 10.0.0.0/8
           ((addr_host_order & 0xfff00000UL) == 0xac100000UL) ||     // 172.16.0.0/12
           ((addr_host_order & 0xffff0000UL) == 0xc0a80000UL) ||     // 192.168.0.0/16
           ((addr_host_order & 0xff000000UL) == 0x7f000000UL) ||     // 127.0.0.0/8
           ((addr_host_order & 0xffff0000UL) == 0xa9fe0000UL) ||     // 169.254.0.0/16
           ((addr_host_order & 0xf0000000UL) == 0xe0000000UL) ||     // multicast
           (addr_host_order == 0xffffffffUL);
}

bool is_private_or_local_address(const sockaddr_storage& addr) {
    if (addr.ss_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(&addr);
        const uint32_t host_order = ntohl(in->sin_addr.s_addr);
        return is_private_or_local_ipv4(host_order);
    }

    if (addr.ss_family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        const auto* bytes = in6->sin6_addr.s6_addr;
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            uint32_t mapped;
            memcpy(&mapped, bytes + 12, sizeof(mapped));
            return is_private_or_local_ipv4(ntohl(mapped));
        }
        const bool loopback = IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr) || IN6_IS_ADDR_UNSPECIFIED(&in6->sin6_addr);
        const bool link_local = (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80);
        const bool unique_local = ((bytes[0] & 0xfe) == 0xfc);
        return loopback || link_local || unique_local || IN6_IS_ADDR_MULTICAST(&in6->sin6_addr);
    }

    return true;
}

std::string sockaddr_to_string(const sockaddr_storage& addr) {
    char host[INET6_ADDRSTRLEN] = {};
    unsigned short port = 0;

    if (addr.ss_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(&addr);
        inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
        port = ntohs(in->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
        port = ntohs(in6->sin6_port);
    } else {
        return "unknown";
    }

    return std::string(host) + ":" + std::to_string(port);
}

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (char ch : value) {
        switch (ch) {
            case '"':
                out << "\\\"";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '\b':
                out << "\\b";
                break;
            case '\f':
                out << "\\f";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    out << "\\u"
                        << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(ch))
                        << std::dec << std::setfill(' ');
                } else {
                    out << ch;
                }
                break;
        }
    }
    return out.str();
}

void emit_json_line(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_stdout_lock);
    std::cout << line << std::endl;
}

void emit_status(const std::string& state, const std::string& message) {
    emit_json_line("{\"type\":\"status\",\"state\":\"" + json_escape(state) + "\",\"message\":\"" + json_escape(message) + "\"}");
}

unsigned long long bytes_per_second(unsigned long long current, unsigned long long previous, double elapsed_seconds) {
    if (elapsed_seconds <= 0.0 || current < previous) {
        return 0;
    }
    return static_cast<unsigned long long>((current - previous) / elapsed_seconds);
}

void emit_metrics(unsigned long long tcp_up_bps, unsigned long long tcp_down_bps,
                  unsigned long long udp_up_bps, unsigned long long udp_down_bps) {
    const auto tcp_up = g_tcp_up_bytes.load();
    const auto tcp_down = g_tcp_down_bytes.load();
    const auto udp_up = g_udp_up_bytes.load();
    const auto udp_down = g_udp_down_bytes.load();

    std::ostringstream out;
    out << "{\"type\":\"metrics\""
        << ",\"tcpUpBps\":" << tcp_up_bps
        << ",\"tcpDownBps\":" << tcp_down_bps
        << ",\"udpUpBps\":" << udp_up_bps
        << ",\"udpDownBps\":" << udp_down_bps
        << ",\"totalUpBps\":" << (tcp_up_bps + udp_up_bps)
        << ",\"totalDownBps\":" << (tcp_down_bps + udp_down_bps)
        << ",\"tcpUpBytes\":" << tcp_up
        << ",\"tcpDownBytes\":" << tcp_down
        << ",\"udpUpBytes\":" << udp_up
        << ",\"udpDownBytes\":" << udp_down
        << "}";
    emit_json_line(out.str());
}

void reset_metrics() {
    g_tcp_up_bytes = 0;
    g_tcp_down_bytes = 0;
    g_udp_up_bytes = 0;
    g_udp_down_bytes = 0;
}

void metrics_loop() {
    using clock = std::chrono::steady_clock;
    auto last_at = clock::now();
    auto last_tcp_up = g_tcp_up_bytes.load();
    auto last_tcp_down = g_tcp_down_bytes.load();
    auto last_udp_up = g_udp_up_bytes.load();
    auto last_udp_down = g_udp_down_bytes.load();

    while (!g_stop_flag) {
        for (int tick = 0; tick < 10 && !g_stop_flag; ++tick) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        reap_tcp_workers();
        rnetch::udp_relay::reap();
        const auto now = clock::now();
        const std::chrono::duration<double> elapsed = now - last_at;

        const auto tcp_up = g_tcp_up_bytes.load();
        const auto tcp_down = g_tcp_down_bytes.load();
        const auto udp_up = g_udp_up_bytes.load();
        const auto udp_down = g_udp_down_bytes.load();

        emit_metrics(
            bytes_per_second(tcp_up, last_tcp_up, elapsed.count()),
            bytes_per_second(tcp_down, last_tcp_down, elapsed.count()),
            bytes_per_second(udp_up, last_udp_up, elapsed.count()),
            bytes_per_second(udp_down, last_udp_down, elapsed.count()));

        last_at = now;
        last_tcp_up = tcp_up;
        last_tcp_down = tcp_down;
        last_udp_up = udp_up;
        last_udp_down = udp_down;
    }
}

bool copy_sockaddr(const unsigned char* encoded, sockaddr_storage& address) {
    unsigned short family = 0;
    memcpy(&family, encoded, sizeof(family));
    const size_t size = family == AF_INET ? sizeof(sockaddr_in)
        : family == AF_INET6 ? sizeof(sockaddr_in6) : 0;
    if (!size) return false;
    address = {};
    memcpy(&address, encoded, size);
    return true;
}

template<class Work>
void callback(Work&& work) noexcept {
    try {
        work();
    } catch (...) {
        // C++ exceptions must never cross the SDK's C callback boundary.
        g_stop_flag = true;
        try { emit_status("error", "Legacy NetFilter callback failed; stopping forwarding"); } catch (...) {}
    }
}

void tcp_worker(ENDPOINT_ID id, NF_TCP_CONN_INFO info, const std::shared_ptr<TcpSession>& session) noexcept {
    const auto stopped = [&] { return g_stop_flag.load() || session->closed.load(); };
    bool abort_connection = false;
    try {
        [&] {
            sockaddr_storage target{};
            if (!copy_sockaddr(info.remoteAddress, target)) throw std::runtime_error("Unsupported TCP destination");
            rnetch::utils::SocketHandle proxy(rnetch::socks5::connect(g_socks5_host, g_socks5_port, stopped));
            const bool connected = proxy.get() != INVALID_SOCKET
                && rnetch::socks5::handshake(proxy.get(), g_socks5_user, g_socks5_pass, stopped)
                && rnetch::socks5::connect_remote(proxy.get(), reinterpret_cast<sockaddr*>(&target), stopped);
            if (stopped()) return;
            if (!connected) {
                // Preserve the historical direct fallback on SOCKS failure.
                info.filteringFlag = NF_ALLOW;
                if (nf_completeTCPConnectRequest(id, &info) != NF_STATUS_SUCCESS) {
                    throw std::runtime_error("Complete direct TCP connection failed");
                }
                emit_status("warning", "SOCKS5 TCP failed; using direct connection for " + std::to_string(id));
                return;
            }

            sockaddr_storage local{};
            if (!copy_sockaddr(info.localAddress, local)) throw std::runtime_error("Unsupported TCP local address");
            auto listener = rnetch::tcp_relay::listen(local);
            memset(info.remoteAddress, 0, sizeof(info.remoteAddress));
            memcpy(info.remoteAddress, &listener.address,
                listener.address.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
            info.processId = GetCurrentProcessId();
            info.filteringFlag = NF_ALLOW;
            if (stopped()) return;
            if (nf_completeTCPConnectRequest(id, &info) != NF_STATUS_SUCCESS) {
                throw std::runtime_error("Complete redirected TCP connection failed");
            }
            auto application = rnetch::tcp_relay::accept(listener.socket.get(), local, stopped);
            if (application.get() == INVALID_SOCKET) return;
            listener.socket.close();
            rnetch::tcp_relay::relay(application.get(), proxy.get(), stopped, g_tcp_up_bytes, g_tcp_down_bytes);
            // Normal EOF drains both directions; socket RAII closes the transport.
            // nf_tcpClose would abort outstanding I/O and must not be used here.
        }();
    } catch (const std::exception& error) {
        abort_connection = true;
        try { emit_status("warning", "NetFilter TCP " + std::to_string(id) + ": " + error.what()); } catch (...) {}
    } catch (...) {
        abort_connection = true;
        try { emit_status("warning", "NetFilter TCP worker failed for " + std::to_string(id)); } catch (...) {}
    }
    if ((abort_connection || g_stop_flag) && !session->closed.exchange(true)) nf_tcpClose(id);
    session->finished = true;
}

// Selected TCP flows use real local sockets, with no offline data injection or
// dependency on tcpConnected. Network work never runs on an SDK callback thread.
void threadStart() {}
void threadEnd() {}

void tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO info) noexcept {
    if (!info) return;
    callback([&] {
        NF_TCP_CONN_INFO connection;
        memcpy(&connection, info, sizeof(connection));
        sockaddr_storage target{};
        if (g_stop_flag || connection.direction != NF_D_OUT
            || !copy_sockaddr(connection.remoteAddress, target)
            || is_private_or_local_address(target) || !should_proxy(connection.processId, true)) {
            allow_direct_tcp(id, info);
            return;
        }
        std::lock_guard<std::mutex> lock(g_tcp_context_lock);
        if (g_stop_flag || g_tcp_context.size() >= MAX_ENDPOINTS || g_tcp_context.count(id)) {
            info->filteringFlag = NF_BLOCK;
            return;
        }
        auto session = std::make_shared<TcpSession>();
        g_tcp_context.emplace(id, session);
        connection.filteringFlag = NF_PEND_CONNECT_REQUEST;
        info->filteringFlag = NF_PEND_CONNECT_REQUEST;
        try {
            session->worker = std::thread(tcp_worker, id, connection, session);
        } catch (...) {
            g_tcp_context.erase(id);
            info->filteringFlag = NF_BLOCK;
            throw;
        }
    });
    if (g_stop_flag) info->filteringFlag = NF_BLOCK;
}

void tcpConnected(ENDPOINT_ID, PNF_TCP_CONN_INFO) {}

void tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO) noexcept {
    callback([&] {
        std::lock_guard<std::mutex> lock(g_tcp_context_lock);
        const auto it = g_tcp_context.find(id);
        if (it != g_tcp_context.end()) it->second->closed = true;
        // Do not join here: the worker may be completing an SDK call.
    });
}

void tcpReceive(ENDPOINT_ID id, const char* buf, int len) noexcept {
    callback([&] {
        if (!g_stop_flag && len >= 0 && (len == 0 || buf)) nf_tcpPostReceive(id, buf, len);
    });
}

void tcpSend(ENDPOINT_ID id, const char* buf, int len) noexcept {
    callback([&] {
        if (!g_stop_flag && len >= 0 && (len == 0 || buf)) nf_tcpPostSend(id, buf, len);
    });
}

void tcpCanReceive(ENDPOINT_ID) {}
void tcpCanSend(ENDPOINT_ID) {}

void udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO info) noexcept {
    callback([&] {
        if (!info || g_stop_flag || !should_proxy(info->processId, false)) {
            nf_udpDisableFiltering(id);
        } else {
            rnetch::udp_relay::created(id, info);
        }
    });
}

void udpConnectRequest(ENDPOINT_ID, PNF_UDP_CONN_REQUEST) {}

void udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO) noexcept {
    callback([&] { rnetch::udp_relay::closed(id); });
}

void udpReceive(ENDPOINT_ID id, const unsigned char* remote, const char* buf, int len, PNF_UDP_OPTIONS options) noexcept {
    callback([&] { rnetch::udp_relay::receive(id, remote, buf, len, options); });
}

void udpSend(ENDPOINT_ID id, const unsigned char* remote, const char* buf, int len, PNF_UDP_OPTIONS options) noexcept {
    callback([&] { rnetch::udp_relay::send(id, remote, buf, len, options); });
}

void udpCanReceive(ENDPOINT_ID) {}
void udpCanSend(ENDPOINT_ID) {}

NF_EventHandler g_eventHandler = {
    threadStart,
    threadEnd,
    tcpConnectRequest,
    tcpConnected,
    tcpClosed,
    tcpReceive,
    tcpSend,
    tcpCanReceive,
    tcpCanSend,
    udpCreated,
    udpConnectRequest,
    udpClosed,
    udpReceive,
    udpSend,
    udpCanReceive,
    udpCanSend
};

void add_bypass_rule(const char* network, const char* mask) {
    NF_RULE_EX bypass_rule = {};
    bypass_rule.direction = NF_D_OUT;
    bypass_rule.filteringFlag = NF_ALLOW;
    bypass_rule.ip_family = AF_INET;
    inet_pton(AF_INET, network, bypass_rule.remoteIpAddress);
    inet_pton(AF_INET, mask, bypass_rule.remoteIpAddressMask);
    if (nf_addRuleEx(&bypass_rule, TRUE) != NF_STATUS_SUCCESS) {
        throw std::runtime_error("Failed to install local bypass rule");
    }
}

std::vector<NF_RULE_EX> compile_driver_rules(const std::vector<rnetch::Rule>& rules) {
    std::vector<NF_RULE_EX> compiled;
    std::set<std::pair<int, std::wstring>> seen;
    for (const auto& configured : rules) {
        if (!configured.accelerate_tcp && !configured.accelerate_udp) continue;
        for (const auto& name : configured.process_names) {
            auto mask = normalized_process_path(name);
            mask = mask.substr(mask.find_last_of(L'\\') + 1);
            if (mask.empty() || mask.size() >= MAX_PATH || mask.find(L'\0') != std::wstring::npos) {
                throw std::runtime_error("Invalid NetFilter process filename pattern");
            }
            // SDK supports tail masks with '*'. Widen '?' and path rules here;
            // should_proxy performs the exact final check using the original rule.
            std::replace(mask.begin(), mask.end(), L'?', L'*');
            for (int protocol : {IPPROTO_TCP, IPPROTO_UDP}) {
                if (!(protocol == IPPROTO_TCP ? configured.accelerate_tcp : configured.accelerate_udp)
                    || !seen.emplace(protocol, mask).second) continue;
                NF_RULE_EX rule = {};
                std::copy(mask.begin(), mask.end(), rule.processName);
                rule.direction = NF_D_OUT;
                rule.protocol = protocol;
                rule.filteringFlag = protocol == IPPROTO_TCP ? NF_INDICATE_CONNECT_REQUESTS : NF_FILTER;
                compiled.push_back(rule);
            }
        }
    }
    return compiled;
}

namespace rnetch {
    BOOL WINAPI stop_console_handler(DWORD event) noexcept {
        if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT) {
            g_stop_flag = true;
            return TRUE;
        }
        return FALSE;
    }

    void wait_for_stop() {
        // Keep the owner responsive to worker/callback failures as well as input.
        // Blocking std::cin.get() left SDK filtering attached after an internal
        // stop request until the user eventually pressed Enter.
        const bool registered = SetConsoleCtrlHandler(stop_console_handler, TRUE) != FALSE;
        const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        const DWORD type = GetFileType(input);
        DWORD mode = 0;
        const bool console = GetConsoleMode(input, &mode) != FALSE;
        while (!g_stop_flag && input != INVALID_HANDLE_VALUE && input != nullptr) {
            if (console) {
                INPUT_RECORD records[16];
                DWORD available = 0;
                if (!PeekConsoleInputW(input, records, static_cast<DWORD>(std::size(records)), &available)) break;
                if (available) {
                    DWORD count = 0;
                    if (!ReadConsoleInputW(input, records, available, &count)) break;
                    bool enter = false;
                    for (DWORD index = 0; index < count; ++index) {
                        if (records[index].EventType != KEY_EVENT) continue;
                        const auto& key = records[index].Event.KeyEvent;
                        enter = enter || (key.bKeyDown &&
                            (key.wVirtualKeyCode == VK_RETURN || key.uChar.UnicodeChar == 26));
                    }
                    if (enter) break;
                }
            } else {
                DWORD available = 0;
                if (type == FILE_TYPE_PIPE && !PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) break;
                if (type != FILE_TYPE_PIPE || available) {
                    char ch = 0;
                    DWORD count = 0;
                    if (!ReadFile(input, &ch, 1, &count, nullptr) || !count || ch == '\n' || ch == '\r') break;
                }
            }
            Sleep(100);
        }
        if (registered) SetConsoleCtrlHandler(stop_console_handler, FALSE);
    }

    bool start(const std::string& socks5_host, const std::string& socks5_port, const std::string& socks5_user, const std::string& socks5_pass, const std::vector<Rule>& rules) {
        if (g_nf_initialized) return false;
        std::vector<NF_RULE_EX> driver_rules;
        try {
            driver_rules = compile_driver_rules(rules);
        } catch (const std::exception& error) {
            emit_status("error", error.what());
            return false;
        }
        g_stop_flag = false;
        reset_metrics();

        g_logger.openFile("rnetch_log.txt");
        log_message("Rnetch starting...");

        // Initialize socks5 logger to use same log file
        rnetch::socks5::init_logger("rnetch_log.txt");

        // Initialize Winsock if not initialized
        if (!g_wsa_initialized) {
            WSADATA wsaData;
            int wsa_res = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (wsa_res != 0) {
                log_message(std::string("WSAStartup failed: ") + std::to_string(wsa_res));
                std::cerr << "WSAStartup failed: " << wsa_res << std::endl;
                emit_status("error", "WSAStartup failed: " + std::to_string(wsa_res));
                rnetch::socks5::close_logger();
                g_logger.close();
                return false;
            }
            g_wsa_initialized = true;
        }

        g_socks5_host = socks5_host;
        g_socks5_port = socks5_port;
        g_socks5_user = socks5_user;
        g_socks5_pass = socks5_pass;
        g_rules = rules;
        rnetch::udp_relay::configure(socks5_host, socks5_port, socks5_user, socks5_pass,
            g_stop_flag, g_udp_up_bytes, g_udp_down_bytes);

        if (!driver::install() || !driver::start()) {
            log_message("Failed to install or start driver.");
            std::cerr << "Failed to install or start driver." << std::endl;
            emit_status("error", "Failed to install or start driver.");
            g_stop_flag = true;
            rnetch::udp_relay::stop();
            g_rules.clear();
            if (g_wsa_initialized) {
                WSACleanup();
                g_wsa_initialized = false;
            }
            rnetch::socks5::close_logger();
            g_logger.close();
            return false;
        }

        const auto init_status = nf_init("netfilter2", &g_eventHandler);
        if (init_status != NF_STATUS_SUCCESS) {
            const auto message = "Failed to initialize netfilter driver. nf_init status: " + std::to_string(init_status);
            log_message(message);
            std::cerr << message << std::endl;
            emit_status("error", message);
            g_stop_flag = true;
            stop_tcp_workers();
            rnetch::udp_relay::stop();
            driver::stop();
            g_rules.clear();
            if (g_wsa_initialized) {
                WSACleanup();
                g_wsa_initialized = false;
            }
            rnetch::socks5::close_logger();
            g_logger.close();
            return false;
        }

        g_nf_initialized = true;
        try {
            for (auto& rule : driver_rules) {
                if (nf_addRuleEx(&rule, FALSE) != NF_STATUS_SUCCESS) {
                    throw std::runtime_error("Failed to install process rule");
                }
            }

            add_bypass_rule("10.0.0.0", "255.0.0.0");
            add_bypass_rule("172.16.0.0", "255.240.0.0");
            add_bypass_rule("192.168.0.0", "255.255.0.0");
            add_bypass_rule("169.254.0.0", "255.255.0.0");
            add_bypass_rule("127.0.0.0", "255.0.0.0");
            NF_RULE_EX own_process = {};
            own_process.processId = GetCurrentProcessId();
            own_process.direction = NF_D_OUT;
            own_process.filteringFlag = NF_ALLOW;
            if (nf_addRuleEx(&own_process, TRUE) != NF_STATUS_SUCCESS) {
                throw std::runtime_error("Failed to install relay process bypass rule");
            }
        } catch (const std::exception& error) {
            emit_status("error", error.what());
            stop();
            return false;
        }

        try {
            auto metrics = std::make_shared<rnetch::utils::ThreadHandle>();
            metrics->thr = std::thread(metrics_loop);
            g_metrics_worker = std::move(metrics);
        } catch (const std::exception& error) {
            emit_status("error", error.what());
            stop();
            return false;
        }
        log_message("Rnetch started successfully.");
        emit_status("started", "Rnetch started successfully.");
        emit_metrics(0, 0, 0, 0);
        return true;
    }

    void stop() {
        log_message("Rnetch stopping...");
        emit_status("stopping", "Rnetch stopping...");

        // Signal workers to stop
        g_stop_flag = true;

        if (g_metrics_worker) {
            try {
                g_metrics_worker->join();
            } catch (...) {
                log_message("Exception while joining metrics worker.");
            }
            g_metrics_worker.reset();
        }

        // Stop selecting new connections before draining workers. Keep SDK
        // callbacks/API alive until every worker that might call them has joined.
        if (g_nf_initialized) nf_deleteRules();
        stop_tcp_workers();
        rnetch::udp_relay::stop();
        if (g_nf_initialized) {
            nf_free();
            g_nf_initialized = false;
            driver::stop();
        }
        g_rules.clear();

        // Cleanup Winsock if initialized
        if (g_wsa_initialized) {
            WSACleanup();
            g_wsa_initialized = false;
            log_message("WSACleanup done.");
        }

        log_message("Rnetch stopped.");
        emit_metrics(0, 0, 0, 0);
        emit_status("stopped", "Rnetch stopped.");
        rnetch::socks5::close_logger();
        g_logger.close();
    }
} // namespace rnetch
