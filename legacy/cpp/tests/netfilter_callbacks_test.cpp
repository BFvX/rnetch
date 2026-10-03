// Standalone integration test: link tcp_relay.cpp, udp_relay.cpp and socks5.cpp
// with /D_NFAPI_STATIC_LIB, proxy_process.cpp, Ws2_32.lib and Iphlpapi.lib.
// No SDK DLL or driver is used.
#ifndef _NFAPI_STATIC_LIB
#define _NFAPI_STATIC_LIB
#endif
#include "../src/rnetch.cpp"
#include <future>

namespace test {

using Socket = rnetch::utils::SocketHandle;
using Clock = std::chrono::steady_clock;
using Bytes = std::vector<unsigned char>;
constexpr DWORD game_pid = 0x7fff0042;

struct StubState {
    std::mutex mutex;
    std::condition_variable wake;
    std::map<ENDPOINT_ID, NF_TCP_CONN_INFO> completed;
    std::map<DWORD, std::wstring> processes;
    std::vector<NF_RULE_EX> rules;
    std::atomic<unsigned> closed{0};
    std::atomic<unsigned> disabled{0};
    std::atomic<unsigned> posted_tcp{0};
    std::atomic<unsigned> driver_calls{0};
    std::atomic<unsigned> sdk_lifecycle_calls{0};
} state;

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void check(int value, const char* message) {
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

sockaddr_storage address(bool mapped, const char* ip, unsigned short port = 0) {
    sockaddr_storage result{};
    if (mapped) {
        sockaddr_in6 value{};
        value.sin6_family = AF_INET6;
        value.sin6_port = htons(port);
        const std::string text = std::string("::ffff:") + ip;
        require(InetPtonA(AF_INET6, text.c_str(), &value.sin6_addr) == 1, "Parse mapped test address");
        memcpy(&result, &value, sizeof(value));
    } else {
        sockaddr_in value{};
        value.sin_family = AF_INET;
        value.sin_port = htons(port);
        require(InetPtonA(AF_INET, ip, &value.sin_addr) == 1, "Parse test IPv4 address");
        memcpy(&result, &value, sizeof(value));
    }
    return result;
}

int address_length(const sockaddr_storage& value) {
    return value.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
}

unsigned short port(const sockaddr_storage& value) {
    unsigned short result = 0;
    memcpy(&result, reinterpret_cast<const unsigned char*>(&value) + 2, sizeof(result));
    return ntohs(result);
}

sockaddr_storage local_address(SOCKET socket) {
    sockaddr_storage result{};
    int length = sizeof(result);
    check(getsockname(socket, reinterpret_cast<sockaddr*>(&result), &length), "Read local test address");
    return result;
}

void blocking_timeout(SOCKET socket) {
    u_long nonblocking = 0;
    check(ioctlsocket(socket, FIONBIO, &nonblocking), "Set blocking test socket");
    DWORD timeout = 2000;
    for (int option : {SO_RCVTIMEO, SO_SNDTIMEO}) {
        check(setsockopt(socket, SOL_SOCKET, option, reinterpret_cast<const char*>(&timeout),
            sizeof(timeout)), "Set test socket timeout");
    }
}

Socket bound_application(bool mapped) {
    auto local = address(mapped, "127.0.0.1");
    Socket socket(WSASocketW(local.ss_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED));
    require(socket.get() != INVALID_SOCKET, "Create original application socket");
    if (mapped) {
        DWORD v6_only = 0;
        check(setsockopt(socket.get(), IPPROTO_IPV6, IPV6_V6ONLY,
            reinterpret_cast<const char*>(&v6_only), sizeof(v6_only)), "Set application dual-stack mode");
    }
    blocking_timeout(socket.get());
    check(bind(socket.get(), reinterpret_cast<const sockaddr*>(&local), address_length(local)),
        "Bind original application source port");
    return socket;
}

void write_bytes(SOCKET socket, const Bytes& bytes) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        int count = send(socket, reinterpret_cast<const char*>(bytes.data() + offset),
            static_cast<int>(bytes.size() - offset), 0);
        check(count, "Write mock SOCKS data");
        require(count > 0, "Mock write made no progress");
        offset += static_cast<size_t>(count);
    }
}

Bytes read_exact(SOCKET socket, size_t size) {
    Bytes bytes(size);
    size_t offset = 0;
    while (offset < size) {
        int count = recv(socket, reinterpret_cast<char*>(bytes.data() + offset),
            static_cast<int>(size - offset), 0);
        check(count, "Read exact mock SOCKS data");
        require(count > 0, "Unexpected mock SOCKS EOF");
        offset += static_cast<size_t>(count);
    }
    return bytes;
}

Bytes read_to_eof(SOCKET socket) {
    Bytes bytes;
    std::array<unsigned char, 16384> chunk{};
    for (;;) {
        int count = recv(socket, reinterpret_cast<char*>(chunk.data()), static_cast<int>(chunk.size()), 0);
        check(count, "Read mock data through EOF");
        if (!count) return bytes;
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + count);
    }
}

template<class Predicate>
void wait_for(Predicate predicate, const char* message, std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
    const auto deadline = Clock::now() + timeout;
    while (!predicate()) {
        require(Clock::now() < deadline, message);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

class MockServer {
public:
    template<class Work>
    explicit MockServer(Work work) : listener_(rnetch::tcp_relay::listen(address(false, "127.0.0.1"))) {
        worker_ = std::async(std::launch::async, [this, work] {
            const auto deadline = Clock::now() + std::chrono::seconds(3);
            auto socket = rnetch::tcp_relay::accept(listener_.socket.get(), address(false, "0.0.0.0"), [&] {
                return stopped_.load() || Clock::now() >= deadline;
            });
            require(socket.get() != INVALID_SOCKET, "Mock SOCKS server was not connected");
            blocking_timeout(socket.get());
            work(socket.get());
        });
    }
    ~MockServer() {
        stopped_ = true;
        if (worker_.valid()) worker_.wait();
    }
    std::string port_string() const { return std::to_string(port(listener_.address)); }
    void finish() { worker_.get(); }
private:
    rnetch::tcp_relay::Listener listener_;
    std::atomic_bool stopped_{false};
    std::future<void> worker_;
};

struct Harness {
    explicit Harness(const std::string& proxy_port = "1") {
        g_stop_flag = true;
        stop_tcp_workers();
        rnetch::udp_relay::stop();
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.completed.clear();
            state.rules.clear();
            state.processes = {{game_pid, L"C:\\Games\\Battlefield 6\\bf6.exe"}};
        }
        state.closed = 0;
        state.disabled = 0;
        state.posted_tcp = 0;
        reset_metrics();
        g_socks5_host = "127.0.0.1";
        g_socks5_port = proxy_port;
        g_socks5_user.clear();
        g_socks5_pass.clear();
        g_rules = {{{L"bf6.exe"}, true, true}};
        g_stop_flag = false;
    }
    ~Harness() {
        g_stop_flag = true;
        stop_tcp_workers();
        rnetch::udp_relay::stop();
        g_rules.clear();
    }
};

NF_TCP_CONN_INFO connection(SOCKET application, bool mapped) {
    NF_TCP_CONN_INFO info{};
    info.filteringFlag = NF_INDICATE_CONNECT_REQUESTS;
    info.processId = game_pid;
    info.direction = NF_D_OUT;
    info.ip_family = mapped ? AF_INET6 : AF_INET;
    const auto local = local_address(application);
    const auto remote = address(mapped, "203.0.113.9", 443);
    memcpy(info.localAddress, &local, static_cast<size_t>(address_length(local)));
    memcpy(info.remoteAddress, &remote, static_cast<size_t>(address_length(remote)));
    return info;
}

NF_TCP_CONN_INFO completed(ENDPOINT_ID id) {
    std::unique_lock<std::mutex> lock(state.mutex);
    require(state.wake.wait_for(lock, std::chrono::seconds(3), [&] { return state.completed.count(id) != 0; }),
        "Timed out waiting for asynchronous TCP completion");
    return state.completed.at(id);
}

void wait_finished(ENDPOINT_ID id, std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
    wait_for([&] {
        std::lock_guard<std::mutex> lock(g_tcp_context_lock);
        auto it = g_tcp_context.find(id);
        return it == g_tcp_context.end() || it->second->finished.load();
    }, "TCP worker did not finish promptly", timeout);
    reap_tcp_workers();
}

void redirects_without_connected_or_data_callbacks(bool mapped) {
    const ENDPOINT_ID id = mapped ? 102 : 101;
    const Bytes greeting{'s', 'e', 'r', 'v', 'e', 'r', '-', 'f', 'i', 'r', 's', 't'};
    Bytes upload(120000);
    Bytes response(100000);
    for (size_t i = 0; i < upload.size(); ++i) upload[i] = static_cast<unsigned char>(i % 251);
    for (size_t i = 0; i < response.size(); ++i) response[i] = static_cast<unsigned char>(i % 239);
    MockServer server([&](SOCKET socket) {
        require(read_exact(socket, 3) == Bytes({5, 1, 0}), "Worker must send SOCKS5 greeting");
        write_bytes(socket, {5, 0});
        require(read_exact(socket, 10) == Bytes({5, 1, 0, 1, 203, 0, 113, 9, 1, 187}),
            "SOCKS CONNECT must preserve destination and normalize mapped IPv4");
        Bytes reply{5, 0, 0, 1, 127, 0, 0, 1, 0, 0};
        reply.insert(reply.end(), greeting.begin(), greeting.end());
        write_bytes(socket, reply); // Coalesce server-first data with the SOCKS reply.
        require(read_to_eof(socket) == upload, "Receive upload and client half-close at SOCKS server");
        write_bytes(socket, response);
        check(shutdown(socket, SD_SEND), "Half-close mock SOCKS response");
    });
    Harness harness(server.port_string());
    auto application = bound_application(mapped);
    auto info = connection(application.get(), mapped);
    const auto called = Clock::now();
    tcpConnectRequest(id, &info);
    require(Clock::now() - called < std::chrono::milliseconds(100), "Connect callback must not perform network I/O");
    require(info.filteringFlag == NF_PEND_CONNECT_REQUEST, "Selected TCP callback must immediately pend");
    auto redirect = completed(id);
    require(redirect.filteringFlag == NF_ALLOW, "Redirected connection must use NF_ALLOW");
    require(redirect.processId == GetCurrentProcessId(), "Redirected connection must carry local proxy PID");
    require(redirect.ip_family == info.ip_family, "Redirect must preserve SDK address family");
    sockaddr_storage target{};
    require(copy_sockaddr(redirect.remoteAddress, target), "Decode local redirect target");
    require(target.ss_family == info.ip_family && port(target) != 0, "Local redirect must preserve sockaddr family");
    require(is_private_or_local_address(target), "Redirect target must remain local");
    check(connect(application.get(), reinterpret_cast<const sockaddr*>(&target), address_length(target)),
        "Connect original application source socket to redirect");
    // Deliberately never call tcpConnected/tcpSend/tcpReceive.
    require(read_exact(application.get(), greeting.size()) == greeting, "Relay must preserve coalesced server-first bytes");
    write_bytes(application.get(), upload);
    check(shutdown(application.get(), SD_SEND), "Half-close redirected application upload");
    require(read_to_eof(application.get()) == response, "Relay must drain final 100 KB after upload EOF");
    server.finish();
    wait_finished(id);
    require(state.closed == 0, "Normal TCP EOF must not invoke nf_tcpClose");
    require(state.posted_tcp == 0, "Redirect relay must not inject SDK TCP data");
    require(g_tcp_up_bytes == upload.size(), "Integration upload byte count must match");
    require(g_tcp_down_bytes == response.size() + greeting.size(), "Integration download byte count must match");
}

void cancels_pending_handshake(bool close_callback) {
    const ENDPOINT_ID id = close_callback ? 201 : 202;
    std::promise<void> greeting_received;
    auto greeting_ready = greeting_received.get_future();
    MockServer server([&](SOCKET socket) {
        require(read_exact(socket, 3) == Bytes({5, 1, 0}), "Receive hanging SOCKS greeting");
        greeting_received.set_value();
        unsigned char byte = 0;
        int count = recv(socket, reinterpret_cast<char*>(&byte), 1, 0);
        require(count == 0 || (count == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET),
            "Cancellation must close pending SOCKS transport");
    });
    Harness harness(server.port_string());
    auto application = bound_application(false);
    auto info = connection(application.get(), false);
    const auto called = Clock::now();
    tcpConnectRequest(id, &info);
    require(Clock::now() - called < std::chrono::milliseconds(100), "Pending SOCKS handshake must not block connect callback");
    require(info.filteringFlag == NF_PEND_CONNECT_REQUEST, "Pending handshake must leave SDK connection pended");
    require(greeting_ready.wait_for(std::chrono::seconds(2)) == std::future_status::ready,
        "Worker must reach pending handshake");
    greeting_ready.get();
    const auto cancelled = Clock::now();
    if (close_callback) {
        tcpClosed(id, &info);
        require(Clock::now() - cancelled < std::chrono::milliseconds(100), "tcpClosed callback must not join worker");
        wait_finished(id, std::chrono::milliseconds(750));
        require(state.closed == 0, "SDK-closed connection must not be closed again");
    } else {
        g_stop_flag = true;
        stop_tcp_workers();
        require(state.closed == 1, "Stop must abort the outstanding pended SDK connection exactly once");
    }
    require(Clock::now() - cancelled < std::chrono::milliseconds(750), "Cancellation must interrupt SOCKS handshake promptly");
    server.finish();
    std::lock_guard<std::mutex> lock(state.mutex);
    require(state.completed.empty(), "Cancelled handshake must not later complete or redirect the SDK connection");
}

void compiles_process_rules_and_bypasses_self() {
    Harness harness;
    const std::vector<rnetch::Rule> configured{
        {{L"C:/Games/Battlefield 6/BF?.EXE", L"bf?.exe"}, true, true},
        {{L"ignored.exe"}, false, false}
    };
    const auto rules = compile_driver_rules(configured);
    require(rules.size() == 2, "Equivalent widened process masks must be deduplicated per protocol");
    for (const auto& rule : rules) {
        wchar_t process_name[MAX_PATH]{};
        memcpy(process_name, rule.processName, sizeof(process_name));
        require(std::wstring(process_name) == L"bf*.exe", "Driver process mask must be normalized basename");
        require(rule.direction == NF_D_OUT && rule.ip_family == 0, "Process rule must cover outgoing IPv4 and IPv6");
        if (rule.protocol == IPPROTO_TCP) {
            require(rule.filteringFlag == NF_INDICATE_CONNECT_REQUESTS, "TCP must only indicate connect requests");
            require((rule.filteringFlag & (NF_FILTER | NF_OFFLINE)) == 0, "TCP must not select offline data filtering");
        } else {
            require(rule.protocol == IPPROTO_UDP && rule.filteringFlag == NF_FILTER, "UDP must retain datagram filtering");
        }
    }
    require(!should_proxy(GetCurrentProcessId(), true), "Relay process must bypass TCP selection");
    require(!should_proxy(GetCurrentProcessId(), false), "Relay process must bypass UDP selection");
    require(should_proxy(game_pid, true), "Matching game process must be selected");
    g_rules = {{{L"C:/Other/*.exe"}, true, true}};
    require(!should_proxy(game_pid, true), "Exact process path check must reject driver-mask false positives");
    auto application = bound_application(false);
    auto info = connection(application.get(), false);
    info.processId = GetCurrentProcessId();
    tcpConnectRequest(301, &info);
    require(info.filteringFlag == NF_ALLOW && state.disabled == 1, "Self connection callback must allow and disable filtering");
    require(g_tcp_context.empty(), "Self bypass must create no forwarding worker");
    info = connection(application.get(), false);
    auto private_target = address(false, "192.168.1.1", 443);
    memcpy(info.remoteAddress, &private_target, sizeof(sockaddr_in));
    tcpConnectRequest(302, &info);
    require(info.filteringFlag == NF_ALLOW && state.disabled == 2, "Private destination must bypass forwarding");
}

class PipeInput {
public:
    PipeInput() : previous_(GetStdHandle(STD_INPUT_HANDLE)) {
        require(CreatePipe(&read_, &write_, nullptr, 0) != FALSE, "Create empty test stdin pipe");
        if (!SetStdHandle(STD_INPUT_HANDLE, read_)) {
            CloseHandle(read_);
            CloseHandle(write_);
            throw std::runtime_error("Replace test process stdin handle");
        }
    }
    ~PipeInput() {
        // Restore the test process handle before releasing its temporary pipe.
        SetStdHandle(STD_INPUT_HANDLE, previous_);
        CloseHandle(read_);
        if (write_) CloseHandle(write_);
    }
    void release_waiter() {
        // A failed assertion must not leave std::async's destructor waiting for
        // an implementation that regressed to a blocking pipe read.
        const char newline = '\n';
        DWORD written = 0;
        WriteFile(write_, &newline, 1, &written, nullptr);
        CloseHandle(write_);
        write_ = nullptr;
    }
private:
    HANDLE previous_;
    HANDLE read_ = nullptr;
    HANDLE write_ = nullptr;
};

void callback_failure_interrupts_empty_stdin_wait() {
    Harness harness;
    const HANDLE original_input = GetStdHandle(STD_INPUT_HANDLE);
    bool was_waiting = false;
    bool returned_promptly = false;
    Clock::duration elapsed{};
    {
        PipeInput input;
        std::promise<void> started;
        auto ready = started.get_future();
        auto waiter = std::async(std::launch::async, [&] {
            started.set_value();
            rnetch::wait_for_stop();
        });
        ready.wait();
        // Keep the write end open and send no bytes: this is an idle input
        // source, not EOF. The owner must still be waiting before the failure.
        was_waiting = waiter.wait_for(std::chrono::milliseconds(30)) == std::future_status::timeout;
        const auto failed = Clock::now();
        callback([] { throw std::runtime_error("Injected SDK callback failure"); });
        returned_promptly = waiter.wait_for(std::chrono::milliseconds(150)) == std::future_status::ready;
        elapsed = Clock::now() - failed;
        if (!returned_promptly) input.release_waiter();
        waiter.get();
    }
    require(GetStdHandle(STD_INPUT_HANDLE) == original_input, "Restore original test stdin handle");
    require(was_waiting, "Open empty stdin pipe must keep owner waiting before callback failure");
    require(g_stop_flag.load(), "Callback exception must request internal stop");
    require(returned_promptly && elapsed < std::chrono::milliseconds(150),
        "Callback failure must interrupt idle stdin wait within 150 ms");
}

} // namespace test

extern "C" {
NF_STATUS NFAPI_CC nf_init(const char*, NF_EventHandler*) {
    ++test::state.sdk_lifecycle_calls;
    return NF_STATUS_SUCCESS;
}
void NFAPI_CC nf_free() { ++test::state.sdk_lifecycle_calls; }
NF_STATUS NFAPI_CC nf_deleteRules() { return NF_STATUS_SUCCESS; }
NF_STATUS NFAPI_CC nf_addRuleEx(PNF_RULE_EX rule, int) {
    std::lock_guard<std::mutex> lock(test::state.mutex);
    test::state.rules.push_back(*rule);
    return NF_STATUS_SUCCESS;
}
NF_STATUS NFAPI_CC nf_completeTCPConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO info) {
    {
        std::lock_guard<std::mutex> lock(test::state.mutex);
        test::state.completed[id] = *info;
    }
    test::state.wake.notify_all();
    return NF_STATUS_SUCCESS;
}
NF_STATUS NFAPI_CC nf_tcpClose(ENDPOINT_ID) {
    ++test::state.closed;
    return NF_STATUS_SUCCESS;
}
NF_STATUS NFAPI_CC nf_tcpDisableFiltering(ENDPOINT_ID) {
    ++test::state.disabled;
    return NF_STATUS_SUCCESS;
}
NF_STATUS NFAPI_CC nf_tcpPostSend(ENDPOINT_ID, const char*, int) {
    ++test::state.posted_tcp;
    return NF_STATUS_SUCCESS;
}
NF_STATUS NFAPI_CC nf_tcpPostReceive(ENDPOINT_ID, const char*, int) {
    ++test::state.posted_tcp;
    return NF_STATUS_SUCCESS;
}
BOOL NFAPI_CC nf_getProcessNameW(DWORD process_id, wchar_t* buffer, DWORD length) {
    std::lock_guard<std::mutex> lock(test::state.mutex);
    const auto it = test::state.processes.find(process_id);
    if (it == test::state.processes.end() || it->second.size() >= length) return FALSE;
    std::copy(it->second.begin(), it->second.end(), buffer);
    buffer[it->second.size()] = L'\0';
    return TRUE;
}
NF_STATUS NFAPI_CC nf_udpPostSend(ENDPOINT_ID, const unsigned char*, const char*, int, PNF_UDP_OPTIONS) {
    return NF_STATUS_SUCCESS;
}
NF_STATUS NFAPI_CC nf_udpPostReceive(ENDPOINT_ID, const unsigned char*, const char*, int, PNF_UDP_OPTIONS) {
    return NF_STATUS_SUCCESS;
}
NF_STATUS NFAPI_CC nf_udpDisableFiltering(ENDPOINT_ID) { return NF_STATUS_SUCCESS; }
}

namespace rnetch::driver {
bool install() { ++test::state.driver_calls; return true; }
bool start() { ++test::state.driver_calls; return true; }
bool stop() { ++test::state.driver_calls; return true; }
}

int main() {
    try {
        test::Winsock winsock;
        test::redirects_without_connected_or_data_callbacks(false);
        test::redirects_without_connected_or_data_callbacks(true);
        test::cancels_pending_handshake(true);
        test::cancels_pending_handshake(false);
        test::compiles_process_rules_and_bypasses_self();
        test::callback_failure_interrupts_empty_stdin_wait();
        test::require(test::state.driver_calls == 0 && test::state.sdk_lifecycle_calls == 0,
            "Integration tests must not start or initialize any driver");
        std::cout << "6 NetFilter callback integration tests passed (mock SDK; loopback only)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "NetFilter callback integration test failed: " << error.what() << '\n';
        return 1;
    }
}
