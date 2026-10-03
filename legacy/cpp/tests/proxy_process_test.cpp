#include "../src/proxy_process.h"
#include <ws2tcpip.h>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void check(bool value, const char* message) {
    if (!value) {
        const DWORD windows_error = GetLastError();
        const int winsock_error = WSAGetLastError();
        throw std::runtime_error(std::string(message) + " (Windows " + std::to_string(windows_error)
            + ", Winsock " + std::to_string(winsock_error) + ")");
    }
}

struct Socket {
    SOCKET value;
    explicit Socket(SOCKET socket) : value(socket) { check(value != INVALID_SOCKET, "Create socket"); }
    ~Socket() { closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
};

struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value) CloseHandle(value); }
};

struct Child {
    PROCESS_INFORMATION info{};
    explicit Child(PROCESS_INFORMATION value) : info(value) {}
    ~Child() {
        if (WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT) {
            TerminateProcess(info.hProcess, 1);
            WaitForSingleObject(info.hProcess, 5000);
        }
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
    }
    void wait() const {
        check(WaitForSingleObject(info.hProcess, 10000) == WAIT_OBJECT_0, "Child process deadline");
        DWORD exit_code = 1;
        check(GetExitCodeProcess(info.hProcess, &exit_code), "Read child exit code");
        if (exit_code != 0) throw std::runtime_error("Child test exited with code " + std::to_string(exit_code));
    }
};

Child spawn(const wchar_t* mode, HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE)) {
    wchar_t executable[32768]{};
    check(GetModuleFileNameW(nullptr, executable, 32768) != 0, "Find test executable");
    std::wstring command = L"\"" + std::wstring(executable) + L"\" " + mode;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = output;
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION info{};
    check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info), "Start isolated test process");
    return Child(info);
}

unsigned short listen_on(SOCKET socket, int family, bool wildcard = false) {
    sockaddr_in6 storage{};
    int length = 0;
    if (family == AF_INET) {
        auto* address = reinterpret_cast<sockaddr_in*>(&storage);
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(sockaddr_in);
    } else {
        storage.sin6_family = AF_INET6;
        storage.sin6_addr = wildcard ? in6addr_any : in6addr_loopback;
        length = sizeof(storage);
    }
    check(bind(socket, reinterpret_cast<sockaddr*>(&storage), length) == 0, "Bind loopback socket");
    check(getsockname(socket, reinterpret_cast<sockaddr*>(&storage), &length) == 0, "Get loopback port");
    check(listen(socket, 1) == 0, "Listen on loopback");
    return ntohs(storage.sin6_port);
}

void connect_to(SOCKET socket, int family, unsigned short port, bool mapped = false) {
    sockaddr_in6 storage{};
    storage.sin6_port = htons(port);
    int length = 0;
    if (family == AF_INET) {
        auto* address = reinterpret_cast<sockaddr_in*>(&storage);
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(sockaddr_in);
    } else {
        storage.sin6_family = AF_INET6;
        check(inet_pton(AF_INET6, mapped ? "::ffff:127.0.0.1" : "::1", &storage.sin6_addr) == 1, "Parse IPv6 loopback");
        length = sizeof(storage);
    }
    check(::connect(socket, reinterpret_cast<sockaddr*>(&storage), length) == 0, "Connect loopback client");
}

void local_case(const std::string& mode) {
    check(!rnetch::proxy_process::is_proxy(GetCurrentProcessId()), "Fresh PID must not be exempt");
    check(!rnetch::proxy_process::register_connection(INVALID_SOCKET), "Invalid socket must fail closed");
    const int server_family = mode == "ipv4" || mode == "mapped-client" ? AF_INET : AF_INET6;
    const int client_family = mode == "ipv4" || mode == "mapped-server" ? AF_INET : AF_INET6;
    Socket listener(socket(server_family, SOCK_STREAM, IPPROTO_TCP));
    if (mode == "mapped-server") {
        const DWORD disabled = 0;
        check(setsockopt(listener.value, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&disabled), sizeof(disabled)) == 0, "Enable dual-stack listener");
    }
    const auto port = listen_on(listener.value, server_family, mode == "mapped-server");
    Socket client(socket(client_family, SOCK_STREAM, IPPROTO_TCP));
    if (mode == "mapped-client") {
        const DWORD disabled = 0;
        check(setsockopt(client.value, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&disabled), sizeof(disabled)) == 0, "Enable mapped client");
    }
    connect_to(client.value, client_family, port, mode == "mapped-client");
    // Query while the server-side connection is still in the accept queue: no
    // application handshake/upstream traffic may be sent before registration.
    check(rnetch::proxy_process::register_connection(client.value), "Register reverse-side process");
    check(rnetch::proxy_process::is_proxy(GetCurrentProcessId()), "Local proxy owner was not detected");
    check(rnetch::proxy_process::is_proxy(GetCurrentProcessId()), "Live process creation time must revalidate");
    check(!rnetch::proxy_process::is_proxy(0), "Unregistered PID must not inherit an exemption");
}

void child_server() {
    Socket listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    const DWORD port = listen_on(listener.value, AF_INET);
    DWORD written = 0;
    check(WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &port, sizeof(port), &written, nullptr) && written == sizeof(port), "Announce child proxy port");
    fd_set ready;
    FD_ZERO(&ready);
    FD_SET(listener.value, &ready);
    timeval wait{5, 0};
    check(select(0, &ready, nullptr, nullptr, &wait) == 1, "Child accept timeout");
    Socket peer(accept(listener.value, nullptr, nullptr));
    const DWORD timeout = 5000;
    check(setsockopt(peer.value, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0, "Child receive timeout");
    char stop = 0;
    check(recv(peer.value, &stop, 1, 0) == 1, "Child stop signal");
}

void separate_process_lifetime() {
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    Handle reader, writer;
    check(CreatePipe(&reader.value, &writer.value, &security, 0), "Create readiness pipe");
    check(SetHandleInformation(reader.value, HANDLE_FLAG_INHERIT, 0), "Prevent child inheriting reader");
    auto child = spawn(L"child-server", writer.value);
    CloseHandle(writer.value);
    writer.value = nullptr;
    DWORD available = 0;
    const ULONGLONG until = GetTickCount64() + 5000;
    do {
        check(PeekNamedPipe(reader.value, nullptr, 0, nullptr, &available, nullptr), "Read child readiness");
        if (available >= sizeof(DWORD)) break;
        check(GetTickCount64() < until, "Child readiness deadline");
        Sleep(10);
    } while (true);
    DWORD port = 0, read = 0;
    check(ReadFile(reader.value, &port, sizeof(port), &read, nullptr) && read == sizeof(port), "Read child port");
    Socket client(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    connect_to(client.value, AF_INET, static_cast<unsigned short>(port));
    check(rnetch::proxy_process::register_connection(client.value), "Register separate proxy process");
    check(rnetch::proxy_process::is_proxy(child.info.dwProcessId), "Must identify server PID, not client PID");
    check(!rnetch::proxy_process::is_proxy(GetCurrentProcessId()), "Client process must remain eligible for interception");
    check(send(client.value, "x", 1, 0) == 1, "Stop child proxy");
    child.wait();
    check(!rnetch::proxy_process::is_proxy(child.info.dwProcessId), "Exited process must lose the cached exemption");
}
} // namespace

int main(int argc, char** argv) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
    int result = 0;
    try {
        if (argc == 2) {
            if (std::string(argv[1]) == "child-server") child_server();
            else local_case(argv[1]);
        } else {
            int passed = 0;
            int failed = 0;
            for (const auto* mode : {L"ipv4", L"ipv6", L"mapped-server", L"mapped-client"}) {
                try {
                    auto child = spawn(mode);
                    child.wait();
                    ++passed;
                    std::wcout << L"PASS: proxy PID lookup " << mode << L'\n';
                } catch (const std::exception& error) {
                    ++failed;
                    std::wcerr << L"FAIL: proxy PID lookup " << mode << L'\n';
                    std::cerr << error.what() << '\n';
                }
            }
            try {
                separate_process_lifetime();
                ++passed;
                std::cout << "PASS: reverse server PID and expired process identity\n";
            } catch (const std::exception& error) {
                ++failed;
                std::cerr << "FAIL: reverse server PID and expired process identity: " << error.what() << '\n';
            }
            std::cout << passed << "/5 proxy-process tests passed, " << failed << " failed (loopback only, no driver)\n";
            result = failed == 0 ? 0 : 1;
        }
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        result = 1;
    }
    WSACleanup();
    return result;
}
