#include "proxy_process.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace rnetch::proxy_process {
namespace {
std::mutex registry_mutex;
std::unordered_map<DWORD, std::uint64_t> registry;

bool failure(DWORD error) {
    WSASetLastError(static_cast<int>(error));
    return false;
}

struct ProcessHandle {
    HANDLE value;
    ~ProcessHandle() {
        const DWORD error = GetLastError();
        if (value) CloseHandle(value);
        SetLastError(error);
    }
};

bool process_identity(DWORD process_id, std::uint64_t& identity) {
    ProcessHandle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id)};
    if (!process.value) return false;
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(process.value, &exit_code)) return false;
    if (exit_code != STILL_ACTIVE) return failure(ERROR_INVALID_PARAMETER);
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process.value, &created, &exited, &kernel, &user)) return false;
    identity = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    return true;
}

struct Endpoint {
    USHORT family = 0;
    USHORT port = 0; // Network byte order, as in sockaddr and the table's low 16 bits.
    ULONG scope = 0;
    std::array<unsigned char, 16> address{};

    void normalize() {
        if (family != AF_INET6) return;
        static constexpr unsigned char mapped_prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
        if (std::memcmp(address.data(), mapped_prefix, sizeof(mapped_prefix)) != 0) return;
        std::array<unsigned char, 16> ipv4{};
        std::memcpy(ipv4.data(), address.data() + 12, 4);
        address = ipv4;
        family = AF_INET;
        scope = 0;
    }
    bool operator==(const Endpoint& other) const {
        return family == other.family && port == other.port && scope == other.scope && address == other.address;
    }
};

Endpoint ipv4(DWORD address, DWORD port) {
    Endpoint endpoint;
    endpoint.family = AF_INET;
    endpoint.port = static_cast<USHORT>(port);
    std::memcpy(endpoint.address.data(), &address, 4);
    return endpoint;
}

Endpoint ipv6(const UCHAR* address, DWORD port, DWORD scope) {
    Endpoint endpoint;
    endpoint.family = AF_INET6;
    endpoint.port = static_cast<USHORT>(port);
    endpoint.scope = scope;
    std::memcpy(endpoint.address.data(), address, 16);
    endpoint.normalize();
    return endpoint;
}

bool socket_endpoint(SOCKET socket, bool peer, Endpoint& endpoint) {
    sockaddr_storage storage{};
    int length = sizeof(storage);
    const int result = peer ? getpeername(socket, reinterpret_cast<sockaddr*>(&storage), &length)
        : getsockname(socket, reinterpret_cast<sockaddr*>(&storage), &length);
    if (result != 0) return false;
    if (storage.ss_family == AF_INET && length >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto& address = reinterpret_cast<const sockaddr_in&>(storage);
        endpoint = ipv4(address.sin_addr.s_addr, address.sin_port);
        return true;
    }
    if (storage.ss_family == AF_INET6 && length >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto& address = reinterpret_cast<const sockaddr_in6&>(storage);
        endpoint = ipv6(address.sin6_addr.u.Byte, address.sin6_port, address.sin6_scope_id);
        return true;
    }
    return failure(WSAEAFNOSUPPORT);
}

bool find_owner(ULONG family, const Endpoint& server, const Endpoint& client, DWORD& owner, bool& found) {
    DWORD length = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &length, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR && result != ERROR_INSUFFICIENT_BUFFER) return failure(result);
    for (int attempt = 0; attempt < 4; ++attempt) {
        if (length > 32 * 1024 * 1024) return failure(ERROR_NOT_ENOUGH_MEMORY);
        // DWORD-aligned API storage; memcpy individual rows to avoid assuming
        // C++ object lifetime or packing beyond the actual SDK table offsets.
        std::vector<std::uint64_t> table((static_cast<size_t>(length) + 7) / 8 + 1);
        const auto capacity = table.size() * sizeof(table[0]);
        result = GetExtendedTcpTable(table.data(), &length, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (result == ERROR_INSUFFICIENT_BUFFER) continue;
        if (result != NO_ERROR) return failure(result);
        const size_t offset = family == AF_INET ? offsetof(MIB_TCPTABLE_OWNER_PID, table) : offsetof(MIB_TCP6TABLE_OWNER_PID, table);
        const size_t row_size = family == AF_INET ? sizeof(MIB_TCPROW_OWNER_PID) : sizeof(MIB_TCP6ROW_OWNER_PID);
        if (length < offset || length > capacity) return failure(ERROR_INVALID_DATA);
        DWORD count = 0;
        std::memcpy(&count, table.data(), sizeof(count));
        if (count > (length - offset) / row_size) return failure(ERROR_INVALID_DATA);
        const auto* bytes = reinterpret_cast<const unsigned char*>(table.data()) + offset;
        for (DWORD index = 0; index < count; ++index) {
            Endpoint local, remote;
            DWORD process_id = 0;
            if (family == AF_INET) {
                MIB_TCPROW_OWNER_PID row{};
                std::memcpy(&row, bytes + static_cast<size_t>(index) * row_size, sizeof(row));
                local = ipv4(row.dwLocalAddr, row.dwLocalPort);
                remote = ipv4(row.dwRemoteAddr, row.dwRemotePort);
                process_id = row.dwOwningPid;
            } else {
                MIB_TCP6ROW_OWNER_PID row{};
                std::memcpy(&row, bytes + static_cast<size_t>(index) * row_size, sizeof(row));
                local = ipv6(row.ucLocalAddr, row.dwLocalPort, row.dwLocalScopeId);
                remote = ipv6(row.ucRemoteAddr, row.dwRemotePort, row.dwRemoteScopeId);
                process_id = row.dwOwningPid;
            }
            if (!(local == server && remote == client)) continue;
            if (found && owner != process_id) return failure(ERROR_INVALID_DATA);
            found = true;
            owner = process_id;
        }
        return true;
    }
    return failure(ERROR_RETRY);
}
} // namespace

bool register_connection(SOCKET socket) noexcept {
    try {
        int type = 0;
        int length = sizeof(type);
        if (getsockopt(socket, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &length) != 0) return false;
        if (type != SOCK_STREAM) return failure(WSAEPROTOTYPE);
        Endpoint client, server;
        if (!socket_endpoint(socket, false, client) || !socket_endpoint(socket, true, server)) return false;
        DWORD owner = 0;
        bool found = false;
        if (server.family == AF_INET && !find_owner(AF_INET, server, client, owner, found)) return false;
        // IPv4 peers of a dual-stack listener can appear only as mapped IPv6 rows.
        if (!found && !find_owner(AF_INET6, server, client, owner, found)) return false;
        if (!found) return true; // Remote SOCKS server; nothing local to exempt.
        std::uint64_t identity = 0;
        if (!process_identity(owner, identity)) return false;
        std::lock_guard<std::mutex> lock(registry_mutex);
        registry[owner] = identity;
        return true;
    } catch (...) {
        return failure(ERROR_NOT_ENOUGH_MEMORY);
    }
}

bool is_proxy(DWORD process_id) noexcept {
    bool known = false;
    try {
        std::uint64_t expected = 0;
        {
            std::lock_guard<std::mutex> lock(registry_mutex);
            const auto entry = registry.find(process_id);
            if (entry == registry.end()) return false;
            expected = entry->second;
            known = true;
        }
        std::uint64_t current = 0;
        if (process_identity(process_id, current)) {
            if (current == expected) return true;
        } else if (GetLastError() != ERROR_INVALID_PARAMETER) {
            // Preserve a known daemon's exemption if permissions temporarily
            // prevent inspection. An accessible reused PID is still revalidated.
            return true;
        }
        std::lock_guard<std::mutex> lock(registry_mutex);
        const auto entry = registry.find(process_id);
        if (entry != registry.end() && entry->second == expected) registry.erase(entry);
        return false;
    } catch (...) { return known; }
}
} // namespace rnetch::proxy_process
