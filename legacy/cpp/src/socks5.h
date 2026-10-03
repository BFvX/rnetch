#pragma once
#ifndef SOCKS5_H
#define SOCKS5_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <functional>

namespace rnetch {
    namespace socks5 {
        using CancelCheck = std::function<bool()>;
        void init_logger(const std::string& path);
        void close_logger();
        // Connection (including DNS) and each handshake/command have a five-second
        // deadline. Cancellation is polled at most every 100 ms and sets WSAEINTR.
        // All helpers return the connected socket to blocking mode; data workers
        // should use their own polling/read timeouts and shutdown for cancellation.
        SOCKET connect(const std::string& host, const std::string& port, const CancelCheck& cancelled = {});
        bool handshake(SOCKET client, const std::string& username, const std::string& password, const CancelCheck& cancelled = {});
        bool udp_associate(SOCKET client, SOCKADDR_IN6& remote_addr, const CancelCheck& cancelled = {});
        bool connect_remote(SOCKET client, sockaddr* remote_addr, const CancelCheck& cancelled = {});
    } // namespace socks5
} // namespace rnetch

#endif // SOCKS5_H
