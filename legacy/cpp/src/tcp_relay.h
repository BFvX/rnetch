#pragma once
#ifndef RNETCH_TCP_RELAY_H
#define RNETCH_TCP_RELAY_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "utils/socket.h"
#include <ws2tcpip.h>
#include <atomic>
#include <functional>

namespace rnetch::tcp_relay {

struct Listener {
    utils::SocketHandle socket;
    sockaddr_storage address{};
};

// The caller retains its Winsock startup guard until every worker has joined.
// Bind the original local IP (loopback if unspecified), with an ephemeral port.
Listener listen(const sockaddr_storage& original_local);

// Returns INVALID_SOCKET on cancellation; timeout/socket failures throw.
// A zero original source port or unspecified IP is an unconstrained field.
utils::SocketHandle accept(SOCKET listener, const sockaddr_storage& expected,
    const std::function<bool()>& stopped);

// Borrows both sockets. The caller owns/closes them after this function returns.
// Always shuts down both sockets on exit, including cancellation and exceptions.
// Each direction retains at most 32 KiB and forwards EOF as a TCP half-close.
void relay(SOCKET application, SOCKET proxy, const std::function<bool()>& stopped,
    std::atomic<unsigned long long>& up, std::atomic<unsigned long long>& down);

} // namespace rnetch::tcp_relay

#endif // RNETCH_TCP_RELAY_H
