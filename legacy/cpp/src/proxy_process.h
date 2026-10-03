#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>

namespace rnetch::proxy_process {
// Register the process owning the reverse side of an established SOCKS TCP
// connection before its handshake can cause the daemon to open upstream flows.
// No matching local owner is normal for a remote SOCKS server. On failure the
// caller must close the connection; GetLastError/WSAGetLastError carry the cause.
bool register_connection(SOCKET socket) noexcept;
// A PID is exempt only while it still has the registered process creation time.
bool is_proxy(DWORD process_id) noexcept;
} // namespace rnetch::proxy_process
