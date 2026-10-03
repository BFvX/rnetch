#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include "nfapi.h"
#include <atomic>
#include <string>

namespace rnetch::udp_relay {

// Configure before installing SDK rules. The referenced atomics outlive stop().
void configure(const std::string& host, const std::string& port,
               const std::string& user, const std::string& pass,
               std::atomic_bool& stopping,
               std::atomic<unsigned long long>& uploaded,
               std::atomic<unsigned long long>& downloaded);
// The caller performs process selection before created(). No callback joins or
// performs Winsock I/O; the first public datagram starts an endpoint worker.
void created(ENDPOINT_ID id, PNF_UDP_CONN_INFO info);
void closed(ENDPOINT_ID id);
void receive(ENDPOINT_ID id, const unsigned char* remote, const char* data,
             int length, PNF_UDP_OPTIONS options);
void send(ENDPOINT_ID id, const unsigned char* remote, const char* data,
          int length, PNF_UDP_OPTIONS options);
// Call reap from the owner/telemetry thread, never an SDK callback.
void reap();
// Set the application's stop flag, then call stop before nf_free/WSACleanup.
void stop();

} // namespace rnetch::udp_relay
