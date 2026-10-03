#pragma once
#ifndef RNETCH_H
#define RNETCH_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <vector>
#include "nfapi.h"

namespace rnetch {
    struct Rule {
        std::vector<std::wstring> process_names;
        bool accelerate_tcp;
        bool accelerate_udp;
    };

    bool start(const std::string& socks5_host, const std::string& socks5_port, const std::string& socks5_user, const std::string& socks5_pass, const std::vector<Rule>& rules);
    // Owner wait: Enter/EOF/Ctrl+C or an internal callback/worker failure.
    void wait_for_stop();
    void stop();
} // namespace rnetch

#endif // RNETCH_H
