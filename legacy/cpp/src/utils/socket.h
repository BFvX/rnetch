#pragma once
#ifndef RNETCH_UTILS_SOCKET_H
#define RNETCH_UTILS_SOCKET_H

#include <winsock2.h>
#include <memory>

namespace rnetch::utils {

struct SocketHandle {
    explicit SocketHandle(SOCKET s = INVALID_SOCKET) noexcept : s_(s) {}
    ~SocketHandle() { close(); }
    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;
    SocketHandle(SocketHandle&& other) noexcept : s_(other.s_) { other.s_ = INVALID_SOCKET; }
    SocketHandle& operator=(SocketHandle&& other) noexcept {
        if (this != &other) {
            close();
            s_ = other.s_;
            other.s_ = INVALID_SOCKET;
        }
        return *this;
    }
    SOCKET get() const noexcept { return s_; }
    void close() noexcept {
        if (s_ != INVALID_SOCKET) {
            closesocket(s_);
            s_ = INVALID_SOCKET;
        }
    }
private:
    SOCKET s_{ INVALID_SOCKET };
};

} // namespace rnetch::utils

#endif // RNETCH_UTILS_SOCKET_H


