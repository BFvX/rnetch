#pragma once
#ifndef RNETCH_UTILS_THREAD_H
#define RNETCH_UTILS_THREAD_H

#include <thread>
#include <utility>

namespace rnetch::utils {

struct ThreadHandle {
    ThreadHandle() = default;
    explicit ThreadHandle(std::thread&& t) noexcept : thr(std::move(t)) {}
    ~ThreadHandle() {
        if (thr.joinable()) {
            try { thr.join(); } catch (...) {}
        }
    }
    ThreadHandle(const ThreadHandle&) = delete;
    ThreadHandle& operator=(const ThreadHandle&) = delete;
    ThreadHandle(ThreadHandle&& other) noexcept : thr(std::move(other.thr)) {}
    ThreadHandle& operator=(ThreadHandle&& other) noexcept {
        if (this != &other) {
            if (thr.joinable()) {
                try { thr.join(); } catch (...) {}
            }
            thr = std::move(other.thr);
        }
        return *this;
    }
    bool joinable() const noexcept { return thr.joinable(); }
    void join() { if (thr.joinable()) thr.join(); }
    std::thread thr;
};

} // namespace rnetch::utils

#endif // RNETCH_UTILS_THREAD_H


