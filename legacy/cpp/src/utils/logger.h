#pragma once
#ifndef RNETCH_UTILS_LOGGER_H
#define RNETCH_UTILS_LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>

namespace rnetch::utils {

class Logger {
public:
    Logger() = default;
    ~Logger() { close(); }

    void openFile(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) file_.close();
        file_.open(path, std::ios::out | std::ios::app);
    }

    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) file_.close();
    }

    void log(const std::string& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!file_.is_open()) return;
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm buf;
        localtime_s(&buf, &in_time_t);
        file_ << std::put_time(&buf, "%Y-%m-%d %X") << " - " << message << std::endl;
    }

private:
    std::ofstream file_;
    std::mutex mutex_;
};

} // namespace rnetch::utils

#endif // RNETCH_UTILS_LOGGER_H


