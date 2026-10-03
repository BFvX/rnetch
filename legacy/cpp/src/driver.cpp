#include "driver.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <array>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>

namespace rnetch::driver {
namespace {
constexpr const char* driver_name = "netfilter2";
std::mutex lifecycle_mutex;
// Service existence does not imply ownership. Claim only a successful start
// performed by this process, never a pre-existing or concurrently started one.
bool started_by_us = false;

struct ServiceHandle {
    SC_HANDLE value;
    explicit ServiceHandle(SC_HANDLE handle) : value(handle) {}
    ~ServiceHandle() { if (value) CloseServiceHandle(value); }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
};

void print_error(const char* message, DWORD error = GetLastError()) {
    std::cerr << message << " Error: " << error << std::endl;
}

bool query_status(SC_HANDLE service, SERVICE_STATUS_PROCESS& status) {
    DWORD bytes_needed = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes_needed)) {
        print_error("QueryServiceStatusEx failed.");
        return false;
    }
    return true;
}

bool wait_for_state(SC_HANDLE service, DWORD desired_state, DWORD timeout_ms) {
    constexpr DWORD interval = 250;
    for (DWORD waited = 0; waited <= timeout_ms; waited += interval) {
        SERVICE_STATUS_PROCESS status{};
        if (!query_status(service, status)) return false;
        if (status.dwCurrentState == desired_state) return true;
        if (waited < timeout_ms) Sleep(interval);
    }
    std::cerr << "Timed out waiting for driver service state " << desired_state << "." << std::endl;
    return false;
}

std::string comparable_path(std::string path) {
    const auto first = path.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    path = path.substr(first, path.find_last_not_of(" \t") - first + 1);
    if (path.size() >= 2 && path.front() == '"' && path.back() == '"') {
        path = path.substr(1, path.size() - 2);
    }
    if (path.compare(0, 4, "\\??\\") == 0 || path.compare(0, 4, "\\\\?\\") == 0) path.erase(0, 4);
    for (auto& character : path) if (character == '/') character = '\\';
    return path;
}

bool executable_driver_path(char (&driver_path)[MAX_PATH]) {
    const DWORD length = GetModuleFileNameA(nullptr, driver_path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        print_error("Cannot resolve an untruncated executable path.");
        return false;
    }
    char* name = std::strrchr(driver_path, '\\');
    constexpr char filename[] = "nfdriver.sys";
    if (!name || MAX_PATH - static_cast<size_t>(name + 1 - driver_path) < sizeof(filename)) {
        std::cerr << "Cannot construct the driver path." << std::endl;
        return false;
    }
    std::memcpy(name + 1, filename, sizeof(filename));
    return true;
}

bool check_existing(SC_HANDLE service, const char* expected_path) {
    SERVICE_STATUS_PROCESS status{};
    if (!query_status(service, status)) return false;
    if (status.dwServiceType != SERVICE_KERNEL_DRIVER) {
        std::cerr << "Existing netfilter2 service is not a kernel driver; leaving it unchanged." << std::endl;
        return false;
    }
    // Reuse a running driver without rewriting its future load path. The SDK
    // will reject nf_init if another client is attached; stop() remains a no-op.
    if (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING) return true;
    if (status.dwCurrentState != SERVICE_STOPPED) {
        std::cerr << "Existing netfilter2 service is changing state; leaving it unchanged." << std::endl;
        return false;
    }
    // A stopped service may belong to a different application/SDK installation.
    // Validate its path read-only rather than silently replacing that driver.
    alignas(QUERY_SERVICE_CONFIGA) std::array<unsigned char, 8192> storage{};
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGA*>(storage.data());
    DWORD needed = 0;
    if (!QueryServiceConfigA(service, config, static_cast<DWORD>(storage.size()), &needed)) {
        print_error("QueryServiceConfig failed; existing service left unchanged.");
        return false;
    }
    const auto actual = comparable_path(config->lpBinaryPathName ? config->lpBinaryPathName : "");
    if (config->dwServiceType != SERVICE_KERNEL_DRIVER ||
        _stricmp(actual.c_str(), comparable_path(expected_path).c_str()) != 0) {
        std::cerr << "Existing stopped netfilter2 service uses a different driver path; leaving it unchanged: "
                  << actual << std::endl;
        return false;
    }
    return true;
}

bool stop_owned(SC_HANDLE service) {
    SERVICE_STATUS status{};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) {
            print_error("Stop owned driver failed.", error);
            return false;
        }
        started_by_us = false;
        return true;
    }
    if (!wait_for_state(service, SERVICE_STOPPED, 15000)) return false;
    started_by_us = false;
    return true;
}
} // namespace

bool install() {
    std::lock_guard<std::mutex> guard(lifecycle_mutex);
    char driver_path[MAX_PATH]{};
    if (!executable_driver_path(driver_path)) return false;
    ServiceHandle scm(OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.value) { print_error("OpenSCManager failed."); return false; }
    ServiceHandle existing(OpenServiceA(scm.value, driver_name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
    if (existing.value) return check_existing(existing.value, driver_path);
    const DWORD open_error = GetLastError();
    if (open_error != ERROR_SERVICE_DOES_NOT_EXIST) {
        print_error("Open existing driver service failed; configuration left unchanged.", open_error);
        return false;
    }

    ServiceHandle creator(OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
    if (!creator.value) { print_error("OpenSCManager for driver creation failed."); return false; }
    ServiceHandle created(CreateServiceA(creator.value, driver_name, driver_name, SERVICE_QUERY_STATUS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driver_path,
        nullptr, nullptr, nullptr, nullptr, nullptr));
    if (created.value) return true;
    const DWORD create_error = GetLastError();
    if (create_error == ERROR_SERVICE_EXISTS) {
        // Another application won the create race. Inspect its service without
        // modifying it, just as if it had existed at the initial OpenService.
        ServiceHandle raced(OpenServiceA(scm.value, driver_name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
        if (raced.value) return check_existing(raced.value, driver_path);
        print_error("Open concurrently created driver service failed.");
        return false;
    }
    print_error("CreateService failed.", create_error);
    return false;
}

bool start() {
    std::lock_guard<std::mutex> guard(lifecycle_mutex);
    ServiceHandle scm(OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.value) { print_error("OpenSCManager failed."); return false; }
    ServiceHandle service(OpenServiceA(scm.value, driver_name, SERVICE_QUERY_STATUS));
    if (!service.value) { print_error("OpenService failed."); return false; }
    SERVICE_STATUS_PROCESS status{};
    if (!query_status(service.value, status)) return false;
    if (status.dwCurrentState == SERVICE_RUNNING) return true;
    if (status.dwCurrentState == SERVICE_START_PENDING) return wait_for_state(service.value, SERVICE_RUNNING, 15000);
    if (status.dwCurrentState == SERVICE_STOP_PENDING && !wait_for_state(service.value, SERVICE_STOPPED, 15000)) return false;
    if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING) {
        std::cerr << "Existing driver is not stopped; refusing to change its state." << std::endl;
        return false;
    }
    started_by_us = false;
    char driver_path[MAX_PATH]{};
    if (!executable_driver_path(driver_path)) return false;
    ServiceHandle starter(OpenServiceA(scm.value, driver_name,
        SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
    if (!starter.value) { print_error("Open driver for start failed."); return false; }
    // A previously running foreign service can stop between install and start.
    // Recheck before loading anything instead of trusting the earlier state.
    if (!check_existing(starter.value, driver_path)) return false;
    if (!StartServiceA(starter.value, 0, nullptr)) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            return wait_for_state(starter.value, SERVICE_RUNNING, 15000);
        }
        print_error("StartService failed.", error);
        return false;
    }
    started_by_us = true;
    if (wait_for_state(starter.value, SERVICE_RUNNING, 15000)) return true;
    // The caller does not run normal stop() when start() fails. Roll back only
    // the service that this call actually started, retaining ownership on error.
    stop_owned(starter.value);
    return false;
}

bool stop() {
    std::lock_guard<std::mutex> guard(lifecycle_mutex);
    if (!started_by_us) return true;
    ServiceHandle scm(OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.value) { print_error("OpenSCManager for stop failed."); return false; }
    ServiceHandle service(OpenServiceA(scm.value, driver_name, SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!service.value) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) { started_by_us = false; return true; }
        print_error("Open owned driver for stop failed.");
        return false;
    }
    SERVICE_STATUS_PROCESS status{};
    if (!query_status(service.value, status)) return false;
    if (status.dwCurrentState == SERVICE_STOPPED) { started_by_us = false; return true; }
    return stop_owned(service.value);
}

bool uninstall() {
    // This remains an explicit operation. Normal startup failure and shutdown
    // never delete an existing service registration.
    std::lock_guard<std::mutex> guard(lifecycle_mutex);
    ServiceHandle scm(OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.value) return false;
    ServiceHandle service(OpenServiceA(scm.value, driver_name, DELETE));
    if (!service.value) return false;
    return DeleteService(service.value) != FALSE;
}
} // namespace rnetch::driver
