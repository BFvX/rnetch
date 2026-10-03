// All SCM entry points in driver.cpp are replaced below. This test never opens
// the real service manager, loads a driver, or changes host service state.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

namespace scm_mock {
struct State {
    bool exists = true;
    DWORD state = SERVICE_STOPPED;
    DWORD type = SERVICE_KERNEL_DRIVER;
    std::string path = "C:\\demo\\nfdriver.sys";
    std::string module_path = "C:\\demo\\rnetch.exe";
    std::map<SC_HANDLE, DWORD> handles;
    size_t next_handle = 1;
    int opens = 0, creates = 0, starts = 0, stops = 0, config_reads = 0;
    bool create_race = false, start_race = false, fail_start = false;
    bool fail_open = false, fail_query = false, fail_config = false, fail_stop = false;
    bool start_never_ready = false, truncated_module = false;
    int pending_reads = -1;
} state;

void expect(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

SC_HANDLE handle(DWORD access) {
    auto result = reinterpret_cast<SC_HANDLE>(state.next_handle++);
    state.handles.emplace(result, access);
    return result;
}

SC_HANDLE WINAPI open_scm(LPCSTR, LPCSTR, DWORD access) {
    ++state.opens;
    return handle(access);
}

SC_HANDLE WINAPI open_service(SC_HANDLE, LPCSTR, DWORD access) {
    if (state.fail_open || !state.exists) {
        SetLastError(state.fail_open ? ERROR_ACCESS_DENIED : ERROR_SERVICE_DOES_NOT_EXIST);
        return nullptr;
    }
    return handle(access);
}

BOOL WINAPI close_service(SC_HANDLE service) {
    expect(state.handles.erase(service) == 1, "SCM handle double-closed or invalid");
    return TRUE;
}

SC_HANDLE WINAPI create_service(SC_HANDLE, LPCSTR, LPCSTR, DWORD access, DWORD type,
    DWORD, DWORD, LPCSTR path, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR) {
    ++state.creates;
    if (state.create_race) {
        state.exists = true;
        state.state = SERVICE_RUNNING;
        state.path = "C:\\another-app\\nfdriver.sys";
        SetLastError(ERROR_SERVICE_EXISTS);
        return nullptr;
    }
    expect(!state.exists, "Existing service must not be recreated");
    state.exists = true;
    state.type = type;
    state.path = path;
    return handle(access);
}

BOOL WINAPI query_status(SC_HANDLE, SC_STATUS_TYPE, LPBYTE data, DWORD size, LPDWORD needed) {
    if (state.fail_query) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    expect(size >= sizeof(SERVICE_STATUS_PROCESS), "Service status buffer too small");
    if (state.pending_reads == 0) state.state = SERVICE_RUNNING;
    else if (state.pending_reads > 0) --state.pending_reads;
    auto* result = reinterpret_cast<SERVICE_STATUS_PROCESS*>(data);
    *result = {};
    result->dwCurrentState = state.state;
    result->dwServiceType = state.type;
    *needed = sizeof(*result);
    return TRUE;
}

BOOL WINAPI query_config(SC_HANDLE, LPQUERY_SERVICE_CONFIGA config, DWORD size, LPDWORD needed) {
    ++state.config_reads;
    if (state.fail_config) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    *needed = static_cast<DWORD>(sizeof(*config) + state.path.size() + 1);
    expect(size >= *needed, "Service config buffer too small");
    *config = {};
    config->dwServiceType = state.type;
    config->lpBinaryPathName = reinterpret_cast<char*>(config + 1);
    std::memcpy(config->lpBinaryPathName, state.path.c_str(), state.path.size() + 1);
    return TRUE;
}

BOOL WINAPI start_service(SC_HANDLE service, DWORD, LPCSTR*) {
    ++state.starts;
    expect((state.handles.at(service) & SERVICE_START) != 0, "Missing service start access");
    if (state.fail_start) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    if (state.start_race) {
        state.state = SERVICE_RUNNING;
        SetLastError(ERROR_SERVICE_ALREADY_RUNNING);
        return FALSE;
    }
    state.state = state.start_never_ready ? SERVICE_START_PENDING : SERVICE_RUNNING;
    return TRUE;
}

BOOL WINAPI control_service(SC_HANDLE service, DWORD code, LPSERVICE_STATUS status) {
    ++state.stops;
    expect((state.handles.at(service) & SERVICE_STOP) && code == SERVICE_CONTROL_STOP,
           "Unexpected service control operation");
    if (state.fail_stop) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    state.state = SERVICE_STOPPED;
    state.pending_reads = -1;
    *status = {};
    status->dwCurrentState = state.state;
    return TRUE;
}

BOOL WINAPI delete_service(SC_HANDLE) {
    state.exists = false;
    return TRUE;
}

DWORD WINAPI module_filename(HMODULE, LPSTR output, DWORD size) {
    if (state.truncated_module) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return size; }
    expect(size > state.module_path.size(), "Executable path buffer too small");
    std::memcpy(output, state.module_path.c_str(), state.module_path.size() + 1);
    return static_cast<DWORD>(state.module_path.size());
}

void WINAPI sleep(DWORD) {}

void reset() {
    expect(state.handles.empty(), "SCM handle leaked by previous operation");
    state = State{};
}
} // namespace scm_mock

#define OpenSCManagerA scm_mock::open_scm
#define OpenServiceA scm_mock::open_service
#define CloseServiceHandle scm_mock::close_service
#define CreateServiceA scm_mock::create_service
#define QueryServiceStatusEx scm_mock::query_status
#define QueryServiceConfigA scm_mock::query_config
#define StartServiceA scm_mock::start_service
#define ControlService scm_mock::control_service
#define DeleteService scm_mock::delete_service
#define GetModuleFileNameA scm_mock::module_filename
#define Sleep scm_mock::sleep
#define ChangeServiceConfigA DO_NOT_CHANGE_PREEXISTING_SERVICES
#include "../src/driver.cpp"

namespace driver = rnetch::driver;
using scm_mock::expect;

int main() {
    try {
        auto& state = scm_mock::state;
        // A failed nf_init after reuse will call stop(). It must neither stop
        // another application's running driver nor rewrite its registry path.
        state.state = SERVICE_RUNNING;
        state.path = "C:\\another-app\\nfdriver.sys";
        expect(driver::install() && driver::start() && driver::stop(), "Cannot reuse running service");
        expect(state.starts == 0 && state.stops == 0 && state.creates == 0 && state.config_reads == 0,
               "Running service was mutated or claimed");
        expect(state.path == "C:\\another-app\\nfdriver.sys", "Running driver path overwritten");

        // The foreign service may stop after install checked RUNNING. Starting
        // it later must still validate the path instead of loading that binary.
        state.state = SERVICE_STOPPED;
        expect(!driver::start() && driver::stop() && state.starts == 0 && state.stops == 0,
               "Service state change bypassed stopped-driver path validation");

        scm_mock::reset();
        state.state = SERVICE_START_PENDING;
        state.pending_reads = 2;
        expect(driver::install() && driver::start() && driver::stop(), "Cannot await external startup");
        expect(state.starts == 0 && state.stops == 0, "External pending startup claimed");

        scm_mock::reset();
        state.path = "C:\\another-app\\nfdriver.sys";
        expect(!driver::install(), "Mismatched stopped driver must be rejected");
        expect(driver::stop() && state.stops == 0 && state.creates == 0,
               "Installation failure affected existing service");

        for (const auto& path : {std::string("\"C:\\DEMO\\nfdriver.sys\""),
                                std::string("\\??\\C:\\demo\\nfdriver.sys"),
                                std::string("\\\\?\\C:\\demo\\nfdriver.sys")}) {
            scm_mock::reset();
            state.path = path;
            expect(driver::install() && driver::start(), "Quoted/native driver path rejected");
            expect(driver::stop() && state.stops == 1 && state.state == SERVICE_STOPPED,
                   "Owned driver was not stopped");
            expect(driver::stop() && state.stops == 1, "Repeated stop affected unowned service");
        }

        scm_mock::reset();
        state.exists = false;
        expect(driver::install() && state.creates == 1, "Missing service not created");
        expect(driver::start() && driver::stop() && state.starts == 1 && state.stops == 1,
               "New service ownership failed");

        scm_mock::reset();
        state.exists = false;
        state.create_race = true;
        expect(driver::install() && driver::start() && driver::stop(), "Concurrent creation not handled");
        expect(state.stops == 0 && state.path == "C:\\another-app\\nfdriver.sys", "Create race claimed foreign driver");

        scm_mock::reset();
        state.start_race = true;
        expect(driver::install() && driver::start() && driver::stop(), "Concurrent startup not handled");
        expect(state.starts == 1 && state.stops == 0, "Already-running result claimed ownership");

        scm_mock::reset();
        state.fail_start = true;
        expect(driver::install() && !driver::start() && driver::stop(), "Failed start cleanup failed");
        expect(state.stops == 0, "Failed StartService claimed ownership");

        scm_mock::reset();
        state.start_never_ready = true;
        expect(driver::install() && !driver::start(), "Incomplete startup should fail");
        expect(state.stops == 1 && state.state == SERVICE_STOPPED && driver::stop(),
               "Failed owned startup was not rolled back");
        expect(state.stops == 1, "Startup rollback did not release ownership");

        scm_mock::reset();
        expect(driver::install() && driver::start(), "Cannot create owned stop-failure scenario");
        state.fail_stop = true;
        expect(!driver::stop() && state.handles.empty(), "Failed stop leaked SCM handles");
        state.fail_stop = false;
        expect(driver::stop() && state.stops == 2, "Stop failure lost ownership before retry");

        scm_mock::reset();
        state.fail_config = true;
        expect(!driver::install() && state.handles.empty(), "Config query failure leaked handles");
        state.fail_config = false;
        state.fail_query = true;
        expect(!driver::install() && state.handles.empty(), "Status query failure leaked handles");
        state.fail_query = false;
        state.fail_open = true;
        expect(!driver::install() && state.creates == 0 && state.handles.empty(), "Open failure modified service");

        scm_mock::reset();
        state.truncated_module = true;
        expect(!driver::install() && state.opens == 0, "Truncated executable path reached SCM");
        state.truncated_module = false;
        state.module_path = "C:\\" + std::string(MAX_PATH - 10, 'x') + "\\a.exe";
        expect(!driver::install() && state.opens == 0, "Overlong driver filename reached SCM");
        expect(state.handles.empty(), "SCM handles leaked");
        std::cout << "Driver ownership regressions passed (mock SCM only)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
