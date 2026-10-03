#pragma once
#ifndef DRIVER_H
#define DRIVER_H

namespace rnetch {
    namespace driver {
        // Reuse existing registrations without changing them. A stopped service
        // must already reference the nfdriver.sys beside this executable.
        bool install();
        bool start();
        // Only stop a service successfully started by this process.
        bool stop();
        bool uninstall();
    } // namespace driver
} // namespace rnetch

#endif // DRIVER_H
