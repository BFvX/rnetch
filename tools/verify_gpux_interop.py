"""Driver-free Rust client interop with the original C++ GPUX server.

All sockets bind to loopback. The FEC cases lose one DATA packet per group in
both directions, while checking two sessions and IPv4/IPv6 destinations.
"""
from __future__ import annotations

import argparse
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path


class Echo:
    def __init__(self, family: int):
        self.socket = socket.socket(family, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
        self.socket.settimeout(0.1)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    @property
    def target(self):
        host, port = self.socket.getsockname()[:2]
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

    def run(self):
        while not self.stop.is_set():
            try:
                payload, peer = self.socket.recvfrom(65535)
                self.socket.sendto(payload, peer)
            except (socket.timeout, ConnectionResetError):
                pass

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.socket.close()


class LossRelay:
    def __init__(self, server_port: int, lose_fec: bool):
        self.server = ("127.0.0.1", server_port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.client = None
        self.lose_fec = lose_fec
        self.dropped = {"up": 0, "down": 0}
        self.groups = set()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                payload, peer = self.socket.recvfrom(65535)
            except (socket.timeout, ConnectionResetError):
                continue
            direction = "down" if peer == self.server else "up"
            if direction == "up":
                self.client = peer
            if self.lose_fec and len(payload) >= 63 and payload[:4] == b"GPUX" and payload[5] == 3:
                group = struct.unpack_from("!I", payload, 40)[0]
                index = payload[46]
                key = (direction, group)
                if group and index == 0 and key not in self.groups:
                    self.groups.add(key)
                    self.dropped[direction] += 1
                    continue
            destination = self.server if direction == "up" else self.client
            if destination:
                self.socket.sendto(payload, destination)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.socket.close()


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-exe", type=Path, required=True)
    parser.add_argument("--client-exe", type=Path, default=Path("target/debug/examples/gpux_probe.exe"))
    args = parser.parse_args()
    server_exe, client_exe = args.server_exe.resolve(), args.client_exe.resolve()
    if not server_exe.is_file() or not client_exe.is_file():
        parser.error("Build gpux_server and cargo build --example gpux_probe first")
    echoes = [Echo(socket.AF_INET), Echo(socket.AF_INET6)]
    try:
        cases = [
            ("plaintext", False, 0, 0),
            ("chacha20-poly1305", False, 0, 0),
            ("chacha20-poly1305", False, 300, 200),
            ("plaintext", True, 300, 200),
            ("chacha20-poly1305", True, 300, 200),
        ]
        with tempfile.TemporaryDirectory(prefix="rnetch-gpux-interop-") as directory:
            for index, (encryption, fec, batching, pacing) in enumerate(cases):
                server_port = free_port()
                relay = LossRelay(server_port, fec)
                config = Path(directory) / f"case-{index}.xml"
                config.write_text(f'''<config>
<backend type="netfilter"/><udp_transport type="gpux"/>
<gpux host="127.0.0.1" port="{relay.port}" token="local-interop"
 encryption="{encryption}" deadline_ms="500" batch_window_us="{batching}"
 pacing_interval_us="{pacing}" fec_uplink="{int(fec)}" fec_group_max_us="2000"/>
<rules><rule name="probe.exe" tcp="0" udp="1"/></rules>
</config>''', encoding="utf-8")
                with (Path(directory) / f"server-{index}.log").open("w+", encoding="utf-8") as log:
                    server = subprocess.Popen([
                        str(server_exe), "--listen-host", "127.0.0.1", "--listen-port", str(server_port),
                        "--token", "local-interop", "--encryption", encryption,
                        "--reject-special-remotes", "0", "--exit-after-close",
                        "--downlink-deadline-ms", "500", "--pacing-interval-us", "0",
                        "--fec-downlink", str(int(fec)), "--fec-downlink-k", "4",
                        "--fec-group-max-us", "2000", "--verbose-data", "1",
                    ], stdout=log, stderr=subprocess.STDOUT)
                    try:
                        time.sleep(0.15)
                        result = subprocess.run([str(client_exe), str(config), *(echo.target for echo in echoes)],
                                                capture_output=True, text=True, timeout=15)
                        if result.returncode:
                            log.flush()
                            log.seek(0)
                            raise AssertionError(f"{encryption}, fec={fec}:\n{result.stdout}\n{result.stderr}\n{log.read()}")
                        server.wait(timeout=5)
                        if server.returncode:
                            raise AssertionError(f"Server exit code {server.returncode}")
                        if fec and not all(relay.dropped.values()):
                            raise AssertionError(f"FEC loss was not exercised in both directions: {relay.dropped}")
                        log.flush()
                        log.seek(0)
                        server_log = log.read()
                        for event in ("FLOW_OPEN", "DATA_UP", "DATA_DOWN", "FLOW_CLOSE", "CLOSE"):
                            if event not in server_log:
                                raise AssertionError(f"Missing server lifecycle event {event}")
                        print(f"PASS {encryption}, fec={int(fec)}, batch={batching}, pace={pacing}, dropped={relay.dropped}")
                        print(result.stdout.strip())
                    finally:
                        if server.poll() is None:
                            server.terminate()
                            server.wait(timeout=5)
                        relay.close()
    finally:
        for echo in echoes:
            echo.close()


if __name__ == "__main__":
    main()
