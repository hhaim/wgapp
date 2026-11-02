#!/usr/bin/env python3
"""Exercise the production GOST relay configuration on loopback; no Fly changes."""
from pathlib import Path
import runpy
import secrets
import socket
import subprocess
import threading
import time


ROOT = Path(__file__).resolve().parent.parent
build_config = runpy.run_path(str(ROOT / "relay/gost_config.py"))["build_config"]
probe = runpy.run_path(str(ROOT / "scripts/verify-relay.py"))
helpers = runpy.run_path(str(ROOT / "scripts/verify-gost-local.py"))


def start_server(environment):
    config = build_config(environment)
    port = helpers["free_port"](socket.SOCK_STREAM)
    config["services"][0]["addr"] = f"127.0.0.1:{port}"
    process = helpers["launch"](config)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Production relay configuration failed to start")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return port
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Production relay listener did not start")


def main():
    password = secrets.token_hex(32)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo:
        echo.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        echo.bind(("127.0.0.1", 0))
        echo.settimeout(0.2)
        environment = {"WGPROXY_USERNAME": "test-user", "WGPROXY_PASSWORD": password,
                       "WGPROXY_UDP_PORT": str(echo.getsockname()[1]), "WGPROXY_ALLOWED_DOMAINS": "*"}
        for field, value in [("WGPROXY_USERNAME", "bad\nname"), ("WGPROXY_PASSWORD", ""),
                             ("WGPROXY_UDP_PORT", "0"), ("WGPROXY_ALLOWED_DOMAINS", "invalid:pattern")]:
            try:
                build_config({**environment, field: value})
            except ValueError:
                continue
            raise RuntimeError(f"Invalid {field} accepted")
        print("PASS invalid credentials, destination patterns and port fail validation", flush=True)
        port = start_server(environment)
        probe["check_cases"]("127.0.0.1", "test-user", password, "127.0.0.1", echo.getsockname()[1],
                             relay_port=port, secure=False)
        restricted = start_server({**environment, "WGPROXY_ALLOWED_DOMAINS": "local*"})
        status = probe["relay_status"]("127.0.0.1", "test-user", password, "localhost", echo.getsockname()[1],
                                        relay_port=restricted, secure=False)
        if status != 0:
            raise RuntimeError("Destination matching the configured hostname pattern was rejected")
        status = probe["relay_status"]("127.0.0.1", "test-user", password, "127.0.0.1", echo.getsockname()[1],
                                        relay_port=restricted, secure=False)
        if status != 3:
            raise RuntimeError("Destination outside configured hostname pattern was accepted")
        print("PASS hostname restriction rejects an address outside the allowed pattern", flush=True)

        stopped = threading.Event()

        def echo_packets():
            while not stopped.is_set():
                try:
                    payload, sender = echo.recvfrom(65535)
                    echo.sendto(payload, sender)
                except socket.timeout:
                    continue

        thread = threading.Thread(target=echo_packets, daemon=True)
        thread.start()
        try:
            listen_port = helpers["free_port"](socket.SOCK_DGRAM)
            client = helpers["launch"]({"log": {"level": "error"}, "services": [{
                "name": "local-udp", "addr": f"127.0.0.1:{listen_port}",
                "handler": {"type": "udp", "chain": "relay"},
                "listener": {"type": "udp", "metadata": {"keepAlive": True, "ttl": "2m", "readQueueSize": 128}},
                "forwarder": {"nodes": [{"name": "echo", "addr": f"127.0.0.1:{echo.getsockname()[1]}"}]},
            }], "chains": [{"name": "relay", "hops": [{"name": "hop", "nodes": [{
                "name": "relay", "addr": f"127.0.0.1:{port}",
                "connector": {"type": "relay", "auth": {"username": "test-user", "password": password}},
                "dialer": {"type": "ws", "metadata": {"path": "/ws"}},
            }]}]}]})
            deadline = time.monotonic() + 5
            while True:
                if client.poll() is not None:
                    raise RuntimeError("GOST test client failed to start")
                bound = subprocess.run(["/usr/sbin/lsof", "-a", "-p", str(client.pid),
                                        f"-iUDP@127.0.0.1:{listen_port}", "-Fn"], capture_output=True)
                if bound.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("GOST client UDP listener did not start")
                time.sleep(0.05)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                sender.settimeout(5)
                sender.connect(("127.0.0.1", listen_port))
                for size in [1, 32, 92, 148, 1279, 1280, 1420]:
                    payload = secrets.token_bytes(size)
                    sender.send(payload)
                    if sender.recv(65535) != payload:
                        raise RuntimeError("UDP datagram boundaries/payload changed")
                burst = [index.to_bytes(4, "big") + secrets.token_bytes(300) for index in range(32)]
                for payload in burst:
                    sender.send(payload)
                if sorted(sender.recv(65535) for _ in burst) != sorted(burst):
                    raise RuntimeError("UDP burst payload/boundary mismatch")
            print("PASS seven datagram sizes and 32-packet burst through the production WS relay", flush=True)
        finally:
            stopped.set()
            thread.join(timeout=1)


if __name__ == "__main__":
    try:
        main()
    finally:
        for process in reversed(helpers["PROCESSES"]):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        print("Local relay test processes stopped; no cloud changes made.", flush=True)
