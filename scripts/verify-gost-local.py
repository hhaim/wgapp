#!/usr/bin/env python3
"""Loopback-only GOST UDP/TLS and shared-access-key smoke test; no WG profile used."""
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import threading
import time


GOST = Path(__file__).resolve().parent.parent / "build/gost-check/gost"
PROCESSES = []


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def pipe_bytes(data):
    reader, writer = os.pipe()
    try:
        os.write(writer, data)
    finally:
        os.close(writer)
    return reader


def launch(config, descriptors=()):
    # Config and transient TLS material travel over anonymous pipes only.
    process = subprocess.Popen([str(GOST), "-C", "-"], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               pass_fds=descriptors)
    PROCESSES.append(process)
    for descriptor in descriptors:
        os.close(descriptor)
    process.stdin.write(json.dumps(config).encode())
    process.stdin.close()
    return process


def main():
    print(subprocess.check_output([str(GOST), "-V"], text=True).strip(), flush=True)
    # OpenSSL writes both ephemeral PEM objects to a pipe, never to disk.
    pem = subprocess.check_output([
        "/opt/homebrew/bin/openssl", "req", "-new", "-x509", "-newkey", "rsa:2048",
        "-noenc", "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout", "/dev/stdout", "-out", "/dev/stdout"], stderr=subprocess.DEVNULL)
    certificate = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S).group() + b"\n"
    private_key = re.search(rb"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", pem, re.S).group() + b"\n"

    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
    echo.bind(("127.0.0.1", 0))
    echo.settimeout(0.2)
    stopped = threading.Event()
    received = []

    def echo_packets():
        while not stopped.is_set():
            try:
                payload, sender = echo.recvfrom(65535)
                received.append(payload)
                echo.sendto(payload, sender)
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=echo_packets, daemon=True)
    thread.start()
    relay_port = free_port(socket.SOCK_STREAM)
    shared_key = secrets.token_hex(32)
    cert_fd = pipe_bytes(certificate)
    key_fd = pipe_bytes(private_key)
    server = launch({"log": {"level": "error", "output": "stderr"}, "services": [{
        "name": "local-relay", "addr": f"127.0.0.1:{relay_port}",
        "handler": {"type": "relay", "auth": {"username": "wgproxy", "password": shared_key}},
        "listener": {"type": "tls", "tls": {"certFile": f"/dev/fd/{cert_fd}", "keyFile": f"/dev/fd/{key_fd}"}}
    }]}, (cert_fd, key_fd))
    deadline = time.monotonic() + 5
    while True:
        if server.poll() is not None:
            detail = server.stderr.read().decode(errors="replace").replace(shared_key, "<redacted>")
            raise RuntimeError("GOST server could not load its in-memory configuration: " + detail[:1000])
        try:
            with socket.create_connection(("127.0.0.1", relay_port), timeout=0.2):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError("GOST TLS listener did not become ready")
            time.sleep(0.05)

    def client(password):
        listen_port = free_port(socket.SOCK_DGRAM)
        ca_fd = pipe_bytes(certificate)
        process = launch({"log": {"level": "error", "output": "stderr"}, "services": [{
            "name": "local-udp", "addr": f"127.0.0.1:{listen_port}",
            "handler": {"type": "udp", "chain": "relay"},
            "listener": {"type": "udp", "metadata": {"keepAlive": True, "ttl": "2m", "readQueueSize": 128}},
            "forwarder": {"nodes": [{"name": "echo", "addr": f"127.0.0.1:{echo.getsockname()[1]}"}]}
        }], "chains": [{"name": "relay", "hops": [{"name": "hop", "nodes": [{
            "name": "relay-node", "addr": f"127.0.0.1:{relay_port}",
            "connector": {"type": "relay", "auth": {"username": "wgproxy", "password": password}},
            "dialer": {"type": "tls", "tls": {"secure": True, "serverName": "localhost", "caFile": f"/dev/fd/{ca_fd}"}}
        }]}]}]}, (ca_fd,))
        # Wait for this process to bind its own UDP listener.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                detail = process.stderr.read().decode(errors="replace").replace(password, "<redacted>")
                raise RuntimeError("GOST client could not load its in-memory configuration: " + detail[:1000])
            check = subprocess.run(["/usr/sbin/lsof", "-a", "-p", str(process.pid),
                                    f"-iUDP@127.0.0.1:{listen_port}", "-Fn"], capture_output=True)
            if check.returncode == 0:
                return listen_port
            time.sleep(0.05)
        raise RuntimeError("GOST local UDP listener did not become ready")

    try:
        port = client(shared_key)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            sender.settimeout(5)
            sender.connect(("127.0.0.1", port))
            for size in [1, 32, 92, 148, 1279, 1280, 1420]:
                payload = secrets.token_bytes(size)
                sender.send(payload)
                reply = sender.recv(65535)
                if reply != payload:
                    raise RuntimeError(f"UDP payload/boundary mismatch at {size} bytes")
            print("PASS authenticated UDP over verified TLS: all seven datagram sizes round-trip intact", flush=True)
            burst = [index.to_bytes(4, "big") + secrets.token_bytes(300 + index) for index in range(32)]
            for payload in burst:
                sender.send(payload)
            replies = [sender.recv(65535) for _ in burst]
            if sorted(replies) != sorted(burst):
                raise RuntimeError("UDP burst payload/boundary mismatch")
            print("PASS 32-packet UDP burst: datagram boundaries and payloads preserved", flush=True)

        bad_port = client(secrets.token_hex(32))
        baseline = len(received)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.settimeout(1.5)
            sender.sendto(b"wrong-key-test", ("127.0.0.1", bad_port))
            try:
                sender.recv(65535)
                raise RuntimeError("Wrong shared access key was accepted")
            except socket.timeout:
                pass
        if len(received) != baseline:
            raise RuntimeError("Unauthorized UDP traffic reached the target")
        print("PASS wrong shared access key: no reply and no traffic reached the UDP target", flush=True)
        print("PASS configurations, access keys and ephemeral TLS private key stayed in memory/pipes", flush=True)
    finally:
        stopped.set()
        echo.close()
        thread.join(timeout=1)


if __name__ == "__main__":
    try:
        main()
    finally:
        for process in reversed(PROCESSES):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        print("Local GOST test processes stopped; no Fly.io changes made.", flush=True)
