#!/usr/bin/env python3
"""Bounded GOST security regressions; local by default, --live uses .env credentials."""
import argparse
import base64
from pathlib import Path
import runpy
import secrets
import socket
import ssl
import struct
import subprocess
import time


ROOT = Path(__file__).resolve().parent.parent
probe = runpy.run_path(str(ROOT / "scripts/verify-relay.py"))
local = runpy.run_path(str(ROOT / "scripts/verify-relay-local.py"))
checks = 0


def passed(name):
    global checks
    checks += 1
    print(f"PASS {name}", flush=True)


def packet(features, command=0x81, version=1):
    return bytes([version, command]) + struct.pack("!H", len(features)) + features


def http_status(domain, path, port=443, secure=True, upgrade=False, method="GET"):
    # No credentials are ever sent by these HTTP/path probes, including port 80.
    with socket.create_connection((domain, port), timeout=20) as tcp:
        stream = ssl.create_default_context().wrap_socket(tcp, server_hostname=domain) if secure else tcp
        try:
            stream.settimeout(15)
            websocket_key = base64.b64encode(secrets.token_bytes(16)).decode()
            headers = ("Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                       f"Sec-WebSocket-Key: {websocket_key}\r\n") if upgrade else "Connection: close\r\n"
            stream.sendall(f"{method} {path} HTTP/1.1\r\nHost: {domain}\r\n{headers}\r\n".encode())
            response = b""
            while not response.endswith(b"\r\n\r\n"):
                response += probe["read_exact"](stream, 1)
                if len(response) > 16384:
                    raise RuntimeError("HTTP response header exceeded test limit")
            return int(response.split(b"\r\n", 1)[0].split()[1]), response
        finally:
            if stream is not tcp:
                stream.close()


def protocol_tests(domain, username, password, destination, port, **connection):
    probe["check_cases"](domain, username, password, destination, port, **connection)
    passed("baseline authentication, UDP port, TCP and BIND regression group (7 cases)")
    request = probe["relay_request"](username, password, destination, port)
    features = request[4:]

    def exchange(payload, headers=None, unmasked=False, timeout=15):
        with probe["websocket_connection"](domain, headers=headers, timeout=timeout, **connection) as stream:
            if unmasked:
                # Small unmasked frame: clients are required to mask WebSocket frames.
                stream.sendall(bytes([0x82, 4]) + b"test")
            else:
                probe["send_frame"](stream, 2, payload)
            return probe["relay_response"](stream)

    candidates = [
        ("empty username", "", password), ("empty password", username, ""),
        ("password prefix", username, password[:16]),
        ("password NUL suffix", username, password + "\x00"),
        ("username NUL suffix", username + "\x00", password),
        ("password case change", username, password.upper() if password.upper() != password else password + "A"),
    ]
    for name, user, secret in candidates:
        status = exchange(probe["relay_request"](user, secret, destination, port))
        if status != 2:
            raise RuntimeError(f"Authentication bypass: {name}, status {status}")
        passed(name + " rejected")
    basic = base64.b64encode(f"{username}:{password}".encode()).decode()
    status = exchange(probe["relay_request"](username, None, destination, port), headers={"Authorization": "Basic " + basic})
    if status != 2:
        raise RuntimeError("HTTP Basic header bypassed relay authentication")
    passed("HTTP Basic header alone cannot replace GOST authentication")

    malformed = [
        ("unsupported relay version", packet(features, version=2)),
        ("unsupported command", packet(features, command=0x8F)),
        ("short authentication feature", packet(probe["feature"](1, b"\xff"))),
        ("declared feature length exceeds payload", packet(b"\x01\xff\xffx")),
    ]
    for name, payload in malformed:
        try:
            status = exchange(payload)
        except (ConnectionError, RuntimeError, ssl.SSLError):
            status = "closed"
        if status == 0:
            raise RuntimeError("Malformed request accepted: " + name)
        passed(name + " rejected/connection closed")
    for network, label in [(2, "raw IP"), (16, "Unix socket"), (17, "serial")]:
        payload = packet(features + probe["feature"](4, struct.pack("!H", network)), command=1)
        if exchange(payload) == 0:
            raise RuntimeError("Forbidden network accepted: " + label)
        passed(label + " network forwarding rejected")
    try:
        status = exchange(b"", unmasked=True)
    except (ConnectionError, RuntimeError, ssl.SSLError):
        status = "closed"
    if status == 0:
        raise RuntimeError("Unmasked WebSocket client frame was accepted")
    passed("unmasked WebSocket client frame rejected")
    # The deployed Fly path was observed to propagate closure after ~15s,
    # while the direct backend closes at its configured 10s deadline.
    close_budget = 20 if connection.get("secure", True) else 12.5
    start = time.monotonic()
    try:
        # One deliberately incomplete handshake; no concurrency/load test.
        exchange(b"\x01\x81\x00\x20", timeout=close_budget + 1)
    except (ConnectionError, RuntimeError, ssl.SSLError):
        pass
    else:
        raise RuntimeError("Incomplete handshake unexpectedly completed")
    if time.monotonic() - start > close_budget:
        raise RuntimeError("Incomplete relay handshake was not closed within configured timeout")
    passed(f"incomplete unauthenticated handshake closed within {close_budget}s observation budget")
    if probe["relay_status"](domain, username, password, destination, port, **connection) != 0:
        raise RuntimeError("Service unhealthy after negative protocol tests")
    passed("valid authentication still works after negative tests")


def local_tests():
    password = secrets.token_hex(32)
    environment = {"WGPROXY_USERNAME": "test-user", "WGPROXY_PASSWORD": password,
                   "WGPROXY_UDP_PORT": "51820", "WGPROXY_ALLOWED_DOMAINS": "*"}
    port = local["start_server"](environment)
    protocol_tests("127.0.0.1", "test-user", password, "127.0.0.1", 51820, relay_port=port, secure=False)
    restricted = local["start_server"]({**environment, "WGPROXY_ALLOWED_DOMAINS": "localhost"})
    for destination in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "2130706433", "0177.0.0.1",
                        "localhost.evil.test", "evillocalhost", "localhost@evil.test"]:
        status = probe["relay_status"]("127.0.0.1", "test-user", password, destination, 51820, relay_port=restricted, secure=False)
        if status != 3:
            raise RuntimeError("Hostname allowlist bypass, status " + str(status))
        passed("hostname allowlist denies " + destination)
    if probe["relay_status"]("127.0.0.1", "test-user", password, "localhost", 51820, relay_port=restricted, secure=False) != 0:
        raise RuntimeError("Exact allowed hostname failed")
    passed("exact allowed hostname accepted")
    # Test rotation in a separate local server; deployed credentials are unchanged.
    rotated_password = secrets.token_hex(32)
    rotated = local["start_server"]({**environment, "WGPROXY_PASSWORD": rotated_password})
    for candidate, expected in [(password, 2), (rotated_password, 0)]:
        if probe["relay_status"]("127.0.0.1", "test-user", candidate, "127.0.0.1", 51820, relay_port=rotated, secure=False) != expected:
            raise RuntimeError("Credential rotation did not enforce the new password")
    passed("local credential rotation rejects old password and accepts new password")


def live_tests(destination):
    values = dict(line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines()
                  if line and not line.startswith("#") and "=" in line)
    domain = values["WGPROXY_DOMAIN"]
    # App service exposure is checked via Fly metadata, rather than scanning
    # other tenants' shared edge IP ports. The audit requires 443-only ingress.
    for path, upgrade in [("/", False), ("/.env", False), ("/metrics", False),
                          ("/config", False), ("/ws", False), ("/wrong-path", True)]:
        status, _ = http_status(domain, path, upgrade=upgrade)
        if status not in (400, 401, 403, 404, 405, 426):
            raise RuntimeError(f"Unexpected public HTTP surface at {path}: {status}")
        passed(f"public HTTP endpoint {path} denied ({status})")
    status, _ = http_status(domain, "example.com:51820", method="CONNECT")
    if 200 <= status < 300 or status == 101:
        raise RuntimeError("Unauthenticated HTTP CONNECT accepted")
    passed("unauthenticated HTTP CONNECT denied")
    protocol_tests(domain, values["WGPROXY_USERNAME"], values["WGPROXY_PASSWORD"], destination,
                   int(values.get("WGPROXY_UDP_PORT", "51820")))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="bounded requests to the deployed relay; no deployment/config changes")
    parser.add_argument("--destination", default="example.com", help="permitted hostname for live tests; no UDP payload is sent")
    args = parser.parse_args()
    try:
        live_tests(args.destination) if args.live else local_tests()
        print(f"PASS {checks} security checks/groups; no WG profile or keys read", flush=True)
    finally:
        for process in reversed(local["helpers"]["PROCESSES"]):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
