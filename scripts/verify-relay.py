#!/usr/bin/env python3
"""Verify GOST WSS authentication and forwarding policy without WireGuard keys."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import struct


def read_exact(stream, size):
    result = b""
    while len(result) < size:
        data = stream.recv(size - len(result))
        if not data:
            raise RuntimeError("Relay closed the connection before its response")
        result += data
    return result


def send_frame(stream, opcode, payload):
    mask = os.urandom(4)
    length = len(payload)
    header = bytes([0x80 | opcode, 0x80 | length]) if length < 126 else bytes([0x80 | opcode, 0xFE]) + struct.pack("!H", length)
    stream.sendall(header + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))


def receive_binary(stream):
    while True:
        first, second = read_exact(stream, 2)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", read_exact(stream, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", read_exact(stream, 8))[0]
        if length > 65536 or second & 0x80:
            raise RuntimeError("Invalid relay WebSocket frame")
        payload = read_exact(stream, length)
        opcode = first & 0x0F
        if opcode == 9:
            send_frame(stream, 10, payload)
        elif opcode in (0, 2):
            return payload
        elif opcode != 10:
            raise RuntimeError("Relay closed or returned an unexpected WebSocket frame")


def feature(kind, data):
    return bytes([kind]) + struct.pack("!H", len(data)) + data


def relay_request(username, password, destination, port, udp=True, bind=False):
    features = b""
    if password is not None:
        user, secret = username.encode(), password.encode()
        features += feature(1, bytes([len(user)]) + user + bytes([len(secret)]) + secret)
    try:
        address = ipaddress.ip_address(destination)
        encoded = bytes([1 if address.version == 4 else 4]) + address.packed
    except ValueError:
        hostname = destination.encode("idna")
        encoded = bytes([3, len(hostname)]) + hostname
    features += feature(2, encoded + struct.pack("!H", port))
    command = (2 if bind else 1) | (0x80 if udp else 0)
    return bytes([1, command]) + struct.pack("!H", len(features)) + features


@contextmanager
def websocket_connection(domain, relay_port=443, secure=True, path="/ws", headers=None, timeout=15):
    with socket.create_connection((domain, relay_port), timeout=25) as tcp:
        stream = ssl.create_default_context().wrap_socket(tcp, server_hostname=domain) if secure else tcp
        try:
            stream.settimeout(timeout)
            key = base64.b64encode(os.urandom(16)).decode()
            extra = "".join(f"{name}: {value}\r\n" for name, value in (headers or {}).items())
            stream.sendall((f"GET {path} HTTP/1.1\r\nHost: {domain}\r\nConnection: Upgrade\r\n"
                            f"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n{extra}\r\n").encode())
            response = b""
            while not response.endswith(b"\r\n\r\n"):
                response += read_exact(stream, 1)
                if len(response) > 16384:
                    raise RuntimeError("Unexpectedly large relay HTTP response")
            if response.split(b"\r\n", 1)[0].split()[1] != b"101":
                raise RuntimeError("Relay did not accept the WebSocket upgrade")
            expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            headers = {name.strip().lower(): value.strip() for name, value in
                       (line.split(b":", 1) for line in response.split(b"\r\n")[1:] if b":" in line)}
            if headers.get(b"sec-websocket-accept") != expected:
                raise RuntimeError("Invalid WebSocket upgrade response")
            yield stream
        finally:
            if stream is not tcp:
                stream.close()


def relay_response(stream):
    reply = b""
    while len(reply) < 4:
        reply += receive_binary(stream)
    if reply[0] != 1:
        raise RuntimeError("Unexpected GOST relay protocol version")
    return reply[1]


def relay_status(domain, username, password, destination, port, relay_port=443, secure=True, **options):
    with websocket_connection(domain, relay_port=relay_port, secure=secure) as stream:
        send_frame(stream, 2, relay_request(username, password, destination, port, **options))
        return relay_response(stream)


def check_cases(domain, username, password, destination, port, **connection):
    wrong_password = ("0" if password[0] != "0" else "1") + password[1:]
    cases = [
        ("valid username/password and allowed UDP destination", username, password, port, {}, 0),
        ("incorrect password", username, wrong_password, port, {}, 2),
        ("missing authentication", username, None, port, {}, 2),
        ("incorrect username", "invalid-" + username, password, port, {}, 2),
        ("disallowed UDP port", username, password, 1 if port != 1 else 2, {}, 3),
        ("TCP forwarding", username, password, port, {"udp": False}, 3),
        ("reverse forwarding/BIND", username, password, port, {"bind": True}, 3),
    ]
    for name, user, secret, target_port, options, expected in cases:
        status = relay_status(domain, user, secret, destination, target_port, **connection, **options)
        if status != expected:
            raise RuntimeError(f"FAIL {name}: relay status {status}, expected {expected}")
        print(f"PASS {name}: relay status {status}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", default="example.com", help="allowed destination hostname; no UDP application data is sent")
    args = parser.parse_args()
    env_path = Path(__file__).resolve().parent.parent / ".env"
    values = dict(line.split("=", 1) for line in env_path.read_text().splitlines()
                  if line and not line.startswith("#") and "=" in line)
    domain = values["WGPROXY_DOMAIN"]
    check_cases(domain, values["WGPROXY_USERNAME"], values["WGPROXY_PASSWORD"], args.destination,
                int(values.get("WGPROXY_UDP_PORT", "51820")))
    print(f"Verified {domain}: TLS, authenticated GOST relay over WSS, UDP port policy and BIND denial.")


if __name__ == "__main__":
    main()
