#!/usr/bin/env python3
"""Build the authenticated GOST relay configuration and exec GOST via stdin."""
import argparse
import json
import os
import re


def build_config(environment):
    username = environment.get("WGPROXY_USERNAME", "")
    password = environment.get("WGPROXY_PASSWORD", "")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", username):
        raise ValueError("WGPROXY_USERNAME must contain 1–64 letters, digits, underscores, dots or hyphens")
    if not re.fullmatch(r"[a-f0-9]{64}", password):
        raise ValueError("WGPROXY_PASSWORD must contain 64 lowercase hexadecimal characters")
    raw_port = environment.get("WGPROXY_UDP_PORT", "51820")
    if not re.fullmatch(r"[0-9]{1,5}", raw_port) or not 1 <= int(raw_port) <= 65535:
        raise ValueError("WGPROXY_UDP_PORT must be between 1 and 65535")
    legacy_pattern = environment.get("WGPROXY_ALLOWED_DOMAIN_PATTERN", "^.*$")
    if not environment.get("WGPROXY_ALLOWED_DOMAINS") and legacy_pattern != "^.*$":
        raise ValueError("Replace the old domain regex with WGPROXY_ALLOWED_DOMAINS hostname wildcards")
    domains = [item.strip().lower() for item in environment.get("WGPROXY_ALLOWED_DOMAINS", "*").split(",")]
    if not 1 <= len(domains) <= 16 or any(
        not re.fullmatch(r"[a-z0-9*?.-]{1,253}", item) or ".." in item for item in domains
    ):
        raise ValueError("WGPROXY_ALLOWED_DOMAINS must be 1–16 comma-separated hostname wildcard patterns")
    return {
        "log": {"level": "error", "output": "stderr", "format": "json"},
        "services": [{
            "name": "wgproxy", "addr": "[::]:8080", "bypass": "wireguard-udp-only",
            "handler": {
                "type": "relay", "auth": {"username": username, "password": password},
                "metadata": {"bind": False, "readTimeout": "10s", "udpBufferSize": 4096, "nodelay": True},
            },
            "listener": {
                "type": "ws", "metadata": {"path": "/ws", "readHeaderTimeout": "10s", "handshakeTimeout": "10s"},
            },
        }],
        "bypasses": [{
            "name": "wireguard-udp-only", "whitelist": True, "network": "udp",
            "matchers": [f"{domain}:{int(raw_port)}" for domain in domains],
        }],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate environment without printing the password or starting GOST")
    args = parser.parse_args()
    try:
        config = build_config(os.environ)
    except ValueError as error:
        parser.exit(2, f"Invalid relay settings: {error}\n")
    if args.check:
        print("GOST relay settings valid: authenticated /ws, UDP-only, configured WG port, BIND disabled")
        return
    # The bounded configuration fits in an anonymous pipe. No credential/config
    # file is created, and argv only contains '-C -'.
    payload = json.dumps(config).encode()
    reader, writer = os.pipe()
    with os.fdopen(writer, "wb") as stream:
        stream.write(payload)
    os.dup2(reader, 0)
    if reader != 0:
        os.close(reader)
    os.execvp("gost", ["gost", "-C", "-"])


if __name__ == "__main__":
    main()
