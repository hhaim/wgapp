#!/usr/bin/env python3
"""Round-trip UDP through deployed Fly GOST with .env credentials and no WG keys."""
import json
from pathlib import Path
import secrets
import select
import shlex
import shutil
import socket
import subprocess
import time


ROOT = Path(__file__).resolve().parent.parent


def main():
    values = dict(line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines()
                  if line and not line.startswith("#") and "=" in line)
    if values.get("WGPROXY_ALLOWED_DOMAINS", "*") != "*":
        raise RuntimeError("Loopback echo test needs the existing wildcard policy; no relay policy was changed")
    fly = shutil.which("flyctl") or shutil.which("fly")
    if not fly:
        raise RuntimeError("flyctl is required for the temporary loopback echo listener")
    domain = values["WGPROXY_DOMAIN"]
    port = int(values.get("WGPROXY_UDP_PORT", "51820"))
    remote_code = (
        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
        f"s.bind(('127.0.0.1',{port})); s.settimeout(50); "
        "print('ECHO_READY',flush=True); "
        "exec('for _ in range(39):\\n data,peer=s.recvfrom(65535); s.sendto(data,peer)'); "
        "s.close(); print('ECHO_DONE',flush=True)"
    )
    remote = subprocess.Popen([fly, "ssh", "console", "--app", values["FLY_APP"], "--command",
                               "python3 -u -c " + shlex.quote(remote_code)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    client = None
    try:
        deadline = time.monotonic() + 40
        while True:
            if remote.poll() is not None:
                raise RuntimeError("Temporary Fly echo listener did not start: " + remote.stderr.read().decode(errors="replace")[-1200:])
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([remote.stdout], [], [], remaining)[0]:
                raise RuntimeError("Timed out waiting for the temporary Fly echo listener")
            if remote.stdout.readline().strip() == b"ECHO_READY":
                break
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            local_port = reserve.getsockname()[1]
        relay_ip = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        request = {"proxy": {"domain": domain, "username": values["WGPROXY_USERNAME"], "password": values["WGPROXY_PASSWORD"]},
                   "localPort": local_port, "endpointHost": "127.0.0.1", "endpointPort": port, "relayAddress": relay_ip}
        # The exact Swift builder used by the root launcher emits config to a pipe.
        configuration = subprocess.check_output([str(ROOT / "build/emit-gost-test-config")], input=json.dumps(request).encode())
        client = subprocess.Popen([str(ROOT / "build/tools/gost"), "-C", "-"], stdin=subprocess.PIPE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, cwd="/")
        client.stdin.write(configuration)
        client.stdin.close()
        deadline = time.monotonic() + 5
        while True:
            if client.poll() is not None:
                raise RuntimeError("GOST client failed to load the app's configuration")
            bound = subprocess.run(["/usr/sbin/lsof", "-a", "-p", str(client.pid),
                                    f"-iUDP@127.0.0.1:{local_port}", "-Fn"], capture_output=True)
            if bound.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("GOST client did not bind its loopback UDP listener")
            time.sleep(0.05)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            sender.settimeout(20)
            sender.connect(("127.0.0.1", local_port))
            for size in [1, 32, 92, 148, 1279, 1280, 1420]:
                payload = secrets.token_bytes(size)
                sender.send(payload)
                if sender.recv(65535) != payload:
                    raise RuntimeError("UDP payload changed through Fly relay")
            burst = [index.to_bytes(4, "big") + secrets.token_bytes(300) for index in range(32)]
            for payload in burst:
                sender.send(payload)
            if sorted(sender.recv(65535) for _ in burst) != sorted(burst):
                raise RuntimeError("UDP burst payload/boundary mismatch through Fly relay")
        if remote.wait(timeout=5) != 0:
            raise RuntimeError("Temporary Fly echo listener did not exit cleanly")
        print(f"PASS {domain}: .env username/password, verified WSS/TLS, app Swift configuration, seven UDP sizes and 32-packet burst")
        print("PASS temporary Fly echo listener exited; no WG profile or keys were read")
    finally:
        for process in [client, remote]:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        print("Test client/SSH stopped; remote echo listener has a 50-second receive timeout on failure.")


if __name__ == "__main__":
    main()
