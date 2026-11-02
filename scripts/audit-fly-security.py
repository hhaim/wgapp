#!/usr/bin/env python3
"""Read-only audit of Fly relay ingress, runtime isolation and secret hygiene."""
import json
import argparse
from pathlib import Path
import shlex
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent.parent
# This program returns only booleans, metadata and paths, never credential values.
RUNTIME_AUDIT = r'''
import json, pathlib
processes = []
secrets = []
for path in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
    try:
        arguments = [part for part in path.read_bytes().split(b'\0') if part]
        if not arguments or pathlib.Path(arguments[0].decode()).name != 'gost':
            continue
        base = path.parent
        environment = dict(part.split(b'=', 1) for part in (base / 'environ').read_bytes().split(b'\0') if b'=' in part)
        secrets = [environment.get(name, b'') for name in (b'WGPROXY_PASSWORD', b'WGPROXY_ACCESS_KEY')]
        status = dict(line.split(':', 1) for line in (base / 'status').read_text().splitlines() if ':' in line)
        processes.append({'pid': int(base.name), 'uid': int(status['Uid'].split()[1]),
                          'argv_is_stdin_config': arguments[-2:] == [b'-C', b'-'],
                          'argv_secret_free': not any(secret and secret in b'\0'.join(arguments) for secret in secrets)})
    except (FileNotFoundError, ProcessLookupError):
        continue
matches = []
for folder in ('/app', '/tmp', '/home/wgproxy'):
    for path in pathlib.Path(folder).rglob('*'):
        if path.is_file() and not path.is_symlink() and path.stat().st_size < 1048576:
            if any(secret and secret in path.read_bytes() for secret in secrets):
                matches.append(str(path))
files = [{'path': str(path), 'uid': path.stat().st_uid, 'mode': path.stat().st_mode & 0o777}
         for path in pathlib.Path('/app').iterdir() if path.is_file()]
print(json.dumps({'processes': processes, 'credential_scan_has_password': bool(secrets and secrets[0]),
                  'credential_file_matches': matches, 'app_files': files}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-legacy-http", action="store_true", help="audit the old 80-to-443 redirect before the user publishes the 443-only config")
    args = parser.parse_args()
    values = dict(line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines()
                  if line and not line.startswith("#") and "=" in line)
    app = values["FLY_APP"]
    fly = shutil.which("flyctl") or shutil.which("fly")
    if not fly:
        raise RuntimeError("Install/login to flyctl before the read-only audit")

    def call(*arguments):
        result = subprocess.run([fly, *arguments], capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError("Fly read-only inspection failed; check flyctl login/connectivity")
        return result.stdout

    machines = json.loads(call("machine", "list", "--app", app, "--json"))
    if len(machines) != 1:
        raise RuntimeError("Expected the current single-Machine relay; audit each Machine explicitly if scaled")
    machine = machines[0]
    config = machine["config"]
    services = config.get("services", [])
    assert len(services) == 1, "Unexpected extra public services"
    service = services[0]
    assert service["protocol"] == "tcp" and service["internal_port"] == 8080, "Unexpected ingress protocol/port"
    ports = {port["port"]: port for port in service["ports"]}
    expected_ports = {80, 443} if args.allow_legacy_http else {443}
    assert set(ports) == expected_ports, "Expected 443-only ingress; publish relay/fly.toml first, or use --allow-legacy-http only to audit the previous configuration"
    if 80 in ports:
        assert ports[80].get("force_https") and "http" in ports[80]["handlers"], "Plain HTTP is not redirect-only"
    assert {"http", "tls"}.issubset(ports[443]["handlers"]), "Public relay missing TLS termination"
    assert not config.get("mounts"), "Unexpected persistent volume"
    assert not {"WGPROXY_PASSWORD", "WGPROXY_ACCESS_KEY"}.intersection(config.get("env", {})), "Credential in public Machine env configuration"
    print("PASS deployed service: " + ("legacy TCP 80 redirect / 443 TLS" if 80 in ports else "TCP 443 TLS only") + "; no UDP ingress, extra services or volumes")
    print("PASS passwords absent from public Machine configuration env")
    secrets = json.loads(call("secrets", "list", "--app", app, "--json"))
    names = {entry["name"] for entry in secrets if entry.get("status") == "Deployed"}
    assert {"WGPROXY_USERNAME", "WGPROXY_PASSWORD"}.issubset(names), "GOST credentials missing from deployed Fly secrets"
    print("PASS GOST credentials deployed as Fly secrets (values not read)")
    legacy = names.intersection({"WGPROXY_ACCESS_KEY", "WGPROXY_ALLOWED_DOMAIN_PATTERN"})
    if legacy:
        print("WARN unused wstunnel secrets remain: " + ", ".join(sorted(legacy)))
    concurrency = service.get("concurrency", {})
    print("INFO Machine connection limit: " + str(concurrency.get("hard_limit")) + "; not an authentication rate limit")
    output = call("ssh", "console", "--app", app, "--machine", machine["id"],
                  "--command", "python3 -c " + shlex.quote(RUNTIME_AUDIT))
    runtime = json.loads(next(line for line in output.splitlines() if line.startswith(b'{"processes":')))
    assert len(runtime["processes"]) == 1, "Expected one GOST process"
    process = runtime["processes"][0]
    assert process["uid"] != 0, "GOST is running as root"
    assert process["argv_is_stdin_config"] and process["argv_secret_free"], "GOST config/credentials exposed in argv"
    assert runtime["credential_scan_has_password"], "Runtime credential scan did not obtain a password to check"
    assert not runtime["credential_file_matches"], "Credential file found: " + ", ".join(runtime["credential_file_matches"])
    print("PASS running GOST is nonroot and receives configuration through stdin; argv is credential-free")
    print("PASS no current/legacy relay password in regular files under /app, /tmp or /home/wgproxy (<1 MiB)")
    writable_code = [item["path"] for item in runtime["app_files"]
                     if item["uid"] == process["uid"] and item["mode"] & 0o200]
    if writable_code:
        print("WARN runtime user owns writable bootstrap files: " + ", ".join(writable_code))
    # Capture logs in memory and compare locally; never print their raw contents.
    logs = call("logs", "--app", app, "--no-tail")
    assert values["WGPROXY_PASSWORD"].encode() not in logs, "Current relay password found in recent Fly logs"
    print("PASS current relay password absent from retrieved recent Fly logs (not a complete historical log audit)")
    print("Read-only audit finished; no secret, deployment or policy changes made.")


if __name__ == "__main__":
    main()
