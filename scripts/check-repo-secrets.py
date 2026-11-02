#!/usr/bin/env python3
"""Check Git publication candidates without displaying credentials or reading Keychain."""
import base64
import re
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent


def git(*arguments):
    return subprocess.check_output(["git", "-C", str(ROOT), *arguments])


def main():
    tracked = set(git("ls-files", "-z").split(b"\0")) - {b""}
    candidates = sorted(set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""})
    env_path = ROOT / ".env"
    values = dict(line.split("=", 1) for line in env_path.read_text().splitlines()
                  if line and not line.startswith("#") and "=" in line) if env_path.exists() else {}
    tokens = [(name, value.encode()) for name, value in values.items()
              if re.search(r"PASSWORD|PRIVATE_KEY|PRESHARED_KEY|ACCESS_KEY|TOKEN|SECRET", name)
              and len(value) >= 8]
    if values.get("WGPROXY_USERNAME") and values.get("WGPROXY_PASSWORD"):
        tokens.append(("encoded GOST credentials", base64.b64encode(
            (values["WGPROXY_USERNAME"] + ":" + values["WGPROXY_PASSWORD"]).encode())))
    failures = []
    for name in tracked:
        if Path(name.decode()).name == ".env" or name.startswith(b"build/"):
            failures.append((name.decode(), "sensitive/generated path is tracked"))
    if subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "--no-index", ".env"]).returncode:
        failures.append((".env", "not excluded by .gitignore"))
    patterns = [
        ("private-key PEM", rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\r?\n(?:[A-Za-z0-9+/=]{4,}\r?\n){2,}"),
        ("literal WireGuard secret key", rb"(?:PrivateKey|PresharedKey|privateKey|presharedKey)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9+/]{43}="),
        ("literal relay credential", rb"(?:WGPROXY_(?:PASSWORD|ACCESS_KEY)|[\"'](?:password|accessKey)[\"'])\s*[:=]\s*[\"']?[a-f0-9]{64}\b"),
        ("GitHub token", rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
        ("Fly token", rb"\bFlyV1\s+[A-Za-z0-9_+/=-]{30,}"),
        ("AWS access key ID", rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ]
    for name in candidates:
        path = ROOT / name.decode()
        if path.is_symlink():
            failures.append((name.decode(), "review symlink before publication"))
            continue
        if not path.is_file():
            continue
        content = path.read_bytes()
        for label, token in tokens:
            if token in content:
                failures.append((name.decode(), "contains " + label + " value from .env"))
        for label, expression in patterns:
            if re.search(expression, content):
                failures.append((name.decode(), label))
    commits = git("rev-list", "--all").splitlines()
    print(f"Checked {len(candidates)} Git publication candidates and {len(commits)} existing commits; .env is ignored and untracked" if not failures
          else "Publication checks found issues:")
    # Check known .env credentials and private-key patterns in historical blobs.
    for line in git("rev-list", "--objects", "--all").splitlines():
        object_id, _, name = line.partition(b" ")
        if not name or git("cat-file", "-t", object_id.decode()).strip() != b"blob":
            continue
        content = git("cat-file", "blob", object_id.decode())
        for label, token in tokens:
            if token in content:
                failures.append(("history:" + name.decode(errors="replace"), "contains " + label + " from .env"))
        for label, expression in patterns:
            if re.search(expression, content):
                failures.append(("history:" + name.decode(errors="replace"), label))
    for path, message in sorted(set(failures)):
        print(f"FAIL {path}: {message} (value redacted)")
    if failures:
        raise SystemExit(1)
    print("PASS no known .env credential values or listed secret-key/token patterns in publication files/history")
    print("This is a targeted scan, complemented by Gitleaks; Keychain and WG profiles are never read.")


if __name__ == "__main__":
    main()
