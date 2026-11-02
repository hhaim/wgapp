# WGApp

A native macOS WireGuard launcher with Touch ID profiles, direct connections, and an optional authenticated GOST relay on Fly.io. One profile contains both IPv4/IPv6 endpoints and proxy credentials; choose the connection mode each time.

Direct mode has been tested with WireGuard. GOST authentication and real UDP round trips through Fly have been tested. A complete home WireGuard handshake through proxy mode must also be verified with your profile.

## Requirements

- macOS 14 or later, Touch ID enrolled, and a local logged-in GUI session.
- Apple Command Line Tools: `xcode-select --install` if missing.
- An existing home WireGuard peer and reachable endpoint. This project changes no home ports or configuration.
- For proxy mode: a Fly.io account with billing enabled, `flyctl`, and `jq`.

The installer uses Homebrew for `wireguard-tools` and `wireguard-go`. It prepares the official checksum-pinned GOST 3.3.2 client automatically. No paid Apple signing account is required.

## Build and install on macOS

Open Terminal in the repository directory:

```sh
./b build
./b install
open /Applications/WGApp.app
```

`./b build` compiles and signs the app/helpers under `build/` without sudo. `./b install` prepares dependencies, builds the app, installs it into `/Applications`, and uses sudo to install:

- `/usr/local/libexec/wgapp-root`: root launcher.
- `/usr/local/libexec/wgapp-gost`: verified GOST client.
- `/etc/sudoers.d/wgapp`: passwordless authorization for exactly the launcher's `up`, `down`, and `status` commands.

The installation sudo password is separate from profile authentication. Normal connections use `sudo -n`; they do not request a sudo password.

After changing the app or launcher, quit WGApp, run `./b install`, and reopen it. If you only need to refresh the root helper, dependency and sudoers rule, use `./b install_sudo`. Running `./b install` already includes that step. For development, `./b run` builds and launches the app from `build/`.

## Add a profile

Open WGApp and use **+**. Enter:

| Field | Value |
| --- | --- |
| Name | Non-sensitive profile name, such as `home` |
| Interface IP | One address without CIDR, such as `10.0.0.2` |
| Allowed IPs | Comma-separated networks, such as `10.13.13.0/24,10.0.0.0/24` |
| DNS | One DNS server IP |
| Private key | Existing WireGuard private key |
| Preshared key | Optional WireGuard PSK; must match the home peer if used |
| Peer public key | Home peer's WireGuard public key |
| IPv4 hostname | Home's IPv4 endpoint domain |
| IPv6 hostname | Home's IPv6 endpoint domain |
| UDP port | Defaults to `51820` |

Key fields stay masked. There is one peer and one DNS server per profile. Default routes `0.0.0.0/0` and `::/0` are rejected. Hooks and `SaveConfig` are not supported.

Each complete profile is stored as one local login-Keychain item: service `WGApp`, account equal to the profile name, value equal to versioned JSON. Profile names can be listed without authentication. Editing, reading for connection, and deleting require Touch ID, with the enrolled biometric state checked by the helper. Profiles are not synced through iCloud Keychain.

If saving fails or Touch ID is cancelled, the fields remain in memory as a **Not saved** draft with an error in the main window. Edit to retry; quitting discards that draft.

## Connect directly

Select the profile, choose **Connect**, and leave **Use Fly.io proxy** off. Choose IPv4 or IPv6 and whether to replace macOS DNS with the profile's DNS server.

The app resolves the selected home endpoint, protects its physical-gateway route, creates a utun, applies WireGuard settings through stdin, and installs AllowedIPs routes. It shows **Connected** only after a complete WireGuard handshake. Direct MTU is physical MTU minus 60 for IPv4 or 80 for IPv6. `PersistentKeepalive = 25`.

Disconnect restores DNS and removes the interface, routes and helper processes. Only one profile can be active. The profile row shows endpoint, interface, gateway, MTU, handshake age, uptime and traffic statistics.

## Set up Fly.io

Install the deployment tools if needed and log in:

```sh
brew install flyctl jq
flyctl auth login
bash scripts/publish-flyio.sh --prepare
```

The prepare command creates `.env` from `.env.example` if absent and generates a random 256-bit GOST password if empty. It does not deploy. Existing credentials are retained. `.env` is mode 600 and excluded from Git.

Edit `.env` as needed. Values use plain `NAME=VALUE` lines without shell quotes; the script parses known settings and never executes the file.

| Setting | Default / purpose |
| --- | --- |
| `FLY_APP` | `my-wg-relay`; replace with a unique Fly app name |
| `FLY_ORG` | `personal` |
| `FLY_REGION` | `iad`; replace with your preferred Fly region |
| `WGPROXY_DOMAIN` | Custom hostname used by WGApp, such as `relay.example.com` |
| `WGPROXY_USERNAME` | `relay-user` |
| `WGPROXY_PASSWORD` | Generated 64-character hexadecimal password |
| `WGPROXY_UDP_PORT` | `51820`; permitted destination UDP port |
| `WGPROXY_ALLOWED_DOMAINS` | `*`; optional comma-separated hostname wildcards |

### Configure a public proxy hostname

Use a hostname you control so the public client configuration does not reveal the Fly app name. Create a dedicated DNS name, for example:

```dotenv
WGPROXY_DOMAIN=relay.example.com
```

Deploy the relay first, then add `WGPROXY_DOMAIN` as a custom hostname from the Fly dashboard's **Certificates** page. Follow the dashboard's DNS instructions at your DNS provider; Fly supports ownership verification with the records it displays and manages TLS for the hostname. Wait until the certificate is ready before running the live verification scripts. The [Fly networking documentation](https://fly.io/networking/) describes the custom-domain and managed-certificate flow.

Enter only the `WGPROXY_DOMAIN` hostname in WGApp—do not include `https://`, a port, or a path. The verification scripts read this explicit value and never derive a public hostname from `FLY_APP`.

Keep real app names, proxy domains, organization names, regions, usernames, and passwords in the ignored `.env` file. Committed files contain examples only.

For tighter destination control, use your exact home endpoint names, for example:

```dotenv
WGPROXY_ALLOWED_DOMAINS=ipv4.example.net,ipv6.example.net
```

Wildcards such as `*.example.net` are also supported. These are hostname patterns, not regular expressions. The default `*` permits authenticated forwarding to any destination, including private addresses, on the configured UDP port.

Deploy when ready:

```sh
./b publish_flyio
```

The command creates the app if absent, stages credentials as Fly secrets over stdin, validates the configuration and deploys one shared-CPU 256 MB Machine. It does not print the domain, username, or password. Machine runtime and traffic are billed to your Fly account. Auto stop/start is enabled for idle Machines.

Only `relay/` is uploaded as the Docker build context. No WG keys, profile JSON, home destinations or `.env` are included in the image. The nonroot relay constructs its GOST configuration in memory and passes it through stdin.

`relay/fly.toml` explicitly exposes **TCP 443 only**, with TLS terminated by Fly and internal WebSocket `/ws` on port 8080. There is no public UDP service or port-80 service. **Deploy this configuration to remove port 80 from an older deployment.** On shared Fly edge IPs, another TCP response on port 80 does not prove your app exposes it; verify the app's service metadata with the audit command below.

## Connect through Fly

Edit the existing profile and enable **Configure proxy for this profile**. Enter:

- Proxy domain: `WGPROXY_DOMAIN` from `.env`, without a scheme or port.
- GOST username: `WGPROXY_USERNAME` from `.env`.
- GOST password: `WGPROXY_PASSWORD` from `.env`.

Save, then enable **Use Fly.io proxy** in the connection sheet. Select the IPv4 or IPv6 home endpoint and DNS preference as usual. Different profiles can use different relays and credentials without duplicating their WireGuard keys for each mode.

```text
WireGuard → UDP 127.0.0.1:<local port> → GOST WSS/443 → Fly → UDP home endpoint
```

The launcher checks HTTPS reachability first, protects all resolved relay addresses with physical-gateway host routes, and pins the GOST connection to a reachable IP while verifying the relay hostname's TLS certificate. The client supplies the home hostname; Fly resolves it per connection. Proxy MTU is 1280 and keepalive is 25 seconds. A recent WG handshake is required for **Connected**.

Failure rolls back the client, interface, routes and DNS. The supervisor also cleans up when the proxy exits or the physical gateway/interface changes; reconnect after changing networks.

The GOST password protects relay access. It is **not** the optional WireGuard preshared key. Keep those fields separate.

## Authentication troubleshooting

- **Proxy checkbox gray:** edit the profile and configure its proxy domain/username/password. Update the app with `./b install` if running an older build.
- **Stale root helper:** run `./b install` and reopen WGApp. GOST requires launcher capability version 3.
- **Password while editing:** macOS can ask to approve a changed ad-hoc helper's access to an existing login-Keychain item. If the dialog names the expected `WGProfileHelper` and profile, **Always Allow** approves that helper. Its Touch ID check remains required. The build caches the helper separately so ordinary app/model changes do not change its signature.
- **Touch ID locked/unavailable:** unlock the Mac with its login password, then retry. WGApp uses a biometric-only policy with no password fallback button. A locked login Keychain can separately require its password.
- **Handshake fails:** verify home endpoint, peer keys, AllowedIPs and UDP port. Clear an optional WG PSK unless it is also configured on the home peer. A successful HTTPS/GOST check alone does not prove the home WG peer is reachable.

## Verification and security checks

Basic deployed TLS, authentication and UDP-policy checks, with no WG profile:

```sh
python3 scripts/verify-relay.py
python3 scripts/verify-relay-security.py --live
python3 scripts/audit-fly-security.py
```

For restrictive hostname rules, pass `--destination <allowed-home-hostname>` to the first two commands. The audit checks live service exposure, nonroot runtime, argv secrecy, selected credential-file locations and recent logs. Before removing port 80 from the old deployment, `--allow-legacy-http` audits its redirect configuration explicitly.

Local tests use synthetic credentials and loopback listeners:

```sh
python3 scripts/verify-relay-local.py
python3 scripts/verify-relay-security.py
python3 scripts/verify-gost-local.py
```

They cover malformed authentication/requests, forbidden networks and BIND, incomplete-handshake cleanup, hostname allowlist boundaries, local password rotation, datagram boundaries and packet bursts. A live incomplete handshake was observed closing after approximately 15 seconds; the backend is configured for 10 seconds and the external test allows 20 seconds.

For real UDP round trips through Fly with `.env` credentials and the app's exact client configuration:

```sh
xcrun swiftc -swift-version 5 -parse-as-library -module-cache-path build/ModuleCache Sources/Shared/ProfileModels.swift Sources/Shared/GOSTConfiguration.swift scripts/emit-gost-test-config.swift -o build/emit-gost-test-config
python3 scripts/verify-gost-fly.py
```

This starts a temporary loopback-only echo listener inside your Fly Machine, passes seven UDP packet sizes and a 32-packet burst, then exits. The listener has a 50-second receive timeout on failure. It requires the existing default `*` destination policy and refuses to change a restricted policy. It does not read WG keys or redeploy the app.

Security checks have found **no authentication bypass** in the tested cases. They also identified limits that should not be mistaken for a complete audit:

- A Go binary vulnerability scan of GOST 3.3.2 flags 10 known issues in compiled `golang.org/x/net` and `golang.org/x/crypto` dependencies. Reachability in this WS/UDP configuration has not been established. Update/rebuild and rescan dependencies before treating this as security-reviewed production software. This is not a Linux image/OS-package scan.
- The 100-connection Machine limit is not brute-force or bandwidth rate limiting. A public endpoint still consumes resources for rejected connections.
- The default destination wildcard is broad. Prefer a hostname allowlist. Older deployments may retain unused legacy Fly secrets; the runtime audit reports them for cleanup.
- Bootstrap files are root-owned in the current Dockerfile; older deployed images had runtime-user-owned files. Publish the updated image to apply this hardening.

## Publish the repository safely

Before adding files or pushing to GitHub:

```sh
python3 scripts/check-repo-secrets.py
```

This scans tracked and unignored publication candidates plus existing Git history for current `.env` credential values, encoded GOST credentials, private-key PEM bodies, WG secret-key assignments and common token patterns. It verifies `.env` is ignored and untracked. It never reads Keychain.

For a second scan with Gitleaks:

```sh
brew install gitleaks
gitleaks dir . --config .gitleaks.toml --redact --no-banner
```

`.gitleaks.toml` retains the default detection rules and excludes only local `.env` and generated/ignored build paths. `.env.example` is scanned and contains no password. Never force-add `.env` or publish deployment command output. Secret scans reduce accidental leaks; they cannot prove that arbitrary future credentials are absent.

WGApp creates no plaintext WG profile, editor swap file or temporary key file. Profile/configuration data travels through memory and anonymous pipes; runtime PID/name/socket files contain no profile material. Encrypted Keychain storage and macOS-managed swap, hibernation and diagnostics remain under OS control.

## Uninstall

Disconnect first, disable **Launch at Login** if enabled, then run:

```sh
make uninstall
```

Keychain profiles are preserved. Delete them in WGApp first if you also want to remove them. Fly deployment and billing are managed separately in your Fly account.
