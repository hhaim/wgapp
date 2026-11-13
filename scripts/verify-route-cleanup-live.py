#!/usr/bin/env python3
"""Exercise the freshly built helper using synthetic keys and reserved test networks.

Requires existing noninteractive sudo authorization. Does not install a helper, read
Keychain, change DNS, or toggle Wi-Fi. Refuses to run with an existing WGApp session.
"""
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / 'build/Build/Products/Debug/WGApp.app/Contents/Helpers/WGRootHelper'
INSTALLED = Path('/usr/local/libexec/wgapp-root')
TUNNEL = '198.18.42.0/24'
ENDPOINT = '192.0.2.200'
LOGICAL = 'wga-' + secrets.token_hex(5)
RUNTIME = Path('/var/run/wgapp')
NAME = Path('/var/run/wireguard') / (LOGICAL + '.name')


def run(args, data=None, check=True):
    return subprocess.run([str(a) for a in args], input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=check, timeout=20)


def sudo(*args, data=None, check=True):
    return run(['/usr/bin/sudo', '-n', *args], data, check)


def route(network):
    result = run(['/sbin/route', '-n', 'get', '-inet', network], check=False)
    if result.returncode:
        return None
    fields = {}
    for line in result.stdout.decode().splitlines():
        if ':' in line:
            key, value = line.strip().split(':', 1)
            fields[key] = value.strip()
    return fields


def exact(network):
    fields = route(network)
    if not fields:
        return None
    dest = fields.get('destination')
    mask = fields.get('mask')
    if mask == 'default':
        return None
    try:
        observed = ipaddress.ip_network(dest + '/' + (mask or '32'), strict=False)
        expected = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return None
    return fields if observed == expected else None


def identity(fields):
    return {key: fields.get(key) for key in ('destination', 'mask', 'gateway', 'interface', 'flags')}


def wait_for(predicate, description):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise RuntimeError('Timed out: ' + description)


def invoke(command, payload, check=True):
    return sudo(HELPER, command, data=json.dumps(payload).encode(), check=check)


def down():
    invoke('down', {'logicalName': LOGICAL}, check=False)
    wait_for(lambda: not (RUNTIME / (LOGICAL + '.pid')).exists(), 'supervisor exit')
    wait_for(lambda: not NAME.exists(), 'managed name cleanup')


def main():
    if not HELPER.is_file():
        raise RuntimeError('Run ./b build first')
    for path in (INSTALLED, HELPER):
        print('Helper SHA-256:', path, hashlib.sha256(path.read_bytes()).hexdigest(), flush=True)
    if list(RUNTIME.glob('*.pid')) or list(NAME.parent.glob('wga-*.name')):
        raise RuntimeError('Disconnect existing WGApp sessions before live tests')
    if exact(TUNNEL) or exact(ENDPOINT):
        raise RuntimeError('Reserved test route already present; refusing to modify it')
    default = route('default')
    if not default or default['interface'].startswith('utun'):
        raise RuntimeError('A physical IPv4 default route is required')
    physical = default['interface']
    gateway = default['gateway']
    address = run(['/usr/sbin/ipconfig', 'getifaddr', physical]).stdout.decode().strip()
    mask = run(['/usr/sbin/ipconfig', 'getoption', physical, 'subnet_mask']).stdout.decode().strip()
    lan = str(ipaddress.ip_network(address + '/' + mask, strict=False))
    baseline = identity(exact(lan))
    wg = next(path for path in [Path('/opt/homebrew/bin/wg'), Path('/usr/local/bin/wg')] if path.is_file())
    private = run([wg, 'genkey']).stdout.strip()
    public = run([wg, 'pubkey'], private + b'\n').stdout.decode().strip()
    request = dict(logicalName=LOGICAL, privateKey=private.decode(), peerPublicKey=public,
                   address='198.18.43.1', allowedIPs=[TUNNEL], endpointHost=ENDPOINT,
                   endpointPort=51820, endpointFamily='ipv4', persistentKeepalive=25)
    # Confirm the actual tested helper advertises the fixed cleanup implementation.
    status = json.loads(invoke('status', {'logicalName': LOGICAL}).stdout)
    assert status.get('routeCleanupVersion') == 1
    installed = json.loads(sudo(INSTALLED, 'status', data=json.dumps({'logicalName': LOGICAL}).encode()).stdout)
    print('Installed routeCleanupVersion:', installed.get('routeCleanupVersion'), flush=True)
    replacement_created = False
    preserved_endpoint_created = False
    try:
        # The exact physical-LAN conflict must leave the baseline untouched.
        collision = dict(request, allowedIPs=[TUNNEL, lan])
        result = invoke('up', collision, check=False)
        assert result.returncode != 0, 'LAN collision was accepted'
        wait_for(lambda: exact(TUNNEL) is None, 'partial-start route release')
        assert identity(exact(lan)) == baseline
        assert exact(ENDPOINT) is None
        print('PASS live overlapping LAN conflict and partial-start rollback preserve baseline', flush=True)
        # A normal up/down removes only synthetic owned routes; a second down is harmless.
        invoke('up', request)
        assert exact(TUNNEL)['interface'].startswith('utun')
        assert exact(ENDPOINT)['interface'] == physical
        down()
        down()
        wait_for(lambda: exact(TUNNEL) is None, 'normal route release')
        assert exact(ENDPOINT) is None and identity(exact(lan)) == baseline
        print('PASS live normal disconnect and repeated down preserve LAN route', flush=True)
        # Pre-existing host routes must be retained even if marked with our protocol flags.
        sudo('/sbin/route', '-q', '-n', 'add', '-inet', '-host', ENDPOINT,
             '-gateway', gateway, '-ifp', physical, '-proto1', '-proto2')
        preserved_endpoint_created = True
        endpoint_baseline = identity(exact(ENDPOINT))
        invoke('up', request)
        down()
        wait_for(lambda: exact(TUNNEL) is None, 'normal route release')
        assert identity(exact(ENDPOINT)) == endpoint_baseline
        sudo('/sbin/route', '-q', '-n', 'delete', '-inet', '-host', ENDPOINT, '-gateway', gateway)
        preserved_endpoint_created = False
        print('PASS live pre-existing endpoint route survives tunnel cleanup unchanged', flush=True)
        # Abrupt utun loss, followed by a different interface owning the former prefix.
        result = json.loads(invoke('up', request).stdout)
        interface = result['interfaceName']
        sudo('/bin/rm', '/var/run/wireguard/' + interface + '.sock')
        wait_for(lambda: exact(TUNNEL) is None, 'unexpected utun exit')
        sudo('/sbin/route', '-q', '-n', 'add', '-inet', '-net', TUNNEL, '-interface', 'lo0')
        replacement_created = True
        wait_for(lambda: not (RUNTIME / (LOGICAL + '.pid')).exists(), 'unexpected-exit supervisor cleanup')
        down()
        assert exact(TUNNEL)['interface'] == 'lo0'
        assert exact(ENDPOINT) is None and identity(exact(lan)) == baseline
        print('PASS live unexpected tunnel exit preserves replacement interface route', flush=True)
    finally:
        down()
        if replacement_created and (exact(TUNNEL) or {}).get('interface') == 'lo0':
            sudo('/sbin/route', '-q', '-n', 'delete', '-inet', '-net', TUNNEL, '-interface', 'lo0')
        if preserved_endpoint_created and (exact(ENDPOINT) or {}).get('gateway') == gateway:
            sudo('/sbin/route', '-q', '-n', 'delete', '-inet', '-host', ENDPOINT, '-gateway', gateway)
    assert identity(exact(lan)) == baseline
    assert exact(TUNNEL) is None and exact(ENDPOINT) is None
    print('All live tests passed; synthetic routes removed. Wi-Fi changes and DNS retries are simulated in verify-route-cleanup.sh.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        # Input (including synthetic keys) is deliberately never logged.
        message = error.stderr.decode().strip()
        raise SystemExit(message + '\nLive tests require administrator authorization; run sudo -v in Terminal, then retry.')
