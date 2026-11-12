#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the DC's endpoint mapper with impacket, an independent implementation.

An AD DC answers SAMR, LSAD, Netlogon and DRSR on dynamic ports, so every client
that is not told the port asks the endpoint mapper on 135 first. Two things can
be wrong without a local probe noticing either:

  * the mapper, and the endpoints it names, listen on loopback only, so a client
    on another host cannot reach them at all;

  * the tower names the loopback address, so a client that did reach the mapper
    is told to connect to its own 127.0.0.1.

Both were true of this server. This script asks over an address the caller
chooses — pass the DC's LAN address, not 127.0.0.1, to test what a remote client
sees — and then connects to the port in the tower to prove the answer is usable.

Every PDU is marshalled by impacket's NDR, never by this tree's encoder.

Usage:
  scripts/epm-conformance.py [options]

Options:
  --host HOST        Address to ask. Default: 127.0.0.1
  --epm-port PORT    Endpoint mapper port. Default: 135
  --advertised ADDR  Address the DC publishes for itself, and therefore the one
                     its towers must name. Default: 127.0.0.1
  --user USER        Account for the tower-port check. Default: Administrator
  --password PASS    Its password. Default: P@ssw0rd123!
  --domain DOMAIN    NetBIOS domain name. Default: MONARCHY
  --list             Only list the checks that would run.

Exit status is 0 when every check passes, 1 otherwise.
"""

import argparse
import sys

try:
    from impacket.dcerpc.v5 import epm, rpcrt, transport
    from impacket.uuid import string_to_bin, uuidtup_to_bin
except ImportError:  # pragma: no cover - reported, not raised
    sys.stderr.write(
        'epm-conformance: impacket is not importable; install it in this interpreter\n')
    sys.exit(2)

# The interface and version each endpoint answers on, as the protocol documents
# them. The version matters: the mapper matches on it, and asking for the wrong
# one gets an empty answer that looks like a missing endpoint.
INTERFACES = {
    'lsarpc': ('12345778-1234-abcd-ef00-0123456789ab', '0.0'),
    'samr': ('12345778-1234-abcd-ef00-0123456789ac', '1.0'),
    'netlogon': ('12345678-1234-abcd-ef00-01234567cffb', '1.0'),
    'drsuapi': ('e3514235-4b06-11d1-ab04-00c04fc2dcd2', '4.0'),
}

FLOOR_NCACN_TCP = b'\x07'
FLOOR_NCACN_NP = b'\x0f'
FLOOR_IP = b'\x09'

CREDENTIALS = {}
failures = []
ran = 0


def check(label, ok, detail=''):
    global ran
    ran += 1
    print(('PASS ' if ok else 'FAIL ') + label + ((' :: ' + str(detail)) if detail else ''))
    sys.stdout.flush()
    if not ok:
        failures.append(label)


def bind(host, port, interface=None):
    """A binding to host:port, or raises. Nothing here is local code.

    The endpoint mapper, and netlogon, answer an anonymous bind; SAMR, LSAD and
    DRSR want NTLM at the level a Windows client uses, so a refused anonymous
    bind is retried authenticated. Which one an endpoint accepts is its own
    choice and not what these checks are about.
    """
    binding = 'ncacn_ip_tcp:%s[%d]' % (host, port)
    if interface is None:
        dce = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        return dce
    try:
        dce = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        dce.connect()
        dce.bind(interface)
        return dce
    except Exception:
        pass
    t = transport.DCERPCTransportFactory(binding)
    t.set_credentials(CREDENTIALS['user'], CREDENTIALS['password'], CREDENTIALS['domain'])
    dce = t.get_dce_rpc()
    dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(interface)
    return dce


def lookup(dce, host, port, name):
    """Towers for one interface. The answer carries the server's whole map, so
    the interface floor — not the order of the list — decides what is ours."""
    uuid, version = INTERFACES[name]
    major, minor = (int(part) for part in version.split('.'))
    wanted = string_to_bin(uuid)
    out = []
    for entry in epm.hept_lookup('%s[%d]' % (host, port),
                                 ifId=uuidtup_to_bin((uuid, version)), dce=dce):
        iface = entry['tower']['Floors'][0].fields
        if (raw(iface['InterfaceUUID']) == wanted
                and iface['MajorVersion'] == major and iface['MinorVersion'] == minor):
            out.append(entry)
    return out


def raw(value):
    """A floor field as bytes: impacket shows some floors as hex, others decoded."""
    if isinstance(value, bytes):
        return value
    text = str(value)
    try:
        return bytes.fromhex(text)
    except ValueError:
        return text.encode('latin-1')


def floors(entry):
    """Protocol and data for each floor of a tower, protocol as one byte."""
    out = []
    for floor in entry['tower']['Floors']:
        fields = floor.fields
        if 'ProtocolData' in fields:
            out.append((raw(fields['ProtocolData']), raw(fields['RelatedData'])))
    return out


def tcp_port(entry):
    for protocol, data in floors(entry):
        if protocol == FLOOR_NCACN_TCP:
            return int.from_bytes(data, 'big')
    return None


def tower_address(entry):
    for protocol, data in floors(entry):
        if protocol == FLOOR_IP:
            return '.'.join(str(b) for b in data)
    return None


def has_pipe(entry):
    return any(protocol == FLOOR_NCACN_NP for protocol, _ in floors(entry))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--epm-port', type=int, default=135)
    parser.add_argument('--advertised', default='127.0.0.1')
    parser.add_argument('--user', default='Administrator')
    parser.add_argument('--password', default='P@ssw0rd123!')
    parser.add_argument('--domain', default='MONARCHY')
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args(argv)
    CREDENTIALS.update(user=args.user, password=args.password, domain=args.domain)

    if args.list:
        for name in ('bind epmapper', 'lookup each interface', 'port answers',
                     'tower address', 'pipe tower'):
            print(name)
        return 0

    where = '%s:%d' % (args.host, args.epm_port)
    try:
        dce = bind(args.host, args.epm_port)
        check('bind epmapper at %s' % where, True)
    except Exception as e:
        # Everything below needs this binding, and a refused connection is the
        # finding itself: the mapper is not listening where a client looks.
        check('bind epmapper at %s' % where, False, e)
        print('\n%d checks, %d failing' % (ran, len(failures)))
        return 1

    for name in INTERFACES:
        try:
            entries = lookup(dce, args.host, args.epm_port, name)
        except Exception as e:
            check('lookup %s' % name, False, e)
            continue
        tcp = [e for e in entries if tcp_port(e)]
        check('lookup %s' % name, bool(tcp),
              '%d tower(s), %d over ncacn_ip_tcp' % (len(entries), len(tcp)))
        if not tcp:
            continue

        port = tcp_port(tcp[0])
        address = tower_address(tcp[0])
        check('%s tower names %s' % (name, args.advertised), address == args.advertised, address)

        # A tower is a promise about where to connect. Keep it: the port it
        # names has to accept a bind for the interface it named, from a client
        # that only read the answer.
        uuid, version = INTERFACES[name]
        try:
            other = bind(address or args.host, port, uuidtup_to_bin((uuid, version)))
            other.disconnect()
            check('%s tower port %d answers' % (name, port), True)
        except Exception as e:
            check('%s tower port %d answers' % (name, port), False, e)

        if name == 'lsarpc':
            # The named pipe is how a Windows client reaches the same endpoint,
            # and it lives on SMB rather than on this port: losing it would not
            # show up in any of the checks above.
            check('lsarpc advertises an ncacn_np tower', any(has_pipe(e) for e in entries))

    dce.disconnect()
    print('\n%d checks, %d failing' % (ran, len(failures)))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
