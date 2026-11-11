#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive the DC's SMB2 transport with clients this tree did not write.

The other conformance drivers reach SAMR, LSAD and Netlogon over DCE/RPC on
TCP, so none of them would notice a broken pipe transport: a client that only
speaks the pipes a Windows member uses could be refused while every driver
here stayed green. This one goes through SMB instead, which is the path
`\\\\dc\\IPC$\\samr` and `\\\\dc\\SYSVOL` actually take.

The dialect is pinned rather than left to the client, because the server
answers only 2.0.2 and 2.1 and a client that is allowed to offer 3.x would say
nothing about which one it settled on. The pin is measured, not assumed:
Samba 4.24.7 rejects `SMB2_21` for `client max protocol` ("Ignoring invalid
value 'SMB2_21'"), accepts `SMB2_10` for SMB 2.1 (0x0210), and silently
downgrades `SMB3` to the same 0x0210, so `SMB2_10` is the only spelling that
asks for 2.1. Impacket's own constant is checked here against the number the
server reports, which is why the two negotiate checks read the negotiated
dialect back out of the client instead of trusting the request.

Two clients drive the pipes. Impacket marshals its own NDR, so a reply only
this tree's encoder understands fails. It authenticates at
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY rather than PKT_PRIVACY: impacket's SMB
transport does not feed the SMB session key into its sealed pipe requests, so a
privacy-level call over the pipe fails inside the client while Samba's own
sealed client succeeds against the same server. Integrity still proves the
auth trailer and the session key path, and the third check below drives the
same pipe with Samba's `rpcclient`, which picks its own auth level.

Usage:
  scripts/smb-conformance.py [options]

Options:
  --host HOST            DC address. Default: 127.0.0.1
  --port PORT            SMB port. Default: 445
  --user USER            Account to connect as. Default: Administrator
  --password PASS        Its password. Default: P@ssw0rd123!
  --domain DOMAIN        NetBIOS domain name. Default: MONARCHY
  --dns-domain NAME      Directory the SYSVOL share holds. Default: from --domain
  --sysvol-root PATH     Share root on disk, so a file can be read over SMB and
                         compared with its bytes. Without it that check fails.
  --smbclient PATH       Client binary. Default: smbclient
  --rpcclient PATH       Client binary. Default: rpcclient
  --list                 Only list the checks that would run.

Exit status is 0 when every check passes, 1 otherwise.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

from impacket.dcerpc.v5 import lsad, rpcrt, samr, transport
from impacket.smbconnection import SMB2_DIALECT_002, SMB2_DIALECT_21, SMBConnection

MAXIMUM_ALLOWED = 0x02000000

# MS-SMB2 2.2.3.1.3: the two revisions this server answers, as the numbers a
# client reports back. The pin above is what a client has to send to ask for
# them; these are what the server may answer with.
DIALECT_202 = 0x0202
DIALECT_210 = 0x0210

CHECKS = [
    'negotiate settles on SMB 2.1 (0x0210) when the client offers it',
    'negotiate settles on SMB 2.0.2 (0x0202) when the client offers only that',
    'an SMB 2.1 session opens SYSVOL and lists the domain directory',
    'a file read over SMB 2.1 matches the bytes on disk',
    'NETLOGON refuses a write over SMB 2.1 and creates nothing',
    r'\pipe\samr carries SAMR over SMB 2.1 (impacket NDR)',
    r'\pipe\lsarpc carries LSAD over SMB 2.1 (impacket NDR)',
    r'\pipe\samr serves SAMR to rpcclient over SMB 2.1',
]

(
    NEGOTIATE_21,
    NEGOTIATE_202,
    SESSION,
    FILE_BYTES,
    WRITE_REFUSED,
    PIPE_SAMR,
    PIPE_LSARPC,
    RPC_SAMR,
) = CHECKS

failures = []


def check(label, ok, detail=''):
    if label not in CHECKS:
        raise SystemExit('unknown check label: %r' % label)
    print(('PASS ' if ok else 'FAIL ') + label + ((' :: ' + str(detail)) if detail else ''))
    sys.stdout.flush()
    if not ok:
        failures.append(label)


def summary():
    print('\n%d failure(s): %s' % (len(failures), failures))
    return 0 if not failures else 1


def credential(options):
    return '%s\\%s%%%s' % (options.domain, options.user, options.password)


def run(argv, timeout=60):
    """Run a client and keep its streams; the exit status is the check's own,
    so it is read from the process and never from a pipeline."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        result = subprocess.CompletedProcess(argv, 124, '', 'timed out')
        return result


def smbclient(options, share, command):
    return run([
        options.smbclient,
        '//%s/%s' % (options.host, share),
        '-m', 'SMB2_10',
        '-p', str(options.port),
        '-U', credential(options),
        '-c', command,
    ])


def output(result):
    return (result.stdout + result.stderr).strip()


def negotiated(options, dialect):
    """The dialect the server picked, read back from the client. The session is
    only negotiated: no credential is sent, because the question is what the
    server offers, not who may use it."""
    connection = SMBConnection(options.host, options.host, sess_port=int(options.port),
                               preferredDialect=dialect)
    try:
        return connection.getDialect()
    finally:
        connection.close()


def pipe(options, name, uuid):
    """A DCE/RPC binding over \\\\host\\IPC$\\<name> at SMB 2.1. Impacket's SMB
    transport is used directly rather than through the ncacn_np factory, which
    derives the port from the binding string and would always use 445."""
    endpoint = transport.SMBTransport(options.host, dstport=int(options.port),
                                     filename='\\' + name)
    endpoint.preferred_dialect(SMB2_DIALECT_21)
    endpoint.set_credentials(options.user, options.password, options.domain)
    dce = endpoint.get_dce_rpc()
    dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
    dce.connect()
    dce.bind(uuid)
    return dce


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default='445')
    parser.add_argument('--user', default='Administrator')
    parser.add_argument('--password', default='P@ssw0rd123!')
    parser.add_argument('--domain', default='MONARCHY')
    parser.add_argument('--dns-domain', default='')
    parser.add_argument('--sysvol-root', default='')
    parser.add_argument('--smbclient', default='smbclient')
    parser.add_argument('--rpcclient', default='rpcclient')
    parser.add_argument('--list', action='store_true')
    options = parser.parse_args()

    if options.list:
        print('\n'.join(CHECKS))
        return 0

    dns_domain = options.dns_domain or (options.domain.lower() + '.local')

    for binary in (options.smbclient, options.rpcclient):
        if not any(os.access(os.path.join(path, binary), os.X_OK)
                   for path in os.environ.get('PATH', '').split(os.pathsep) if path):
            print('smb-conformance: %s is not on PATH (the smbclient package provides '
                  'both smbclient and rpcclient)' % binary, file=sys.stderr)
            return 1

    try:
        chosen = negotiated(options, SMB2_DIALECT_21)
        check(NEGOTIATE_21, chosen == DIALECT_210, 'dialect 0x%04x' % chosen)
    except Exception as error:  # noqa: BLE001 - a refused negotiate is the result
        check(NEGOTIATE_21, False, '%s: %s' % (type(error).__name__, error))
    try:
        chosen = negotiated(options, SMB2_DIALECT_002)
        check(NEGOTIATE_202, chosen == DIALECT_202, 'dialect 0x%04x' % chosen)
    except Exception as error:  # noqa: BLE001
        check(NEGOTIATE_202, False, '%s: %s' % (type(error).__name__, error))

    # One session, one tree: the directory the provisioner fills is the proof
    # that authentication, tree connect and readdir all completed at 2.1.
    try:
        result = smbclient(options, 'SYSVOL', 'ls')
        listed = output(result)
        ok = result.returncode == 0 and dns_domain.lower() in listed.lower()
        check(SESSION, ok, (listed.splitlines()[0] if listed else 'no output') if not ok else '')
    except Exception as error:  # noqa: BLE001
        check(SESSION, False, '%s: %s' % (type(error).__name__, error))

    # A file this script writes on disk, read back through the share: the bytes
    # a client sees have to be the bytes that are stored, which a listing alone
    # cannot show.
    fixture = 'smbconf-%s.bin' % os.urandom(4).hex()
    body = os.urandom(4096 + 37)
    local = os.path.join(tempfile.gettempdir(), fixture)
    if not options.sysvol_root:
        check(FILE_BYTES, False, '--sysvol-root not given, so nothing could be compared')
    else:
        stored = os.path.join(options.sysvol_root, fixture)
        try:
            with open(stored, 'wb') as handle:
                handle.write(body)
            result = smbclient(options, 'SYSVOL', 'get %s %s' % (fixture, local))
            read_back = None
            if os.path.exists(local):
                with open(local, 'rb') as handle:
                    read_back = handle.read()
                os.unlink(local)
            check(FILE_BYTES, result.returncode == 0 and read_back == body,
                  'rc=%d, %s of %d bytes' % (result.returncode,
                                             len(read_back) if read_back is not None else 'no',
                                             len(body)))
        except Exception as error:  # noqa: BLE001
            check(FILE_BYTES, False, '%s: %s' % (type(error).__name__, error))
        finally:
            if os.path.exists(stored):
                os.unlink(stored)

    # The shares are read-only by design, and a refusal that leaves the file
    # behind would be a lie: the write is attempted and the directory is then
    # listed for its name.
    forbidden = 'smbconf-write-%s.txt' % os.urandom(4).hex()
    local = os.path.join(tempfile.gettempdir(), forbidden)
    with open(local, 'w', encoding='utf-8') as handle:
        handle.write('this must not land on the share\n')
    try:
        result = smbclient(options, 'NETLOGON', 'put %s %s' % (local, forbidden))
        refused = result.returncode != 0 and 'NT_STATUS_ACCESS_DENIED' in output(result)
        listing = smbclient(options, 'NETLOGON', 'ls')
        absent = forbidden.lower() not in output(listing).lower()
        ok = refused and absent
        check(WRITE_REFUSED, ok, '' if ok else (output(result) or 'the write was accepted'))
    except Exception as error:  # noqa: BLE001
        check(WRITE_REFUSED, False, '%s: %s' % (type(error).__name__, error))
    finally:
        if os.path.exists(local):
            os.unlink(local)

    # SAMR over the pipe: the same calls scripts/samr-conformance.py makes over
    # TCP, so a difference between the two transports shows up as a difference
    # between two green drivers rather than as one driver that never runs.
    try:
        dce = pipe(options, 'samr', samr.MSRPC_UUID_SAMR)
        try:
            server = samr.hSamrConnect5(dce, '\\\\%s\x00' % options.host,
                                        MAXIMUM_ALLOWED, 1, 3)['ServerHandle']
            domains = [entry['Name'] for entry in
                       samr.hSamrEnumerateDomainsInSamServer(
                           dce, server, 0, 0x1000)['Buffer']['Buffer']]
            check(PIPE_SAMR, options.domain in domains, domains)
        finally:
            dce.disconnect()
    except Exception as error:  # noqa: BLE001
        check(PIPE_SAMR, False, '%s: %s' % (type(error).__name__, error))

    # LSAD over the pipe: the policy handle is the first call every LSA client
    # makes, and it needs the pipe rather than the TCP endpoint to exist.
    try:
        dce = pipe(options, 'lsarpc', lsad.MSRPC_UUID_LSAD)
        try:
            policy = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)
            opened = bool(policy['PolicyHandle'])
            check(PIPE_LSARPC, opened, '' if opened else 'the reply carried no policy handle')
        finally:
            dce.disconnect()
    except Exception as error:  # noqa: BLE001
        check(PIPE_LSARPC, False, '%s: %s' % (type(error).__name__, error))

    # And the same pipe with Samba's client, whose NDR, auth level and SMB
    # dialect choices are its own. The RID is the well-known Administrator one,
    # so the reply is checked against AD's value rather than against presence.
    try:
        result = run([
            options.rpcclient, '//%s' % options.host,
            '-p', str(options.port),
            '-m', 'SMB2_10',
            '-U', credential(options),
            '-c', 'enumdomusers',
        ])
        text = output(result)
        found = re.search(r'user:\[Administrator\]\s+rid:\[0x1f4\]', text, re.IGNORECASE)
        ok = result.returncode == 0 and bool(found)
        check(RPC_SAMR, ok, (text.splitlines()[0] if text else 'no output') if not ok else '')
    except Exception as error:  # noqa: BLE001
        check(RPC_SAMR, False, '%s: %s' % (type(error).__name__, error))

    return summary()


if __name__ == '__main__':
    sys.exit(main())
