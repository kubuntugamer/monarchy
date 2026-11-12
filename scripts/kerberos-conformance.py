#!/usr/bin/env python3
"""Kerberos conformance, driven by MIT's own client.

Every check here is made by `kinit`, `klist` and `kvno` from MIT krb5 — the
reference implementation, not this tree's encoder — against a running DC. The
questions are the ones a client actually depends on: does a TGT come back at
all, do the ticket flags say what the client asked for, does a service ticket
arrive for the account that holds the SPN, and are the wrong-password and
unknown-principal refusals the ones a client can tell apart.

The flag checks are why this driver exists. `klist -f` prints the ticket flags
RFC 4120 §5.3 defines, and the KDC used to mark every TGT with the bit for
*forwardable* while never marking it *initial* — one wrong constant, invisible
from inside the tree and visible to every client.

Usage:
  scripts/kerberos-conformance.py [options]

Options:
  --kdc HOST             KDC address. Default: 127.0.0.1
  --kdc-port PORT        KDC port. Default: 88
  --realm REALM          Kerberos realm. Default: CI.EXAMPLE.ORG
  --user USER            Account to authenticate as. Default: Administrator
  --password PASS        Its password. Default: P@ssw0rd123!
  --dc-host NAME         Host holding the service SPNs. Default: derived from
                         the realm's first label, e.g. cidc1.example.org
  --kinit PATH           Client binary. Default: kinit
  --kvno PATH            Service-ticket client. Default: kvno
  --list                 Only list the checks that would run.

Exit status is 0 when every check passes, 1 otherwise.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

CHECKS = [
    'kinit gets a TGT for the account and klist reads it back',
    'the TGT is marked initial and pre-authenticated (IA)',
    'a TGT nobody asked to forward is not marked forwardable',
    'kinit -f yields a TGT marked forwardable (FIA)',
    'kvno gets a service ticket, and it carries the TGT\'s forwardable flag',
    'the TGT session key is AES-256',
    'a wrong password is refused as "Password incorrect"',
    'an account that does not exist is refused as "not found in Kerberos database"',
]

AES256 = 'aes256-cts-hmac-sha1-96'


def krb5_conf(realm, host, port):
    """A minimal client configuration, so nothing in /etc decides what this
    driver tests."""
    return f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    udp_preference_limit = 1

[realms]
    {realm} = {{
        kdc = {host}:{port}
    }}

[domain_realm]
    .{realm.lower()} = {realm}
    {realm.lower()} = {realm}
"""


class Driver:
    def __init__(self, options, conf, workdir):
        self.options = options
        self.workdir = workdir
        self.env = dict(os.environ)
        self.env['KRB5_CONFIG'] = conf
        self.env['KRB5CCNAME'] = 'FILE:' + os.path.join(workdir, 'ccache')
        self.env.pop('KRB5_CLIENT_KTNAME', None)
        for stale in ('ccache',):
            path = os.path.join(workdir, stale)
            if os.path.exists(path):
                os.unlink(path)

    def run(self, binary, args, password=None):
        command = [binary] + args
        return subprocess.run(command, input=password, capture_output=True,
                              text=True, env=self.env, timeout=60)

    def kinit(self, forwardable=False, password=None):
        args = ['-f'] if forwardable else []
        args.append(f'{self.options.user}@{self.options.realm}')
        return self.run(self.options.kinit, args,
                        password=self.options.password if password is None else password)

    def klist(self, *args):
        return self.run('klist', ['-f'] + list(args))

    def flags_of(self, service):
        """The flag letters klist prints for the cache entry of `service`."""
        result = self.klist()
        current = None
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('Flags:'):
                if current is not None and service in current:
                    return stripped.partition(':')[2].strip()
                continue
            if '@' in stripped and service in stripped:
                current = stripped
            elif 'krbtgt/' in stripped and service == 'krbtgt':
                current = stripped
        return None

    def check_kinit(self):
        result = self.kinit()
        if result.returncode != 0:
            return False, (result.stderr or result.stdout).strip()
        listing = self.klist()
        if listing.returncode != 0 or 'krbtgt/' not in listing.stdout:
            return False, f'klist exit {listing.returncode}: {(listing.stderr or "").strip()}'
        return True, f'cache holds krbtgt/{self.options.realm}'

    def check_initial_flag(self):
        flags = self.flags_of('krbtgt')
        if flags is None:
            return False, 'klist printed no flags line for the TGT'
        # RFC 4120 §5.3: I is initial, A is pre-authenticated. Every TGT has
        # both; a client that authenticates itself needs the pair.
        missing = [letter for letter in 'IA' if letter not in flags]
        if missing:
            return False, f'flags {flags!r} lack {"".join(missing)}'
        return True, f'flags {flags}'

    def check_not_forwardable_unasked(self):
        result = self.kinit()
        if result.returncode != 0:
            return False, (result.stderr or result.stdout).strip()
        flags = self.flags_of('krbtgt')
        if flags is None:
            return False, 'klist printed no flags line for the TGT'
        if 'F' in flags:
            return False, f'flags {flags!r} claim forwardable although none was requested'
        return True, f'flags {flags}'

    def check_forwardable(self):
        result = self.kinit(forwardable=True)
        if result.returncode != 0:
            return False, (result.stderr or result.stdout).strip()
        flags = self.flags_of('krbtgt')
        if flags is None:
            return False, 'klist printed no flags line for the TGT'
        missing = [letter for letter in 'FI' if letter not in flags]
        if missing:
            return False, f'flags {flags!r} lack {"".join(missing)}'
        return True, f'flags {flags}'

    def check_service_ticket(self):
        result = self.kinit(forwardable=True)
        if result.returncode != 0:
            return False, (result.stderr or result.stdout).strip()
        principal = f'host/{self.options.dc_host}@{self.options.realm}'
        service = self.run(self.options.kvno, [principal])
        if service.returncode != 0:
            return False, (service.stderr or service.stdout).strip()
        # The service ticket inherits the TGT's forwardable flag; a client
        # cannot show a forwardable credential without it.
        flags = self.flags_of(f'host/{self.options.dc_host}')
        if flags is None:
            # klist prints no flags line at all for a ticket whose flag word is
            # zero, which is itself the finding: the credential is unusable for
            # anything a forwardable one is needed for.
            return False, f'klist printed no flags line for {principal}'
        if 'F' not in flags:
            return False, f'service ticket flags {flags!r} lost the forwardable flag'
        return True, f'flags {flags} for {principal}'

    def check_session_key(self):
        result = self.kinit()
        if result.returncode != 0:
            return False, (result.stderr or result.stdout).strip()
        listing = self.run('klist', ['-e'])
        if AES256 not in listing.stdout:
            return False, f'klist -e names no {AES256} key'
        return True, AES256

    def check_wrong_password(self):
        result = self.kinit(password='deliberately-wrong-password')
        text = (result.stderr or result.stdout).strip()
        if result.returncode == 0:
            return False, 'the wrong password was accepted'
        if 'Password incorrect' not in text:
            return False, text.splitlines()[0] if text else 'no diagnostic'
        return True, text.splitlines()[0]

    def check_unknown_principal(self):
        # Nothing in the realm carries this name, so the KDC has no key to
        # encrypt a reply with and the client must say so rather than fail on
        # the password.
        result = self.run(self.options.kinit,
                          [f'nosuchuser-{os.urandom(3).hex()}@{self.options.realm}'],
                          password=self.options.password)
        text = (result.stderr or result.stdout).strip()
        if result.returncode == 0:
            return False, 'an account that does not exist was issued a ticket'
        if 'not found in Kerberos database' not in text:
            return False, text.splitlines()[0] if text else 'no diagnostic'
        return True, text.splitlines()[0]


def main():
    parser = argparse.ArgumentParser(add_help=True, description=__doc__.splitlines()[0])
    parser.add_argument('--kdc', default='127.0.0.1')
    parser.add_argument('--kdc-port', type=int, default=88)
    parser.add_argument('--realm', default='CI.EXAMPLE.ORG')
    parser.add_argument('--user', default='Administrator')
    parser.add_argument('--password', default='P@ssw0rd123!')
    parser.add_argument('--dc-host', default='')
    parser.add_argument('--kinit', default='kinit')
    parser.add_argument('--kvno', default='kvno')
    parser.add_argument('--list', action='store_true')
    options = parser.parse_args()

    if options.list:
        for description in CHECKS:
            print(description)
        return 0

    for binary in (options.kinit, options.kvno, 'klist'):
        if not shutil.which(binary):
            print(f'kerberos-conformance: {binary} not on PATH (the krb5-user package)',
                  file=sys.stderr)
            return 1

    if not options.dc_host:
        label = options.realm.split('.')[0].lower()
        options.dc_host = f'{label}dc1.{options.realm.lower()}'

    print(f'Kerberos conformance against {options.kdc}:{options.kdc_port}, '
          f'realm {options.realm}, services on {options.dc_host}')

    with tempfile.TemporaryDirectory(prefix='monarchy-krb5-') as workdir:
        conf = os.path.join(workdir, 'krb5.conf')
        with open(conf, 'w', encoding='utf-8') as handle:
            handle.write(krb5_conf(options.realm, options.kdc, options.kdc_port))
        driver = Driver(options, conf, workdir)
        checks = [
            driver.check_kinit,
            driver.check_initial_flag,
            driver.check_not_forwardable_unasked,
            driver.check_forwardable,
            driver.check_service_ticket,
            driver.check_session_key,
            driver.check_wrong_password,
            driver.check_unknown_principal,
        ]
        failures = 0
        for description, check in zip(CHECKS, checks):
            try:
                passed, detail = check()
            except Exception as error:  # noqa: BLE001 - a client that dies is a failed check
                passed, detail = False, f'{type(error).__name__}: {error}'
            print(f'  {"ok  " if passed else "FAIL"} {description}')
            if not passed:
                failures += 1
                print(f'       {detail}')
    if failures:
        print(f'{failures} of {len(checks)} checks failed')
        return 1
    print(f'{len(checks)} checks, all passing')
    return 0


if __name__ == '__main__':
    sys.exit(main())
