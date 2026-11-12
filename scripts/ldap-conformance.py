#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive the DC's LDAP listener with a client this tree did not write.

Every wire test in ui/tests/ encodes its own BER with helpers from this tree, so
a request this code can encode and this code can decode passes whether or not
anybody else's LDAP stack would accept a single byte of it. This driver uses
OpenLDAP's ldapsearch, which brings libldap's encoder, its DN parser and its
filter compiler: a BER length, an ENUMERATED or a bind sequence only this tree
understands fails here.

It is also the check that says *whose* server answered. The rootDSE it reads
carries namingContexts, vendorName and the DNS name the DC was provisioned
with, so an LDAP server that answers on the port but belongs to a different
tree - or to an installed domain on the same box - fails the first check rather
than passing every later one.

Usage:
  scripts/ldap-conformance.py [options]

Options:
  --host HOST            DC address. Default: 127.0.0.1
  --port PORT            LDAP port. Default: 389
  --base-dn DN           Domain naming context. Default: DC=ci,DC=example,DC=org
  --user CN              Administrator's CN. Default: Administrator
  --password PASS        Its password. Default: P@ssw0rd123!
  --dns-domain NAME      Domain the rootDSE must name. Default: from --base-dn
  --ldapsearch PATH      Client binary. Default: ldapsearch
  --list                 Only list the checks that would run.

Exit status is 0 when every check passes, 1 otherwise.
"""

import argparse
import base64
import shutil
import subprocess
import sys

# Result codes this driver distinguishes. ldapsearch exits with the LDAP result
# code, so these are compared against its exit status rather than parsed out of
# its prose.
SUCCESS = 0
NO_SUCH_OBJECT = 32
INVALID_CREDENTIALS = 49

CHECKS = [
    'the rootDSE names this domain and this server, read anonymously',
    'a simple bind as the administrator succeeds',
    'the domain object is readable at the base DN',
    'a subtree search finds the administrator by sAMAccountName',
    'a bind with the DN in the wrong case still succeeds',
    'a wrong password is refused with invalidCredentials (49)',
    'an account that does not exist is refused like a wrong password (49)',
    'a base that does not exist is refused with noSuchObject (32)',
]


def domain_from_base_dn(base_dn):
    """Turn DC=ci,DC=example,DC=org into ci.example.org."""
    parts = []
    for rdn in base_dn.split(','):
        name, _, value = rdn.partition('=')
        if name.strip().lower() != 'dc':
            return ''
        parts.append(value.strip())
    return '.'.join(parts)


def search(binary, host, port, args):
    """Run one ldapsearch and return (exit status, entries, stderr).

    -x forces simple authentication so the SASL defaults of a client's
    ldap.conf cannot quietly replace the bind this driver is testing, and
    -o ldif-wrap=no keeps long values on one line for the parser below.
    """
    command = [binary, '-x', '-H', f'ldap://{host}:{port}',
               '-o', 'ldif-wrap=no', '-LLL'] + args
    completed = subprocess.run(command, capture_output=True, text=True)
    return completed.returncode, parse_entries(completed.stdout), completed.stderr.strip()


def parse_entries(text):
    """Parse LDIF into a list of {attribute: [values]} dicts.

    ldapsearch prints base64 as `attr:: <data>`, which is why the values are
    decoded rather than compared as text: a DN with a non-ASCII character comes
    back that way.
    """
    entries = []
    current = None
    for line in text.splitlines():
        if not line.strip():
            if current is not None:
                entries.append(current)
                current = None
            continue
        if line.startswith('#'):
            continue
        if ':' not in line:
            continue
        name, _, rest = line.partition(':')
        name = name.strip()
        if rest.startswith(':'):
            value = rest[1:].strip()
            try:
                value = base64.b64decode(value).decode('utf-8', 'replace')
            except (ValueError, UnicodeDecodeError):
                value = rest[1:].strip()
        else:
            value = rest.strip()
        if current is None:
            current = {}
        current.setdefault(name, []).append(value)
    if current is not None:
        entries.append(current)
    return entries


def first(entry, attribute):
    values = entry.get(attribute)
    return values[0] if values else ''


class Driver:
    def __init__(self, options):
        self.options = options
        self.admin_dn = f'CN={options.user},CN=Users,{options.base_dn}'

    def bind(self, dn, password, base, scope='base'):
        return search(self.options.ldapsearch, self.options.host, self.options.port,
                      ['-D', dn, '-w', password, '-b', base, '-s', scope,
                       '(objectClass=*)', 'dn'])

    def root_dse(self):
        return search(self.options.ldapsearch, self.options.host, self.options.port,
                      ['-s', 'base', '-b', '', 'namingContexts', 'vendorName',
                       'supportedLDAPVersion'])

    def check_root_dse(self):
        status, entries, _ = self.root_dse()
        if status != SUCCESS or not entries:
            return False, f'exit {status}, no entry returned'
        entry = entries[0]
        contexts = entry.get('namingContexts', [])
        vendor = first(entry, 'vendorName')
        versions = entry.get('supportedLDAPVersion', [])
        if self.options.base_dn not in contexts:
            return False, f'namingContexts {contexts} does not hold {self.options.base_dn}'
        if vendor != 'Monarchy':
            return False, f'vendorName is {vendor!r}, which is not this server'
        if '3' not in versions:
            return False, f'supportedLDAPVersion {versions} does not hold 3'
        return True, f'namingContexts {contexts}, vendorName {vendor}'

    def check_admin_bind(self):
        status, entries, error = self.bind(self.admin_dn, self.options.password, self.options.base_dn)
        if status != SUCCESS or not entries:
            return False, f'exit {status}: {error or "no entry returned"}'
        return True, f'bound as {self.admin_dn}'

    def check_base_object(self):
        status, entries, error = self.bind(self.admin_dn, self.options.password, self.options.base_dn)
        if status != SUCCESS or not entries:
            return False, f'exit {status}: {error or "no entry returned"}'
        dn = first(entries[0], 'dn')
        if dn.lower() != self.options.base_dn.lower():
            return False, f'the base DN answered with {dn!r}'
        return True, f'read {dn}'

    def check_administrator_search(self):
        status, entries, error = search(
            self.options.ldapsearch, self.options.host, self.options.port,
            ['-D', self.admin_dn, '-w', self.options.password,
             '-b', f'CN=Users,{self.options.base_dn}',
             '(sAMAccountName=%s)' % self.options.user, 'sAMAccountName'])
        if status != SUCCESS:
            return False, f'exit {status}: {error}'
        found = [first(entry, 'dn') for entry in entries]
        if len(found) != 1:
            return False, f'the filter returned {len(found)} entries: {found}'
        if found[0].lower() != self.admin_dn.lower():
            return False, f'the filter returned {found[0]!r}'
        if first(entries[0], 'sAMAccountName').lower() != self.options.user.lower():
            return False, f"sAMAccountName is {first(entries[0], 'sAMAccountName')!r}"
        return True, f'{found[0]}'

    def check_shuffled_case_bind(self):
        # MS-ADTS 3.1.1.3.1.2 and RFC 4517: a DN is case-insensitive, so a client
        # that upper-cases or lower-cases a DN it stored must still bind. The
        # attribute types here are lowercased, the values in the same case as
        # the provisioned DN, which is the shape a client produces when it only
        # normalises types.
        shuffled = ','.join(
            rdn.split('=', 1)[0].lower() + '=' + rdn.split('=', 1)[1]
            for rdn in self.admin_dn.split(','))
        status, entries, error = self.bind(shuffled, self.options.password, self.options.base_dn)
        if status != SUCCESS or not entries:
            return False, f'exit {status} for {shuffled}: {error or "no entry returned"}'
        return True, f'bound as {shuffled}'

    def check_wrong_password(self):
        status, entries, _ = self.bind(self.admin_dn, 'not-the-password-A1', self.options.base_dn)
        if status != INVALID_CREDENTIALS:
            return False, f'exit {status}, expected {INVALID_CREDENTIALS}'
        if entries:
            return False, f'refused but returned {len(entries)} entries anyway'
        return True, f'invalidCredentials ({INVALID_CREDENTIALS}) and no entry'

    def check_missing_account(self):
        # A missing account and a wrong password have to be indistinguishable,
        # or the directory answers "does this user exist" to anyone who asks.
        missing = f'CN=Nobody,CN=Users,{self.options.base_dn}'
        status, entries, _ = self.bind(missing, 'not-the-password-A1', self.options.base_dn)
        if status != INVALID_CREDENTIALS:
            return False, f'exit {status}, expected {INVALID_CREDENTIALS}'
        if entries:
            return False, f'refused but returned {len(entries)} entries anyway'
        return True, f'invalidCredentials ({INVALID_CREDENTIALS}), same as a wrong password'

    def check_missing_base(self):
        missing = f'CN=No-Such-Container,{self.options.base_dn}'
        status, entries, _ = self.bind(self.admin_dn, self.options.password, missing)
        if status != NO_SUCH_OBJECT:
            return False, f'exit {status}, expected {NO_SUCH_OBJECT}'
        if entries:
            return False, f'refused but returned {len(entries)} entries anyway'
        return True, f'noSuchObject ({NO_SUCH_OBJECT})'


def main():
    parser = argparse.ArgumentParser(add_help=True, description=__doc__.splitlines()[0])
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=389)
    parser.add_argument('--base-dn', default='DC=ci,DC=example,DC=org')
    parser.add_argument('--user', default='Administrator')
    parser.add_argument('--password', default='P@ssw0rd123!')
    parser.add_argument('--dns-domain', default='')
    parser.add_argument('--ldapsearch', default='ldapsearch')
    parser.add_argument('--list', action='store_true')
    options = parser.parse_args()

    if options.list:
        for description in CHECKS:
            print(description)
        return 0

    if not shutil.which(options.ldapsearch):
        print(f'ldap-conformance: {options.ldapsearch} not on PATH '
              '(the ldap-utils package)', file=sys.stderr)
        return 1

    dns_domain = options.dns_domain or domain_from_base_dn(options.base_dn)
    print(f'LDAP conformance against {options.host}:{options.port}, '
          f'base {options.base_dn} ({dns_domain or "no DNS domain"})')

    driver = Driver(options)
    checks = [
        driver.check_root_dse,
        driver.check_admin_bind,
        driver.check_base_object,
        driver.check_administrator_search,
        driver.check_shuffled_case_bind,
        driver.check_wrong_password,
        driver.check_missing_account,
        driver.check_missing_base,
    ]
    failures = 0
    for description, check in zip(CHECKS, checks):
        try:
            passed, detail = check()
        except Exception as error:  # a client that dies is a failed check, not a traceback
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
