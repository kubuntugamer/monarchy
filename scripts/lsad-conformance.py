#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the DC's lsarpc endpoint with the clients Windows tools are built on.

The point of this script is not to test our encoder against itself: every call
below is marshalled and unmarshalled by somebody else's NDR implementation, so a
reply that only this server understands fails here.

Two clients are used, because neither is complete on its own:

  * Samba's ``samba.dcerpc.lsa`` module is pidl's own NDR, the reference
    implementation this server's layout is written against. It covers the
    policy information classes, name/SID translation, account rights, the
    privilege lookup calls and the domain information policy.

  * impacket's ``lsad``/``lsat`` modules implement MS-LSAD straight from the
    specification and cover what Samba's bindings do not expose from Python:
    LsarGetUserName, account enumeration and handles, LsarStorePrivateData and
    the LSA secret calls.

Usage:
  scripts/lsad-conformance.py [options]

Options:
  --host HOST        DC address. Default: 127.0.0.1
  --port PORT        lsarpc port. Default: 1036
  --user USER        Account to bind as. Default: Administrator
  --password PASS    Its password. Default: P@ssw0rd123!
  --domain DOMAIN    NetBIOS domain name. Default: MONARCHY
  --samba-python P   Interpreter with Samba's Python bindings. Default:
                     /usr/bin/python3 (the system one, not a venv)
  --impacket-python P
                     Interpreter with impacket installed. Default: the
                     interpreter running this script
  --list             Only list the checks that would run.

Exit status is 0 when every check passes, 1 otherwise.
"""

import argparse
import os
import subprocess
import sys

SAMBA_CHECKS = r'''
import sys
from samba.dcerpc import lsa
from samba.dcerpc.security import dom_sid
from samba.credentials import Credentials
from samba import param

HOST, PORT, USER, PASSWORD, DOMAIN, DOMAIN_SID = sys.argv[1:7]
PORT = int(PORT)
failures = []


def check(label, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + label + ((' :: ' + str(detail)) if detail else ''))
    sys.stdout.flush()
    if not ok:
        failures.append(label)


lp = param.LoadParm()
lp.set('netbios name', 'MONARCHYPROBE')
creds = Credentials()
creds.set_username(USER)
creds.set_password(PASSWORD)
creds.set_domain(DOMAIN)
creds.set_workstation('MONARCHYPROBE')

binding = 'ncacn_ip_tcp:%s[%d]' % (HOST, PORT)
i = lsa.lsarpc(binding, lp, creds)
check('bind lsarpc at PKT_PRIVACY (NTLMSSP)', True)
h = i.OpenPolicy2(None, lsa.ObjectAttribute(), lsa.LSA_POLICY_ALL_ACCESS)
check('LsarOpenPolicy2', True)

# Every policy information class this endpoint answers has to survive Samba's
# decoder: the union arm alignment differs per class and a single stray padding
# byte shifts every field after it.
for level in (1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14):
    try:
        info = i.QueryInfoPolicy2(h, level)
        check('QueryInformationPolicy2 level %d' % level, True, type(info).__name__)
    except Exception as e:
        check('QueryInformationPolicy2 level %d' % level, False,
              '%s: %s' % (type(e).__name__, str(e)[:120]))

info = i.QueryInfoPolicy2(h, 3)
check('primary domain name and SID',
      info.name.string == DOMAIN and str(info.sid) == DOMAIN_SID,
      (info.name.string, str(info.sid)))
info = i.QueryInfoPolicy2(h, 12)
check('DNS domain identity',
      info.dns_domain.string.endswith('.') is False
      and str(info.sid) == DOMAIN_SID,
      (info.name.string, info.dns_domain.string, info.dns_forest.string))
info = i.QueryInfoPolicy2(h, 6)
check('server role is LSA_ROLE_PRIMARY', info.role == 3, info.role)
info = i.QueryInfoPolicy2(h, 8)
check('default quota class decodes', True, info.unknown)

names = [lsa.String(USER), lsa.String('Domain Admins'), lsa.String(DOMAIN),
         lsa.String('no-such-account'), lsa.String(DOMAIN + '\\Guest')]
domains, sids, count = i.LookupNames(h, names, lsa.TransSidArray(), 1, 0)
rows = [(s.sid_type, s.rid, s.sid_index) for s in sids.sids]
check('LsarLookupNames', count == len(names) and rows[3][0] == 8 and rows[4][1] == 501,
      '%s %s' % ([(d.name.string, str(d.sid)) for d in domains.domains], rows))

array = lsa.SidArray()
entries = []
for text in (DOMAIN_SID + '-500', DOMAIN_SID + '-512', 'S-1-5-32-544',
             'S-1-5-21-9-9-9-1234'):
    pointer = lsa.SidPtr()
    pointer.sid = dom_sid(text)
    entries.append(pointer)
array.sids = entries
array.num_sids = len(entries)
domains, names_out, count = i.LookupSids(h, array, lsa.TransNameArray(), 1, 0)
rows = [(n.sid_type, n.name.string, n.sid_index) for n in names_out.names]
check('LsarLookupSids',
      count == len(entries) and rows[0][1] == USER and rows[2][1] == 'Administrators'
      and rows[3][0] == 8,
      '%s %s' % ([(d.name.string, str(d.sid)) for d in domains.domains], rows))


def right_set(*rights):
    result = lsa.RightSet()
    result.count = len(rights)
    items = []
    for right in rights:
        item = lsa.StringLarge()
        item.string = right
        items.append(item)
    result.names = items
    return result


admin_sid = dom_sid(DOMAIN_SID + '-500')
i.AddAccountRights(h, admin_sid, right_set('SeDebugPrivilege', 'SeBackupPrivilege'))
rights = i.EnumAccountRights(h, admin_sid)
granted = [r.string for r in rights.names]
check('LsarAddAccountRights / LsarEnumAccountRights',
      'SeDebugPrivilege' in granted and 'SeBackupPrivilege' in granted, granted)
holders = i.EnumAccountsWithUserRight(h, lsa.String('SeDebugPrivilege'))
check('LsarEnumAccountsWithUserRight',
      any(str(s.sid) == DOMAIN_SID + '-500' for s in holders.sids),
      [str(s.sid) for s in holders.sids])
i.RemoveAccountRights(h, admin_sid, 0, right_set('SeBackupPrivilege'))
rights = i.EnumAccountRights(h, admin_sid)
granted = [r.string for r in rights.names]
check('LsarRemoveAccountRights',
      'SeBackupPrivilege' not in granted and 'SeDebugPrivilege' in granted, granted)

value = i.LookupPrivValue(h, lsa.String('SeBackupPrivilege'))
check('LsarLookupPrivilegeValue', value.low == 0x11, (value.low, value.high))
luid = lsa.LUID()
luid.low = 0x11
luid.high = 0
name = i.LookupPrivName(h, luid)
check('LsarLookupPrivilegeName', name.string == 'SeBackupPrivilege', name.string)
display, language = i.LookupPrivDisplayName(h, lsa.String('SeBackupPrivilege'), 0, 0)
check('LsarLookupPrivilegeDisplayName',
      display.string == 'Back up files and directories' and language == 0x0409,
      (display.string, language))

context, seen = 0, []
for _ in range(8):
    try:
        context, page = i.EnumPrivs(h, context, 0x1000)
        seen += [p.name.string for p in page.privs]
    except Exception:
        break
check('LsarEnumeratePrivileges lists the catalog',
      len(seen) == 34 and 'SeBackupPrivilege' in seen, len(seen))

kerberos = i.QueryDomainInformationPolicy(h, 3)
check('LsarQueryDomainInformationPolicy(Kerberos)',
      kerberos.service_tkt_lifetime == 36000000000
      and kerberos.user_tkt_renewaltime == 604800000000
      and kerberos.clock_skew == 300000000,
      (kerberos.service_tkt_lifetime, kerberos.user_tkt_lifetime,
       kerberos.user_tkt_renewaltime, kerberos.clock_skew))
i.QueryDomainInformationPolicy(h, 1)
i.QueryDomainInformationPolicy(h, 2)
check('LsarQueryDomainInformationPolicy(QoS and EFS) decode', True)

descriptor = i.QuerySecurity(h, 0x00000001 | 0x00000004).sd
check('LsarQuerySecurityObject',
      descriptor is not None and str(descriptor.owner_sid) == 'S-1-5-32-544',
      str(descriptor.owner_sid) if descriptor is not None else None)

i.Close(h)
check('LsarClose', True)

print('\n%d failure(s): %s' % (len(failures), failures))
sys.exit(0 if not failures else 1)
'''

IMPACKET_CHECKS = r'''
import sys
from impacket.dcerpc.v5 import transport, rpcrt, lsad, lsat

HOST, PORT, USER, PASSWORD, DOMAIN, DOMAIN_SID = sys.argv[1:7]
PORT = int(PORT)
failures = []


def check(label, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + label + ((' :: ' + str(detail)) if detail else ''))
    sys.stdout.flush()
    if not ok:
        failures.append(label)


transport_ = transport.DCERPCTransportFactory('ncacn_ip_tcp:%s[%d]' % (HOST, PORT))
transport_.set_credentials(USER, PASSWORD, DOMAIN)
dce = transport_.get_dce_rpc()
dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
dce.connect()
dce.bind(lsad.MSRPC_UUID_LSAD)
check('bind lsarpc at PKT_PRIVACY (impacket NDR)', True)
policy = lsad.hLsarOpenPolicy2(dce)['PolicyHandle']
check('LsarOpenPolicy2', True)

for level in (3, 10, 11, 12):
    request = lsad.LsarQueryInformationPolicy2()
    request['PolicyHandle'] = policy
    request['InformationClass'] = level
    response = dce.request(request)
    check('QueryInformationPolicy2 level %d' % level, response['ErrorCode'] == 0,
          hex(response['ErrorCode']))

response = lsat.hLsarGetUserName(dce)
check('LsarGetUserName', response['ErrorCode'] == 0 and response['UserName'] == USER,
      response['UserName'])

request = lsad.LsarEnumerateAccounts()
request['PolicyHandle'] = policy
request['PreferedMaximumLength'] = 0x1000
request['EnumerationContext'] = 0
response = dce.request(request)
sids = [s['Sid'].formatCanonical() for s in response['EnumerationBuffer']['Information']]
check('LsarEnumerateAccounts', response['ErrorCode'] == 0 and DOMAIN_SID + '-500' in sids,
      sids)

request = lsad.LsarOpenAccount()
request['PolicyHandle'] = policy
request['AccountSid'].fromCanonical(DOMAIN_SID + '-500')
request['DesiredAccess'] = 0x000f0fff
account = dce.request(request)['AccountHandle']
check('LsarOpenAccount', True)

response = lsad.hLsarEnumeratePrivilegesAccount(dce, account)
check('LsarEnumeratePrivilegesAccount', response['ErrorCode'] == 0,
      [p['Luid']['LowPart'] for p in response['Privileges']['Privilege']])
response = lsad.hLsarGetSystemAccessAccount(dce, account)
check('LsarGetSystemAccessAccount', response['ErrorCode'] == 0,
      hex(response['SystemAccess']))

privilege = lsad.LSAPR_LUID_AND_ATTRIBUTES()
privilege['Luid']['LowPart'] = 0x12  # SeRestorePrivilege
privilege['Attributes'] = 0
request = lsad.LsarAddPrivilegesToAccount()
request['AccountHandle'] = account
request['Privileges']['PrivilegeCount'] = 1
request['Privileges']['Privilege'].append(privilege)
response = dce.request(request)
granted = [p['Luid']['LowPart']
           for p in lsad.hLsarEnumeratePrivilegesAccount(dce, account)['Privileges']['Privilege']]
check('LsarAddPrivilegesToAccount', response['ErrorCode'] == 0 and 0x12 in granted, granted)

request = lsad.LsarRemovePrivilegesFromAccount()
request['AccountHandle'] = account
request['AllPrivileges'] = 0
request['Privileges']['PrivilegeCount'] = 1
request['Privileges']['Privilege'].append(privilege)
dce.request(request)
granted = [p['Luid']['LowPart']
           for p in lsad.hLsarEnumeratePrivilegesAccount(dce, account)['Privileges']['Privilege']]
check('LsarRemovePrivilegesFromAccount', 0x12 not in granted, granted)

secret_data = b'\x01\x02\x03\x04\x05\x06\x07\x08'
lsad.hLsarStorePrivateData(dce, policy, 'MonarchyConformance', secret_data)
stored = lsad.hLsarRetrievePrivateData(dce, policy, 'MonarchyConformance')
check('LsarStorePrivateData / LsarRetrievePrivateData', bytes(stored)[:8] == secret_data,
      bytes(stored)[:16])

request = lsad.LsarCreateSecret()
request['PolicyHandle'] = policy
request['SecretName'] = 'MonarchyConformanceSecret'
request['DesiredAccess'] = 0x000f0fff
secret = dce.request(request)['SecretHandle']
check('LsarCreateSecret', True)
request = lsad.LsarSetSecret()
request['SecretHandle'] = secret
request['EncryptedCurrentValue']['Buffer'] = b'\xaa' * 8
request['EncryptedCurrentValue']['Length'] = 8
request['EncryptedOldValue']['Buffer'] = b'\xbb' * 8
request['EncryptedOldValue']['Length'] = 8
response = dce.request(request)
check('LsarSetSecret', response['ErrorCode'] == 0, hex(response['ErrorCode']))
response = lsad.hLsarQuerySecret(dce, secret)
current = response['EncryptedCurrentValue']['Buffer']
previous = response['EncryptedOldValue']['Buffer']
current = b''.join(current) if isinstance(current, list) else bytes(current)
previous = b''.join(previous) if isinstance(previous, list) else bytes(previous)
check('LsarQuerySecret', current[:8] == b'\xaa' * 8 and previous[:8] == b'\xbb' * 8,
      (current[:8], previous[:8]))

lsad.hLsarClose(dce, policy)
check('LsarClose', True)

print('\n%d failure(s): %s' % (len(failures), failures))
sys.exit(0 if not failures else 1)
'''


def run(interpreter, source, args):
    command = [interpreter, '-u', '-c', source] + args
    completed = subprocess.run(command, text=True)
    return completed.returncode


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default='1036')
    parser.add_argument('--user', default='Administrator')
    parser.add_argument('--password', default='P@ssw0rd123!')
    parser.add_argument('--domain', default='MONARCHY')
    parser.add_argument('--domain-sid', default=None)
    parser.add_argument('--samba-python', default='/usr/bin/python3')
    parser.add_argument('--impacket-python', default=sys.executable)
    parser.add_argument('--list', action='store_true')
    options = parser.parse_args()

    domain_sid = options.domain_sid or os.environ.get('MONARCHY_DOMAIN_SID')
    if not domain_sid:
        print('--domain-sid (or MONARCHY_DOMAIN_SID) is required: it is the SID the '
              'translation calls are checked against.', file=sys.stderr)
        return 2

    if options.list:
        for line in SAMBA_CHECKS.splitlines() + IMPACKET_CHECKS.splitlines():
            if "check('" in line:
                print(line.strip().split("check('", 1)[1].split("'", 1)[0])
        return 0

    arguments = [options.host, options.port, options.user, options.password,
                 options.domain, domain_sid]
    failures = 0
    print('--- Samba dcerpc (reference NDR)')
    failures += run(options.samba_python, SAMBA_CHECKS, arguments)
    print('\n--- impacket (MS-LSAD from the specification)')
    failures += run(options.impacket_python, IMPACKET_CHECKS, arguments)
    return 0 if failures == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
