#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive the DC's SAMR endpoint with impacket's own NDR.

Every request here is marshalled by impacket from MS-SAMR and every reply is
unmarshalled by it, so a buffer layout that only this server understands fails
here. The checks form one lifecycle rather than a list of unrelated calls: the
domain is enumerated and opened, a user and a group are created, the user is put
in the group and read back through both the group and the enumeration, then both
objects are deleted. Name/RID translation is checked before and after, because
the RID the server returns for the created object is what the lookups have to
agree with.

Usage:
  scripts/samr-conformance.py [options]

Options:
  --host HOST        DC address. Default: 127.0.0.1
  --port PORT        SAMR port. Default: 1035
  --user USER        Account to bind as. Default: Administrator
  --password PASS    Its password. Default: P@ssw0rd123!
  --domain DOMAIN    NetBIOS domain name. Default: MONARCHY
  --list             Only list the checks that would run.

Exit status is 0 when every check passes, 1 otherwise.
"""

import argparse
import sys
import uuid

from impacket.dcerpc.v5 import rpcrt, samr, transport

MAXIMUM_ALLOWED = 0x02000000

CHECKS = [
    'bind samr at PKT_PRIVACY (impacket NDR)',
    'SamrConnect5',
    'SamrConnect2',
    'SamrEnumerateDomainsInSamServer',
    'SamrLookupDomainInSamServer',
    'SamrOpenDomain',
    'SamrCreateUser2InDomain',
    'SamrOpenUser / SamrQueryInformationUser2',
    'SamrLookupNamesInDomain',
    'SamrLookupIdsInDomain',
    'SamrCreateGroupInDomain',
    'SamrAddMemberToGroup / SamrGetMembersInGroup',
    'SamrEnumerateUsersInDomain',
    'SamrDeleteUser',
    'SamrDeleteGroup',
    'SamrCloseHandle',
]

failures = []


def check(label, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + label + ((' :: ' + str(detail)) if detail else ''))
    sys.stdout.flush()
    if not ok:
        failures.append(label)


def list_field(container):
    """The first array inside an impacket structure, whatever impacket named
    the wrapper this version: MS-SAMR's arrays are nested differently in
    different bindings."""
    if isinstance(container, (list, tuple)):
        return container
    fields = getattr(container, 'fields', None)
    if fields:
        for key, value in fields.items():
            if key == 'tag':
                continue
            found = list_field(value)
            if found is not None:
                return found
    return None


def connect(options):
    transport_ = transport.DCERPCTransportFactory(
        'ncacn_ip_tcp:%s[%d]' % (options.host, int(options.port)))
    transport_.set_credentials(options.user, options.password, options.domain)
    dce = transport_.get_dce_rpc()
    dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)
    return dce


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default='1035')
    parser.add_argument('--user', default='Administrator')
    parser.add_argument('--password', default='P@ssw0rd123!')
    parser.add_argument('--domain', default='MONARCHY')
    parser.add_argument('--list', action='store_true')
    options = parser.parse_args()

    if options.list:
        print('\n'.join(CHECKS))
        return 0

    try:
        dce = connect(options)
    except Exception as error:  # noqa: BLE001 - a refused bind is the result
        check(CHECKS[0], False, '%s: %s' % (type(error).__name__, error))
        print('\n%d failure(s): %s' % (len(failures), failures))
        return 1
    check(CHECKS[0], True)

    server_name = '\\\\%s\x00' % options.host
    try:
        server = samr.hSamrConnect5(dce, server_name, MAXIMUM_ALLOWED, 1, 3)['ServerHandle']
        check(CHECKS[1], True)
    except Exception as error:  # noqa: BLE001
        check(CHECKS[1], False, '%s: %s' % (type(error).__name__, error))
        print('\n%d failure(s): %s' % (len(failures), failures))
        return 1

    try:
        samr.hSamrConnect2(dce, server_name, MAXIMUM_ALLOWED)
        check(CHECKS[2], True)
    except Exception as error:  # noqa: BLE001
        check(CHECKS[2], False, '%s: %s' % (type(error).__name__, error))

    response = samr.hSamrEnumerateDomainsInSamServer(dce, server, 0, 0x1000)
    names = [entry['Name'] for entry in response['Buffer']['Buffer']]
    check(CHECKS[3], options.domain in names, names)

    domain_id = samr.hSamrLookupDomainInSamServer(dce, server, options.domain)['DomainId']
    # The SID's own __str__ returns bytes, which a label cannot carry.
    check(CHECKS[4], True,
          domain_id.formatCanonical() if hasattr(domain_id, 'formatCanonical') else 'domain')
    domain = samr.hSamrOpenDomain(dce, server, MAXIMUM_ALLOWED, domain_id)['DomainHandle']
    check(CHECKS[5], True)

    # A unique name keeps a repeated run from colliding with the previous one.
    name = 'conf-user-%s' % uuid.uuid4().hex[:8]
    try:
        created = samr.hSamrCreateUser2InDomain(
            dce, domain, name, samr.USER_NORMAL_ACCOUNT, MAXIMUM_ALLOWED)
        user = created['UserHandle']
        rid = created['RelativeId']
        check(CHECKS[6], rid > 0, rid)
    except Exception as error:  # noqa: BLE001
        check(CHECKS[6], False, '%s: %s' % (type(error).__name__, error))
        print('\n%d failure(s): %s' % (len(failures), failures))
        return 1

    # Class 21 is SamprUserAllInformation (MS-SAMR 2.2.7.6); impacket names the
    # union arm All, not after the structure.
    info = samr.hSamrQueryInformationUser2(dce, user, 21)['Buffer']['All']
    check(CHECKS[7],
          info['UserName'] == name and info['UserId'] == rid
          and info['PrimaryGroupId'] > 0,
          (info['UserName'], info['UserId'], info['PrimaryGroupId']))

    try:
        relative = list_field(samr.hSamrLookupNamesInDomain(dce, domain, (name,))['RelativeIds']) or []
        check(CHECKS[8], len(relative) == 1 and relative[0]['Data'] == rid, relative)
    except Exception as error:  # noqa: BLE001
        check(CHECKS[8], False, '%s: %s' % (type(error).__name__, error))
    try:
        back = list_field(samr.hSamrLookupIdsInDomain(dce, domain, (rid,))['Names']) or []
        check(CHECKS[9], len(back) == 1 and back[0]['Data'] == name, back)
    except Exception as error:  # noqa: BLE001
        check(CHECKS[9], False, '%s: %s' % (type(error).__name__, error))

    group = None
    try:
        group_created = samr.hSamrCreateGroupInDomain(
            dce, domain, 'conf-group', MAXIMUM_ALLOWED)
        group = group_created['GroupHandle']
        check(CHECKS[10], group_created['RelativeId'] > 0, group_created['RelativeId'])
        samr.hSamrAddMemberToGroup(dce, group, rid, 7)
        # The member entry's field name differs between impacket releases; the
        # RID is the integer field of each entry either way.
        members = []
        for entry in list_field(samr.hSamrGetMembersInGroup(dce, group)['Members']) or []:
            for key, value in getattr(entry, 'fields', {}).items():
                if key != 'tag' and isinstance(value, int):
                    members.append(value)
                    break
        check(CHECKS[11], rid in members, members)
    except Exception as error:  # noqa: BLE001
        check(CHECKS[10] if group is None else CHECKS[11], False,
              '%s: %s' % (type(error).__name__, error))

    # Enumeration is checked with the domain's own account filter: a user this
    # script just created has to appear in it.
    # One page large enough for the throwaway domain: impacket raises on
    # STATUS_MORE_ENTRIES, and this check is about the buffer shape, not paging.
    try:
        page = samr.hSamrEnumerateUsersInDomain(
            dce, domain, samr.USER_NORMAL_ACCOUNT, 0, 0x10000)
        listed = [entry['Name'] for entry in page['Buffer']['Buffer']]
        check(CHECKS[12], name in listed, (len(listed), name))
    except Exception as error:  # noqa: BLE001
        check(CHECKS[12], False, '%s: %s' % (type(error).__name__, error))

    try:
        samr.hSamrDeleteUser(dce, user)
        check(CHECKS[13], True)
    except Exception as error:  # noqa: BLE001
        check(CHECKS[13], False, '%s: %s' % (type(error).__name__, error))
    if group is not None:
        try:
            samr.hSamrDeleteGroup(dce, group)
            check(CHECKS[14], True)
        except Exception as error:  # noqa: BLE001
            check(CHECKS[14], False, '%s: %s' % (type(error).__name__, error))
    try:
        samr.hSamrCloseHandle(dce, domain)
        samr.hSamrCloseHandle(dce, server)
        check(CHECKS[15], True)
    except Exception as error:  # noqa: BLE001
        check(CHECKS[15], False, '%s: %s' % (type(error).__name__, error))

    print('\n%d failure(s): %s' % (len(failures), failures))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
