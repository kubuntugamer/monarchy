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

from impacket.dcerpc.v5 import dtypes, rpcrt, samr, transport

MAXIMUM_ALLOWED = 0x02000000

CHECKS = [
    'bind samr at PKT_PRIVACY (impacket NDR)',
    'SamrConnect5',
    'SamrConnect2',
    'SamrEnumerateDomainsInSamServer',
    'SamrLookupDomainInSamServer',
    'SamrOpenDomain',
    'SamrEnumerateDomainsInSamServer lists BUILTIN',
    'SamrOpenDomain / SamrEnumerateAliasesInDomain (BUILTIN)',
    'SamrLookupNamesInDomain (BUILTIN)',
    'BUILTIN aliases are read-only',
    'SamrCreateUser2InDomain',
    'SamrOpenUser / SamrQueryInformationUser2',
    'SamrLookupNamesInDomain',
    'SamrLookupIdsInDomain',
    'SamrCreateGroupInDomain',
    'SamrAddMemberToGroup / SamrGetMembersInGroup',
    'SamrEnumerateUsersInDomain',
    'SamrCreateAliasInDomain',
    'SamrEnumerateAliasesInDomain',
    'SamrEnumerateGroupsInDomain omits the alias',
    'SamrAddMemberToAlias / SamrGetMembersInAlias',
    'SamrQueryInformationAlias',
    'SamrSetInformationAlias / SamrRemoveMemberFromAlias',
    'SamrDeleteAlias',
    'SamrDeleteUser',
    'SamrDeleteGroup',
    'SamrCloseHandle',
]

# The names the checks are reported under, so a reordered list cannot
# silently report one call under another call's name.
(
    BIND,
    CONNECT5,
    CONNECT2,
    DOMAINS,
    LOOKUP_DOMAIN,
    OPEN_DOMAIN,
    DOMAINS_BUILTIN,
    BUILTIN_ALIASES,
    BUILTIN_NAMES,
    BUILTIN_READONLY,
    CREATE_USER,
    OPEN_USER,
    LOOKUP_NAMES,
    LOOKUP_IDS,
    CREATE_GROUP,
    GROUP_MEMBERS,
    ENUM_USERS,
    CREATE_ALIAS,
    ENUM_ALIASES,
    GROUPS_OMIT_ALIAS,
    ALIAS_MEMBERS,
    QUERY_ALIAS,
    SET_ALIAS,
    DELETE_ALIAS,
    DELETE_USER,
    DELETE_GROUP,
    CLOSE,
) = CHECKS

failures = []


def check(label, ok, detail=''):
    if label not in CHECKS:
        raise SystemExit('unknown check label: %r' % label)
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
        check(BIND, False, '%s: %s' % (type(error).__name__, error))
        print('\n%d failure(s): %s' % (len(failures), failures))
        return 1
    check(BIND, True)

    server_name = '\\\\%s\x00' % options.host
    try:
        server = samr.hSamrConnect5(dce, server_name, MAXIMUM_ALLOWED, 1, 3)['ServerHandle']
        check(CONNECT5, True)
    except Exception as error:  # noqa: BLE001
        check(CONNECT5, False, '%s: %s' % (type(error).__name__, error))
        print('\n%d failure(s): %s' % (len(failures), failures))
        return 1

    try:
        samr.hSamrConnect2(dce, server_name, MAXIMUM_ALLOWED)
        check(CONNECT2, True)
    except Exception as error:  # noqa: BLE001
        check(CONNECT2, False, '%s: %s' % (type(error).__name__, error))

    response = samr.hSamrEnumerateDomainsInSamServer(dce, server, 0, 0x1000)
    names = [entry['Name'] for entry in response['Buffer']['Buffer']]
    check(DOMAINS, options.domain in names, names)

    domain_id = samr.hSamrLookupDomainInSamServer(dce, server, options.domain)['DomainId']
    # The SID's own __str__ returns bytes, which a label cannot carry.
    check(LOOKUP_DOMAIN, True,
          domain_id.formatCanonical() if hasattr(domain_id, 'formatCanonical') else 'domain')
    domain = samr.hSamrOpenDomain(dce, server, MAXIMUM_ALLOWED, domain_id)['DomainHandle']
    check(OPEN_DOMAIN, True)

    # Every DC reports BUILTIN next to the account domain: it is where AD keeps
    # the well-known local groups, and their SIDs are in ACLs everywhere.
    try:
        check(DOMAINS_BUILTIN, names[:2] == ['Builtin', options.domain], names)
    except Exception as error:  # noqa: BLE001
        check(DOMAINS_BUILTIN, False, '%s: %s' % (type(error).__name__, error))

    builtin = None
    try:
        builtin_id = samr.hSamrLookupDomainInSamServer(dce, server, 'Builtin')['DomainId']
        builtin = samr.hSamrOpenDomain(dce, server, MAXIMUM_ALLOWED, builtin_id)['DomainHandle']
        page = samr.hSamrEnumerateAliasesInDomain(dce, builtin, 0, 0x10000)
        listed = [(entry['Name'], entry['RelativeId']) for entry in page['Buffer']['Buffer']]
        check(BUILTIN_ALIASES,
              len(listed) == 16 and ('Administrators', 544) in listed, len(listed))
    except Exception as error:  # noqa: BLE001
        check(BUILTIN_ALIASES, False, '%s: %s' % (type(error).__name__, error))

    builtin_alias = None
    if builtin is not None:
        try:
            relative = list_field(samr.hSamrLookupNamesInDomain(
                dce, builtin, ('Administrators',))['RelativeIds']) or []
            check(BUILTIN_NAMES, len(relative) == 1 and relative[0]['Data'] == 544, relative)
        except Exception as error:  # noqa: BLE001
            check(BUILTIN_NAMES, False, '%s: %s' % (type(error).__name__, error))

        # The membership AD seeds at domain creation, and nothing writable: a
        # BUILTIN write has nowhere to persist here, so it is refused.
        try:
            builtin_alias = samr.hSamrOpenAlias(dce, builtin, MAXIMUM_ALLOWED, 544)['AliasHandle']
            general = samr.hSamrQueryInformationAlias(dce, builtin_alias, 1)['Buffer']['General']
            members = [entry['Data']['SidPointer'].formatCanonical()
                       for entry in samr.hSamrGetMembersInAlias(
                           dce, builtin_alias)['Members']['Sids']]
            domain_admins = '%s-512' % domain_id.formatCanonical()
            seeded = general['MemberCount'] == 1 and members == [domain_admins]
            admin_sid = dtypes.RPC_SID()
            admin_sid.fromCanonical('%s-500' % domain_id.formatCanonical())
            refusals = 0
            for call in (samr.hSamrAddMemberToAlias, samr.hSamrRemoveMemberFromAlias):
                try:
                    call(dce, builtin_alias, admin_sid)
                except Exception as error:  # noqa: BLE001
                    refusals += '0xc00000bb' in str(error).lower()
            try:
                samr.hSamrDeleteAlias(dce, builtin_alias)
            except Exception as error:  # noqa: BLE001
                refusals += '0xc00000bb' in str(error).lower()
            check(BUILTIN_READONLY, seeded and refusals == 3,
                  (general['MemberCount'], members, refusals))
        except Exception as error:  # noqa: BLE001
            check(BUILTIN_READONLY, False, '%s: %s' % (type(error).__name__, error))

    # A unique name keeps a repeated run from colliding with the previous one.
    name = 'conf-user-%s' % uuid.uuid4().hex[:8]
    try:
        created = samr.hSamrCreateUser2InDomain(
            dce, domain, name, samr.USER_NORMAL_ACCOUNT, MAXIMUM_ALLOWED)
        user = created['UserHandle']
        rid = created['RelativeId']
        check(CREATE_USER, rid > 0, rid)
    except Exception as error:  # noqa: BLE001
        check(CREATE_USER, False, '%s: %s' % (type(error).__name__, error))
        print('\n%d failure(s): %s' % (len(failures), failures))
        return 1

    # Class 21 is SamprUserAllInformation (MS-SAMR 2.2.7.6); impacket names the
    # union arm All, not after the structure.
    info = samr.hSamrQueryInformationUser2(dce, user, 21)['Buffer']['All']
    check(OPEN_USER,
          info['UserName'] == name and info['UserId'] == rid
          and info['PrimaryGroupId'] > 0,
          (info['UserName'], info['UserId'], info['PrimaryGroupId']))

    try:
        relative = list_field(samr.hSamrLookupNamesInDomain(dce, domain, (name,))['RelativeIds']) or []
        check(LOOKUP_NAMES, len(relative) == 1 and relative[0]['Data'] == rid, relative)
    except Exception as error:  # noqa: BLE001
        check(LOOKUP_NAMES, False, '%s: %s' % (type(error).__name__, error))
    try:
        back = list_field(samr.hSamrLookupIdsInDomain(dce, domain, (rid,))['Names']) or []
        check(LOOKUP_IDS, len(back) == 1 and back[0]['Data'] == name, back)
    except Exception as error:  # noqa: BLE001
        check(LOOKUP_IDS, False, '%s: %s' % (type(error).__name__, error))

    group = None
    group_name = 'conf-group-%s' % uuid.uuid4().hex[:6]
    try:
        group_created = samr.hSamrCreateGroupInDomain(
            dce, domain, group_name, MAXIMUM_ALLOWED)
        group = group_created['GroupHandle']
        check(CREATE_GROUP, group_created['RelativeId'] > 0, group_created['RelativeId'])
        samr.hSamrAddMemberToGroup(dce, group, rid, 7)
        # The member entry's field name differs between impacket releases; the
        # RID is the integer field of each entry either way.
        members = []
        for entry in list_field(samr.hSamrGetMembersInGroup(dce, group)['Members']) or []:
            for key, value in getattr(entry, 'fields', {}).items():
                if key != 'tag' and isinstance(value, int):
                    members.append(value)
                    break
        check(GROUP_MEMBERS, rid in members, members)
    except Exception as error:  # noqa: BLE001
        check(CREATE_GROUP if group is None else GROUP_MEMBERS, False,
              '%s: %s' % (type(error).__name__, error))

    # Enumeration is checked with the domain's own account filter: a user this
    # script just created has to appear in it.
    # One page large enough for the throwaway domain: impacket raises on
    # STATUS_MORE_ENTRIES, and this check is about the buffer shape, not paging.
    try:
        page = samr.hSamrEnumerateUsersInDomain(
            dce, domain, samr.USER_NORMAL_ACCOUNT, 0, 0x10000)
        listed = [entry['Name'] for entry in page['Buffer']['Buffer']]
        check(ENUM_USERS, name in listed, (len(listed), name))
    except Exception as error:  # noqa: BLE001
        check(ENUM_USERS, False, '%s: %s' % (type(error).__name__, error))

    # An alias is the domain-local group SAMR keeps apart from the groups: it is
    # created, enumerated and read through its own calls, and its members are
    # named by SID rather than by RID.
    alias = None
    alias_name = 'conf-alias-%s' % uuid.uuid4().hex[:6]
    alias_rid = 0
    try:
        alias_created = samr.hSamrCreateAliasInDomain(
            dce, domain, alias_name, MAXIMUM_ALLOWED)
        alias = alias_created['AliasHandle']
        alias_rid = alias_created['RelativeId']
        check(CREATE_ALIAS, alias_rid > 0, (alias_name, alias_rid))
    except Exception as error:  # noqa: BLE001
        check(CREATE_ALIAS, False, '%s: %s' % (type(error).__name__, error))

    if alias is not None:
        try:
            page = samr.hSamrEnumerateAliasesInDomain(dce, domain, 0, 0x10000)
            listed = [(entry['Name'], entry['RelativeId']) for entry in page['Buffer']['Buffer']]
            check(ENUM_ALIASES, (alias_name, alias_rid) in listed, listed)
        except Exception as error:  # noqa: BLE001
            check(ENUM_ALIASES, False, '%s: %s' % (type(error).__name__, error))
        try:
            page = samr.hSamrEnumerateGroupsInDomain(dce, domain, 0, 0x10000)
            names = [entry['Name'] for entry in page['Buffer']['Buffer']]
            check(GROUPS_OMIT_ALIAS, alias_name not in names, names)
        except Exception as error:  # noqa: BLE001
            check(GROUPS_OMIT_ALIAS, False, '%s: %s' % (type(error).__name__, error))

        member_sid = dtypes.RPC_SID()
        member_sid.fromCanonical('%s-%d' % (domain_id.formatCanonical(), rid))
        try:
            samr.hSamrAddMemberToAlias(dce, alias, member_sid)
            members = [entry['Data']['SidPointer'].formatCanonical()
                       for entry in samr.hSamrGetMembersInAlias(dce, alias)['Members']['Sids']]
            check(ALIAS_MEMBERS, members == [member_sid.formatCanonical()], members)
        except Exception as error:  # noqa: BLE001
            check(ALIAS_MEMBERS, False, '%s: %s' % (type(error).__name__, error))
        try:
            general = samr.hSamrQueryInformationAlias(dce, alias, 1)['Buffer']['General']
            check(QUERY_ALIAS,
                  general['Name'] == alias_name and general['MemberCount'] == 1,
                  (general['Name'], general['MemberCount']))
        except Exception as error:  # noqa: BLE001
            check(QUERY_ALIAS, False, '%s: %s' % (type(error).__name__, error))
        try:
            comment = 'engineers-%s' % uuid.uuid4().hex[:6]
            buffer = samr.SAMPR_ALIAS_INFO_BUFFER()
            buffer['tag'] = 3
            buffer['AdminComment']['AdminComment'] = comment
            samr.hSamrSetInformationAlias(dce, alias, buffer)
            general = samr.hSamrQueryInformationAlias(dce, alias, 1)['Buffer']['General']
            samr.hSamrRemoveMemberFromAlias(dce, alias, member_sid)
            remaining = samr.hSamrGetMembersInAlias(dce, alias)['Members']['Count']
            check(SET_ALIAS, general['AdminComment'] == comment and remaining == 0,
                  (general['AdminComment'], remaining))
        except Exception as error:  # noqa: BLE001
            check(SET_ALIAS, False, '%s: %s' % (type(error).__name__, error))
        try:
            samr.hSamrDeleteAlias(dce, alias)
            check(DELETE_ALIAS, True)
        except Exception as error:  # noqa: BLE001
            check(DELETE_ALIAS, False, '%s: %s' % (type(error).__name__, error))

    try:
        samr.hSamrDeleteUser(dce, user)
        check(DELETE_USER, True)
    except Exception as error:  # noqa: BLE001
        check(DELETE_USER, False, '%s: %s' % (type(error).__name__, error))
    if group is not None:
        try:
            samr.hSamrDeleteGroup(dce, group)
            check(DELETE_GROUP, True)
        except Exception as error:  # noqa: BLE001
            check(DELETE_GROUP, False, '%s: %s' % (type(error).__name__, error))
    try:
        samr.hSamrCloseHandle(dce, domain)
        samr.hSamrCloseHandle(dce, server)
        check(CLOSE, True)
    except Exception as error:  # noqa: BLE001
        check(CLOSE, False, '%s: %s' % (type(error).__name__, error))

    print('\n%d failure(s): %s' % (len(failures), failures))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
