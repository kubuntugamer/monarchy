#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the DC's drsuapi endpoint with the client the DCSync tools use.

Nothing below is checked against this server's own encoder: every call is
marshalled and unmarshalled by impacket's NDR implementation, which is
written from MS-DRSR directly, so a reply only this server understands
fails here. The sequence mirrors what impacket's secretsdump performs for
a DCSync pull:

  * DCE bind to the DRSUAPI presentation context
  * DRSBind (opnum 0) — the handle and the extension words
  * DRSDomainControllerInfo (opnum 16, level 2) — the DSA GUID a
    GetNCChanges addresses
  * DRSCrackNames (opnum 12) — FQDN to canonical form
  * DRSGetNCChanges (opnum 3): a whole-NC V8 request answered in V6, the
    object chain walked element by element with its attributes read back,
    then one targeted EXOP_REPL_OBJ for a single account
  * DRSUnbind (opnum 1)

Two endpoints serve this interface. The development probe
(build/ui/monarchy-drs-probe PORT) answers without authentication and
carries a fixed fixture (the domain, CN=Users, alice and
Administrator); the console serves it on drsPort (1038 by default)
behind the same NTLMSSP authenticator as SAMR, so pass --user and
--password there. The fixture differences are absorbed by the checks:
object counts are floors, and the Administrator account is located by
its DN rather than by position.

Usage:
  scripts/drs-conformance.py [options]

Options:
  --host HOST        DC address. Default: 127.0.0.1
  --port PORT        drsuapi port. Default: 1038 (the console's drsPort)
  --basedn DN        Domain NC. Default: DC=corp,DC=example,DC=com
  --dnsdomain DNS    DNS domain name. Default: corp.example.com
  --netbios NB       NetBIOS domain name. Default: CORP
  --user USER        Account for an authenticated bind (console endpoint)
  --password PASS    Its password
  --domain DOMAIN    Its domain. Default: the NetBIOS name

Exit status is 0 only when every check passes.
"""
import argparse
import struct
import sys

from impacket.dcerpc.v5 import transport, drsuapi
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


def _text(value):
    if isinstance(value, (bytes, bytearray)):
        return value.decode('utf-16-le', 'replace')
    return str(value)


def _raw(value):
    """Whatever an impacket byte array decoded to, as bytes.

    impacket hands back BYTE arrays as lists whose items may be ints or
    one-byte bytes, so walk it item by item.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode('latin-1', 'replace')
    out = bytearray()
    for item in value:
        if isinstance(item, (bytes, bytearray)):
            out.extend(item)
        else:
            out.append(int(item))
    return bytes(out)


def connect(args):
    binding = 'ncacn_ip_tcp:%s[%d]' % (args.host, args.port)
    rpctransport = transport.DCERPCTransportFactory(binding)
    if args.password:
        rpctransport.set_credentials(args.user, args.password,
                                     args.domain, 'CONFORMANCE')
    dce = rpctransport.get_dce_rpc()
    if args.password:
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)
    return dce


def run(args):
    dce = connect(args)
    context = {}

    def step(name, fn):
        try:
            fn()
            print('PASS  %s' % name)
        except AssertionError as exc:
            print('FAIL  %s: %s' % (name, exc))
            raise
        except Exception as exc:  # noqa: BLE001 - any error is a failure
            print('FAIL  %s: %s: %s' % (name, type(exc).__name__, exc))
            raise

    # --- DRSBind (opnum 0) -------------------------------------------------
    def drs_bind():
        request = drsuapi.DRSBind()
        request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs)
        drs['dwFlags'] = (drsuapi.DRS_EXT_GETCHGREQ_V6
                          | drsuapi.DRS_EXT_GETCHGREPLY_V6
                          | drsuapi.DRS_EXT_GETCHGREQ_V8
                          | drsuapi.DRS_EXT_STRONG_ENCRYPTION)
        drs['SiteObjGuid'] = drsuapi.NULLGUID
        drs['Pid'] = 0
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = 0
        drs['ConfigObjGUID'] = drsuapi.NULLGUID
        drs['dwExtCaps'] = 0xffffffff
        request['pextClient']['cb'] = len(drs)
        request['pextClient']['rgb'] = list(drs.getData())
        resp = dce.request(request)
        assert resp['ErrorCode'] == 0, 'ErrorCode 0x%x' % resp['ErrorCode']
        cb = int(resp['ppextServer']['cb'])
        rgb = _raw(resp['ppextServer']['rgb'])
        assert cb == len(rgb), 'cb=%d over %d bytes' % (cb, len(rgb))
        flags = struct.unpack_from('<I', rgb, 0)[0]
        assert flags == 0x25100000, 'dwFlags 0x%08x' % flags
        context['hDrs'] = resp['phDrs']

    step('DRSBind extensions', drs_bind)

    # --- DRSDomainControllerInfo (opnum 16) --------------------------------
    def dcinfo():
        resp = drsuapi.hDRSDomainControllerInfo(
            dce, context['hDrs'], args.dnsdomain.upper(), 2)
        assert resp['pmsgOut']['tag'] == 2, 'tag %d' % resp['pmsgOut']['tag']
        items = resp['pmsgOut']['V2']['cItems']
        assert items >= 1, 'cItems %d' % items
        item = resp['pmsgOut']['V2']['rItems'][0]
        guid = str(item['NtdsDsaObjectGuid'])
        assert guid.strip('0-'), 'all-zero DSA guid'
        enabled = item['fDsEnabled']
        if not isinstance(enabled, int):
            enabled = int.from_bytes(_raw(enabled), 'little')
        assert enabled == 1, 'fDsEnabled unset'
        host = _text(item['DnsHostName']).rstrip('\x00')
        assert host, 'empty DnsHostName'
        context['guid'] = guid

    step('DRSDomainControllerInfo level 2', dcinfo)

    # --- DRSCrackNames (opnum 12) ------------------------------------------
    def cracknames():
        dn = 'CN=Administrator,CN=Users,' + args.basedn
        resp = drsuapi.hDRSCrackNames(
            dce, context['hDrs'], 0,
            drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME,
            drsuapi.DS_NAME_FORMAT.DS_CANONICAL_NAME, (dn,))
        result = resp['pmsgOut']['V1']['pResult']
        assert result['cItems'] == 1, 'cItems %d' % result['cItems']
        item = result['rItems'][0]
        status = int(item['status'])
        name = _text(item['pName']).rstrip('\x00')
        domain = _text(item['pDomain']).rstrip('\x00')
        expected = args.dnsdomain + '/Users/Administrator'
        assert status == 0, 'status %d' % status
        assert name == expected, '%r != %r' % (name, expected)
        assert domain == args.dnsdomain, '%r != %r' % (domain, args.dnsdomain)

    step('DRSCrackNames FQDN to canonical', cracknames)

    # --- DRSGetNCChanges (opnum 3), whole NC -------------------------------
    def make_dn_dsname(dn):
        ds = drsuapi.DSNAME()
        ds['SidLen'] = 0
        ds['Guid'] = b'\x00' * 16
        ds['Sid'] = ''
        ds['NameLen'] = len(dn) * 2
        ds['StringName'] = dn
        ds['structLen'] = len(ds.getData())
        return ds

    def getnc(dn, max_objects, extended_op=0):
        request = drsuapi.DRSGetNCChanges()
        request['hDrs'] = context['hDrs']
        request['dwInVersion'] = 8
        request['pmsgIn']['tag'] = 8
        request['pmsgIn']['V8']['uuidDsaObjDest'] = context['guid']
        request['pmsgIn']['V8']['uuidInvocIdSrc'] = context['guid']
        request['pmsgIn']['V8']['pNC'] = make_dn_dsname(dn)
        request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0
        request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0
        request['pmsgIn']['V8']['pUpToDateVecDest'] = drsuapi.NULL
        request['pmsgIn']['V8']['ulFlags'] = (drsuapi.DRS_INIT_SYNC
                                              | drsuapi.DRS_WRIT_REP)
        request['pmsgIn']['V8']['cMaxObjects'] = max_objects
        request['pmsgIn']['V8']['cMaxBytes'] = 0
        request['pmsgIn']['V8']['ulExtendedOp'] = extended_op
        request['pmsgIn']['V8']['pPartialAttrSet'] = drsuapi.NULL
        request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = 0
        request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = []
        request['pmsgIn']['V8']['pPartialAttrSetEx1'] = drsuapi.NULL
        return dce.request(request)

    def walk_chain(arm):
        """Every element of pObjects: DN, attribute count, values by attid."""
        objects = {}
        node = arm['pObjects']
        seen = 0
        while node is not None and hasattr(node, 'fields') \
                and 'Entinf' in node.fields:
            entinf = node['Entinf']
            name = entinf['pName']
            dn = _text(name['StringName']).rstrip('\x00')
            attrblock = entinf['AttrBlock']
            count = int(attrblock['attrCount'])
            by_attid = {}
            pattr = attrblock['pAttr']
            for index in range(count):
                attr = pattr[index]
                attid = int(attr['attrTyp'])
                values = []
                pvalues = attr['AttrVal']['pAVal']
                for value_index in range(int(attr['AttrVal']['valCount'])):
                    values.append(_raw(pvalues[value_index]['pVal']))
                by_attid[attid] = values
            objects[dn] = {'attrCount': count, 'attrs': by_attid}
            seen += 1
            assert seen < 10000, 'chain does not terminate'
            try:
                nxt = node['pNextEntInf']
            except (KeyError, AttributeError):
                nxt = None
            node = nxt if hasattr(nxt, 'fields') and 'Entinf' in nxt.fields \
                else None
        return objects

    def getnc_batch():
        resp = getnc(args.basedn, 1000)
        assert resp['pdwOutVersion'] == 6, 'pdwOutVersion %d' \
            % resp['pdwOutVersion']
        assert resp['pmsgOut']['tag'] == 6, 'tag %d' % resp['pmsgOut']['tag']
        arm = resp['pmsgOut']['V6']
        assert int(arm['PrefixTableSrc']['PrefixCount']) == 19, \
            'prefix count %d' % arm['PrefixTableSrc']['PrefixCount']
        assert int(arm['ulExtendedRet']) == 0, 'ulExtendedRet %d' \
            % arm['ulExtendedRet']
        count = int(arm['cNumObjects'])
        assert count >= 2, 'cNumObjects %d' % count
        assert int(arm['fMoreData']) == 0, 'fMoreData set'
        assert int(arm['cNumBytes']) > 0, 'cNumBytes 0'

        objects = walk_chain(arm)
        assert args.basedn in objects, 'domain NC head missing: %r' \
            % sorted(objects)
        admin_dn = 'CN=Administrator,CN=Users,' + args.basedn
        assert admin_dn in objects, 'Administrator missing: %r' % sorted(objects)

        admin = objects[admin_dn]
        required = {
            0x000900DD,  # sAMAccountName
            0x00090092,  # objectSid
            0x00000031,  # distinguishedName
            0x00090290,  # userPrincipalName
            0x00090008,  # userAccountControl
            0x00000000,  # objectClass
            0x00000003,  # cn
            0x00090002,  # objectGuid
            0x00020001,  # instanceType
        }
        missing = required - set(admin['attrs'])
        assert not missing, 'attributes missing: %r' % sorted(missing)
        sam = admin['attrs'][0x000900DD][0]
        assert sam == 'Administrator'.encode('utf-16-le'), \
            'sAMAccountName %r' % sam
        sid = admin['attrs'][0x00090092][0]
        assert sid[:2] == b'\x01\x05', 'objectSid prefix %r' % sid[:4]
        uac = struct.unpack('<I', admin['attrs'][0x00090008][0])[0]
        assert uac & 0x200, 'userAccountControl 0x%x' % uac
        guid = admin['attrs'][0x00090002][0]
        assert len(guid) == 16, 'objectGuid length %d' % len(guid)

    step('DRSGetNCChanges V6 batch with attribute walk', getnc_batch)

    # --- DRSGetNCChanges, targeted EXOP_REPL_OBJ ---------------------------
    def getnc_target():
        admin_dn = 'CN=Administrator,CN=Users,' + args.basedn
        resp = getnc(admin_dn, 1, drsuapi.EXOP_REPL_OBJ)
        arm = resp['pmsgOut']['V6' if resp['pmsgOut']['tag'] == 6 else 'V1']
        assert int(arm['cNumObjects']) == 1, 'cNumObjects %d' \
            % arm['cNumObjects']
        # DRSUAPI_EXOP_ERR_SUCCESS is 1 in the IDL (impacket has no name
        # for it); EXOP_ERR_NONE, the plain cycle's answer, is 0.
        assert int(arm['ulExtendedRet']) == 1, \
            'ulExtendedRet %d' % arm['ulExtendedRet']
        objects = walk_chain(arm)
        assert admin_dn in objects, 'targeted object missing'

    step('DRSGetNCChanges EXOP_REPL_OBJ', getnc_target)

    # --- DRSUnbind (opnum 1) ------------------------------------------------
    def unbind():
        resp = drsuapi.hDRSUnbind(dce, context['hDrs'])
        assert resp['ErrorCode'] == 0, 'ErrorCode 0x%x' % resp['ErrorCode']

    step('DRSUnbind', unbind)
    dce.disconnect()


def main():
    parser = argparse.ArgumentParser(
        description='MS-DRSR conformance against a Monarchy DC, driven by '
                    "impacket's NDR (the client secretsdump is built on).")
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=1038)
    parser.add_argument('--basedn', default='DC=corp,DC=example,DC=com')
    parser.add_argument('--dnsdomain', default='corp.example.com')
    parser.add_argument('--netbios', default='CORP')
    parser.add_argument('--user', default='')
    parser.add_argument('--password', default='')
    parser.add_argument('--domain', default=None)
    args = parser.parse_args()
    if args.domain is None:
        args.domain = args.netbios

    try:
        run(args)
    except Exception as exc:  # noqa: BLE001 - reported above, exit status is the point
        import traceback
        traceback.print_exc()
        print('DRSR conformance FAILED: %s: %s' % (type(exc).__name__, exc))
        return 1
    print('DRSR conformance PASSED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
