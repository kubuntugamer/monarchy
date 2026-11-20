#!/usr/bin/python3
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check an inter-domain trust the way a real client uses it.

Two halves, and the second is the one that matters:

  * the LSAD surface — create a trust over lsarpc, read it back at the levels a
    client asks for, list it, and open it by name. Every call is marshalled by
    Samba's pidl-generated NDR (``samba.dcerpc.lsa``), which is written from
    MS-LSAD, so a reply only this tree understands fails here.
  * a cross-realm ticket, when a krb5.conf naming both realms is supplied:
    MIT's ``kinit`` authenticates in the peer realm, then ``kvno`` asks this
    realm's KDC for a service principal here. MIT walks the trust itself — it
    asks the peer KDC for a referral, takes that ticket to this KDC and gets
    the service ticket — so a KDC that merely stores a trustedDomain object
    fails.

Both directions of the trust are the operator's business: run this against each
DC with the other realm as ``--peer-realm`` and the same ``--trust-password``.

Usage:
  scripts/trust-conformance.py [options]

Options:
  --host HOST            DC address. Default: 127.0.0.1
  --port PORT            lsarpc port. Default: 1036 (the console's lsadPort)
  --user USER            Account able to administer the LSA policy
  --password PASS        Its password
  --domain DOMAIN        Its NetBIOS domain name
  --peer-realm REALM     The realm on the other side of the trust
  --peer-netbios NAME    That realm's NetBIOS name
  --peer-sid SID         That realm's domain SID
  --trust-password PASS  The shared secret both sides are given
  --krb5-conf PATH       A krb5.conf naming both realms, for the ticket half
  --kinit PATH           kinit to drive it. Default: /usr/bin/kinit
  --kvno PATH            kvno to drive it. Default: /usr/bin/kvno
  --peer-admin USER      Peer-realm account for kinit. Default: Administrator
  --peer-password PASS   Its password
  --peer-spn SPN         Service principal in this realm to ask for. Default:
                         ldap/<this DC's host>@<this realm>

Exit status is 0 only when every check passes, 1 when one fails and 2 when the
script cannot run here (Samba's pidl bindings are missing).
"""
import argparse
import os
import subprocess
import sys

try:
    from samba import param
    from samba.credentials import Credentials
    from samba.dcerpc import lsa
    from samba.dcerpc.security import dom_sid
except ImportError as error:  # pragma: no cover - the message is the check
    print('trust-conformance: Samba pidl bindings are not available (%s)' % error)
    print('trust-conformance: this check needs samba.dcerpc.lsa, as the Samba '
          'half of lsad-conformance does')
    raise SystemExit(2)

failures = []


def check(label, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + label + ((' :: ' + str(detail)) if detail else ''))
    sys.stdout.flush()
    if not ok:
        failures.append(label)
    return ok


def connect(args):
    lp = param.LoadParm()
    lp.set('netbios name', 'MONARCHYTRUST')
    creds = Credentials()
    creds.set_username(args.user)
    creds.set_password(args.password)
    creds.set_domain(args.domain)
    creds.set_workstation('MONARCHYTRUST')
    binding = 'ncacn_ip_tcp:%s[%d]' % (args.host, args.port)
    return lsa.lsarpc(binding, lp, creds)


def auth_info(password):
    """lsa_TrustDomainInfoAuthInfo carrying a clear-text trust password.

    The secret travels as TRUST_AUTH_TYPE_CLEAR, which is what lets the DC
    derive the same inter-realm krbtgt keys both sides of the trust use.
    """
    buffer = lsa.TrustDomainInfoBuffer()
    buffer.AuthType = 2
    buffer.last_update_time = 0
    blob = lsa.DATA_BUF2()
    raw = password.encode('utf-8')
    blob.size = len(raw)
    blob.data = list(raw)
    buffer.data = blob
    info = lsa.TrustDomainInfoAuthInfo()
    info.incoming_count = 1
    info.incoming_current_auth_info = buffer
    info.outgoing_count = 1
    info.outgoing_current_auth_info = buffer
    return info


def lsad_half(args):
    interface = connect(args)
    check('bind lsarpc (Samba pidl NDR)', True)
    policy = interface.OpenPolicy2(None, lsa.ObjectAttribute(),
                                   lsa.LSA_POLICY_ALL_ACCESS)
    check('LsarOpenPolicy2', True)

    info = lsa.TrustDomainInfoInfoEx()
    info.domain_name = lsa.StringLarge()
    info.domain_name.string = args.peer_realm
    info.netbios_name = lsa.StringLarge()
    info.netbios_name.string = args.peer_netbios
    info.sid = dom_sid(args.peer_sid)
    info.trust_direction = 3
    info.trust_type = 2
    info.trust_attributes = 0
    handle = interface.CreateTrustedDomainEx(policy, info,
                                             auth_info(args.trust_password),
                                             lsa.LSA_TRUSTED_DOMAIN_ALL_ACCESS)
    check('LsarCreateTrustedDomainEx(%s)' % args.peer_realm, True)

    basic = interface.QueryTrustedDomainInfo(handle, lsa.LSA_TRUSTED_DOMAIN_INFO_BASIC)
    check('QueryTrustedDomainInfo level 5 (basic)',
          basic.netbios_name.string == args.peer_netbios,
          '%s %s' % (basic.netbios_name.string, basic.sid))

    partner = lsa.String()
    partner.string = args.peer_realm
    ex = interface.QueryTrustedDomainInfoByName(policy, partner,
                                                lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX)
    check('QueryTrustedDomainInfoByName level 6 (info ex)',
          ex.domain_name.string.upper() == args.peer_realm.upper()
          and ex.trust_direction == 3,
          'partner=%s flat=%s direction=%d type=%d'
          % (ex.domain_name.string, ex.netbios_name.string,
             ex.trust_direction, ex.trust_type))

    # The binding answers the [in,out] resume handle and the list together, so
    # the call returns (resume_handle, domains).
    resume, enum = interface.EnumTrustedDomainsEx(policy, 0, 0x1000)
    partners = [entry.domain_name.string for entry in enum.domains]
    check('EnumTrustedDomainsEx lists the trust', args.peer_realm in partners,
          '%s resume=%d' % (partners, resume))

    opened = interface.OpenTrustedDomainByName(policy, partner,
                                               lsa.LSA_TRUSTED_DOMAIN_ALL_ACCESS)
    check('OpenTrustedDomainByName', opened is not None)


def ticket_half(args):
    """MIT walks the trust: kinit in the peer realm, then a ticket from here."""
    environment = dict(os.environ)
    environment['KRB5_CONFIG'] = args.krb5_conf
    cache = '/tmp/trust-conformance-ccache-%d' % os.getpid()
    environment['KRB5CCNAME'] = cache

    kinit = subprocess.run([args.kinit, '%s@%s' % (args.peer_admin, args.peer_realm)],
                           input=args.peer_password,
                           env=environment, capture_output=True, text=True)
    check('kinit in %s' % args.peer_realm, kinit.returncode == 0,
          (kinit.stderr or kinit.stdout).strip().splitlines()[-1:] or '')

    kvno = subprocess.run([args.kvno, args.peer_spn], env=environment,
                          capture_output=True, text=True)
    check('kvno %s across the trust' % args.peer_spn, kvno.returncode == 0,
          (kvno.stdout or kvno.stderr).strip().splitlines()[-1:] or '')

    listing = subprocess.run(['/usr/bin/klist', '-c', cache], env=environment,
                             capture_output=True, text=True)
    # A successful kvno leaves the service ticket in the cache, signed for by
    # this realm's KDC from a ticket the peer realm issued: the whole path.
    service_name = args.peer_spn.split('@')[0]
    check('the cache holds the service ticket from this realm',
          service_name in listing.stdout,
          [line.strip() for line in listing.stdout.splitlines() if service_name in line])
    try:
        os.unlink(cache)
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=1036)
    parser.add_argument('--user', default='Administrator')
    parser.add_argument('--password', required=True)
    parser.add_argument('--domain', default='CORP')
    parser.add_argument('--peer-realm', required=True)
    parser.add_argument('--peer-netbios', required=True)
    parser.add_argument('--peer-sid', required=True)
    parser.add_argument('--trust-password', required=True)
    parser.add_argument('--krb5-conf')
    parser.add_argument('--kinit', default='/usr/bin/kinit')
    parser.add_argument('--kvno', default='/usr/bin/kvno')
    parser.add_argument('--peer-admin', default='Administrator')
    parser.add_argument('--peer-password', default='')
    parser.add_argument('--peer-spn', default='')
    args = parser.parse_args()

    lsad_half(args)

    if args.krb5_conf:
        if not args.peer_password:
            check('cross-realm ticket', False, '--krb5-conf needs --peer-password')
        else:
            if not args.peer_spn:
                check('cross-realm ticket', False, '--krb5-conf without --peer-spn')
            else:
                ticket_half(args)

    print('%d failure(s): %s' % (len(failures), failures))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
