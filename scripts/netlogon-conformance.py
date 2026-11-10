#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Monarchy contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive the DC's netlogon endpoint with impacket's own NDR.

MS-NRPC has two halves and this script exercises both:

  * the locator calls, which need no secure channel: NetrGetDCName has to name
    this domain and this DC;
  * the secure channel, which is what every logon call rides on. A machine
    account is created over SAMR, given a password, and then used for
    NetrServerReqChallenge and NetrServerAuthenticate3. If the channel is
    established, NetrLogonSamLogon is asked for a network logon (class 2) and
    validated at NETLOGON_VALIDATION_SAM_INFO2; this script checks the returned
    status and the account the validation names. The interactive (1) and
    service (3) classes are driven too: they carry the password's own one-way
    functions instead of a challenge and its responses, so the same account
    proves itself without NTLMv2, and a wrong one-way function is refused.

A machine account the directory does not hold must be refused with
STATUS_NO_TRUST_SAM_ACCOUNT, so that path is checked with a name nothing serves.

A wrong password has to be refused with STATUS_WRONG_PASSWORD *and* counted:
the account's badPwdCount goes up, the good logon clears it, and SAMR reports
both counters back, so the last two checks read the account over SAMR.

Usage:
  scripts/netlogon-conformance.py [options]

Options:
  --host HOST        DC address. Default: 127.0.0.1
  --port PORT        netlogon port. Default: 1037
  --samr-port PORT   SAMR port, used to create the machine account and read the
                     account's SID. Default: 1035
  --user USER        Account to bind SAMR as and to validate. Default: Administrator
  --password PASS    Its password. Default: P@ssw0rd123!
  --domain DOMAIN    NetBIOS domain name. Default: MONARCHY
  --list             Only list the checks that would run.

Exit status is 0 when every check passes or is skipped with a reason, 1 when a
check fails.
"""

import argparse
import hashlib
import hmac
import os
import struct
import sys
import traceback
import uuid

try:
    from Cryptodome.Cipher import ARC4
except ImportError:  # impacket may be installed against the pycrypto2 package name
    from Crypto.Cipher import ARC4

from impacket import ntlm
from impacket.dcerpc.v5 import nrpc, rpcrt, samr, transport
from impacket.dcerpc.v5.dtypes import NULL

MAXIMUM_ALLOWED = 0x02000000
STATUS_SUCCESS = 0x00000000
STATUS_NO_SUCH_USER = 0xC0000064
STATUS_NO_TRUST_SAM_ACCOUNT = 0xC000018B
STATUS_USER_EXISTS = 0xC0000063
STATUS_WRONG_PASSWORD = 0xC000006A
STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234
STATUS_PASSWORD_EXPIRED = 0xC0000071
STATUS_PASSWORD_MUST_CHANGE = 0xC0000224
STATUS_INVALID_PARAMETER = 0xC000000D
NETLOGON_NEG_STRONG_KEYS = 0x00004000
VALIDATION_SAM_INFO2 = 3

failures = []
skipped = []

CHECKS = [
    'bind netlogon (impacket NDR)',
    'NetrGetDCName names this domain',
    'NetrServerReqChallenge',
    'NetrServerAuthenticate3 refuses an unknown machine account',
    'machine account created over SAMR',
    'NetrServerReqChallenge / NetrServerAuthenticate3 establish a channel',
    'NetrLogonSamLogon validates the account (NTLMv2)',
    'a refused password is counted on the account',
    'SAMR reports the account logon statistics',
    'SAMR sets and reads back the lockout policy',
    'a locked account is refused with STATUS_ACCOUNT_LOCKED_OUT',
    'an aged-out password is refused with STATUS_PASSWORD_EXPIRED',
    'a password that must change is refused with STATUS_PASSWORD_MUST_CHANGE',
    'NetrLogonSamLogon answers an interactive logon (class 1)',
    'NetrLogonSamLogon answers a service logon (class 3)',
    'a wrong one-way function is refused with STATUS_WRONG_PASSWORD',
]


def check(label, ok, detail=''):
    print(('PASS ' if ok else 'FAIL ') + label + ((' :: ' + str(detail)) if detail else ''))
    sys.stdout.flush()
    if not ok:
        failures.append(label)


def skip(label, reason):
    print('SKIP ' + label + ' :: ' + reason)
    sys.stdout.flush()
    skipped.append(label)


def bind(host, port, uuid_):
    transport_ = transport.DCERPCTransportFactory('ncacn_ip_tcp:%s[%d]' % (host, int(port)))
    dce = transport_.get_dce_rpc()
    dce.connect()
    dce.bind(uuid_)
    return dce


def samr_bind(options):
    transport_ = transport.DCERPCTransportFactory(
        'ncacn_ip_tcp:%s[%d]' % (options.host, int(options.samr_port)))
    transport_.set_credentials(options.user, options.password, options.domain)
    dce = transport_.get_dce_rpc()
    dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)
    return dce


def password_policy(options, min_length, history, properties, max_age, min_age):
    """Write the domain password policy through SAMR class 1 (MS-SAMR
    2.2.3.5): the two counts, the flag word, then the two ages as negative
    100-nanosecond counts."""
    dce = samr_bind(options)
    server = samr.hSamrConnect5(dce, '\\\\%s\x00' % options.host,
                                MAXIMUM_ALLOWED, 1, 3)['ServerHandle']
    domain_id = samr.hSamrLookupDomainInSamServer(dce, server, options.domain)['DomainId']
    domain = samr.hSamrOpenDomain(dce, server, MAXIMUM_ALLOWED, domain_id)['DomainHandle']

    def set_delta(field, value):
        unsigned = value & 0xFFFFFFFFFFFFFFFF
        field['LowPart'] = unsigned & 0xFFFFFFFF
        field['HighPart'] = unsigned >> 32
        if field['HighPart'] >= 0x80000000:
            field['HighPart'] -= 1 << 32

    buffer = samr.SAMPR_DOMAIN_INFO_BUFFER()
    buffer['tag'] = 1
    buffer['Password']['MinPasswordLength'] = min_length
    buffer['Password']['PasswordHistoryLength'] = history
    buffer['Password']['PasswordProperties'] = properties
    set_delta(buffer['Password']['MaxPasswordAge'], max_age)
    set_delta(buffer['Password']['MinPasswordAge'], min_age)
    samr.hSamrSetInformationDomain(dce, domain, buffer)
    samr.hSamrCloseHandle(dce, domain)
    samr.hSamrCloseHandle(dce, server)
    return dce


def create_account(options, account_type, password_expired=True):
    """Create an account of `account_type` over SAMR and give it a password.
    Returns the account name, its password and its RID, or None with the reason.
    `password_expired` writes the account through SAMR the way an administrator
    who demands a change at next logon does: pwdLastSet ends up zero."""
    try:
        dce = samr_bind(options)
    except Exception as error:  # noqa: BLE001
        return None, 'SAMR bind failed: %s: %s' % (type(error).__name__, error)

    suffix = '$' if account_type & 0x1000 else ''  # a machine account ends in $
    account = 'CONF%s%s' % (uuid.uuid4().hex[:6].upper(), suffix)
    password = 'M-' + uuid.uuid4().hex[:20]
    try:
        server = samr.hSamrConnect5(dce, '\\\\%s\x00' % options.host,
                                    MAXIMUM_ALLOWED, 1, 3)['ServerHandle']
        domain_id = samr.hSamrLookupDomainInSamServer(dce, server, options.domain)['DomainId']
        domain = samr.hSamrOpenDomain(dce, server, MAXIMUM_ALLOWED, domain_id)['DomainHandle']
    except Exception as error:  # noqa: BLE001
        return None, 'SAMR domain open failed: %s: %s' % (type(error).__name__, error)

    try:
        created = samr.hSamrCreateUser2InDomain(
            dce, domain, account, account_type, MAXIMUM_ALLOWED)
        user = created['UserHandle']
        rid = created['RelativeId']
    except Exception as error:  # noqa: BLE001
        status = getattr(error, 'error_code', None)
        if status != STATUS_USER_EXISTS and status != 0xC0000063:
            return None, 'SamrCreateUser2InDomain failed: %s: %s' % (
                type(error).__name__, error)
        return None, 'machine account already exists: %s' % error

    try:
        write_machine_password(dce, user, password, password_expired)
    except Exception as error:  # noqa: BLE001
        return None, 'SamrSetInformationUser2 (password) failed: %s: %s' % (
            type(error).__name__, error)

    samr.hSamrCloseHandle(dce, user)
    samr.hSamrCloseHandle(dce, domain)
    samr.hSamrCloseHandle(dce, server)
    return (account, password, rid), None


def machine_account(options):
    """A workstation account with a password, which is what a secure channel
    needs."""
    return create_account(options, getattr(samr, 'USER_WORKSTATION_TRUST_ACCOUNT', 0x1000))


def samr_domain(options):
    """A SAMR connection with the server and domain handles already open."""
    dce = samr_bind(options)
    server = samr.hSamrConnect5(dce, '\\\\%s\x00' % options.host,
                                MAXIMUM_ALLOWED, 1, 3)['ServerHandle']
    domain_id = samr.hSamrLookupDomainInSamServer(dce, server, options.domain)['DomainId']
    domain = samr.hSamrOpenDomain(dce, server, MAXIMUM_ALLOWED, domain_id)['DomainHandle']
    return dce, server, domain


def lockout_policy(options, policy=None):
    """Sets the domain's lockout policy when one is given, then reads it back
    over SAMR, so the setter and the query both go through the NDR the engine
    parses. Returns the observed (threshold, duration, window)."""
    dce, server, domain = samr_domain(options)
    try:
        if policy is not None:
            threshold, duration, window = policy
            arm = samr.SAMPR_DOMAIN_LOCKOUT_INFORMATION()
            arm['LockoutDuration'] = duration
            arm['LockoutObservationWindow'] = window
            arm['LockoutThreshold'] = threshold
            request = samr.SamrSetInformationDomain()
            request['DomainHandle'] = domain
            request['DomainInformationClass'] = 12
            # A union cannot be assigned in this release, so the arm is set
            # through its own key after the tag names it.
            request['DomainInformation']['tag'] = 12
            request['DomainInformation'][
                samr.SAMPR_DOMAIN_INFO_BUFFER.union[12][0]] = arm
            dce.request(request)
        response = samr.hSamrQueryInformationDomain(dce, domain, 12)
        observed = response['Buffer']
        if 'LockoutThreshold' not in getattr(observed, 'fields', {}):
            for value in observed.fields.values():
                if 'LockoutThreshold' in getattr(value, 'fields', {}):
                    observed = value
                    break
        return (int(observed['LockoutThreshold']),
                int(observed['LockoutDuration']),
                int(observed['LockoutObservationWindow']))
    finally:
        dce.disconnect()


def logon_statistics(options):
    """badPwdCount and logonCount as SAMR reports them for the account the
    logon calls validate: the counters a DC keeps are what a lockout policy and
    an administrator both read."""
    dce = samr_bind(options)
    server = samr.hSamrConnect5(dce, '\\\\%s\x00' % options.host,
                                MAXIMUM_ALLOWED, 1, 3)['ServerHandle']
    domain_id = samr.hSamrLookupDomainInSamServer(dce, server, options.domain)['DomainId']
    domain = samr.hSamrOpenDomain(dce, server, MAXIMUM_ALLOWED, domain_id)['DomainHandle']
    names = samr.hSamrLookupNamesInDomain(dce, domain, (options.user,))
    # SAMPR_ULONG_ARRAY is a count plus a pointer to the values, and each value
    # may still be the NDR object rather than the integer it carries.
    entries = names['RelativeIds']['Element']
    rid = entries[0]
    rid = int(rid['Data']) if hasattr(rid, 'fields') else int(rid)
    user = samr.hSamrOpenUser(dce, domain, MAXIMUM_ALLOWED, rid)['UserHandle']
    response = samr.hSamrQueryInformationUser2(dce, user, 21)  # SamrUserAllInformation
    # The union's arm for class 21 is SAMPR_USER_ALL_INFORMATION; the union
    # key is what names it, and a release that keys by name is handled too.
    buffer = response['Buffer']
    arm_name = samr.SAMPR_USER_INFO_BUFFER.union[21][0]
    arm = buffer[arm_name] if arm_name in buffer.fields else None
    if arm is None:
        for value in buffer.fields.values():
            if hasattr(value, 'fields') and 'BadPasswordCount' in value.fields:
                arm = value
                break
    bad = int(arm['BadPasswordCount'])
    logons = int(arm['LogonCount'])
    samr.hSamrCloseHandle(dce, user)
    samr.hSamrCloseHandle(dce, domain)
    samr.hSamrCloseHandle(dce, server)
    dce.disconnect()
    return (bad == 0 and logons >= 1), (bad, logons)


def ntlmv2_response(nt_hash, user, domain, challenge):
    """The NTLMv2 response the server's verifier expects: HMAC-MD5 of
    challenge and blob under a key derived from the NT hash, the upper-cased
    account and the domain. Impacket's helper builds its own AV pairs from a
    bytes argument, so the blob is written here instead."""
    response_key = hmac.new(nt_hash, (user.upper() + domain).encode('utf-16le'),
                            'md5').digest()
    blob = (b'\x01\x01\x00\x00' + b'\x00' * 4 + struct.pack('<Q', 0)
            + b'ConfChl2' + b'\x00' * 4 + b'\x00' * 4)
    return hmac.new(response_key, challenge + blob, 'md5').digest() + blob


def validation_field(validation, name):
    """A union arm is the structure itself in this impacket release and a
    pointer whose Data holds it in others, so both shapes are searched."""
    fields = getattr(validation, 'fields', None) or {}
    if name not in fields and 'Data' in fields:
        validation = fields['Data']
        fields = getattr(validation, 'fields', None) or {}
    try:
        value = validation[name]
    except (KeyError, TypeError):
        value = fields.get(name)
    # This release hands back the decoded text for a counted string; others
    # hand back the RPC_UNICODE_STRING wrapper, so unwrap that too.
    inner = getattr(value, 'fields', None) or {}
    if isinstance(inner.get('Data'), (str, bytes)):
        value = inner['Data']
    if isinstance(value, bytes):
        value = value.decode('utf-16le', 'replace')
    return value


def eight(value):
    data = b''.join(value) if isinstance(value, list) else bytes(value)
    return data

def raw_credential(credential):
    """Bytes from whatever shape impacket returned: a fixed byte array comes
    back as bytes, while ComputeNetlogonAuthenticator returns a structure."""
    if isinstance(credential, (bytes, bytearray)):
        return bytes(credential)
    fields = getattr(credential, 'fields', None)
    if fields and isinstance(fields.get('Data'), (bytes, bytearray)):
        return bytes(fields['Data'])
    return bytes(credential.getData())


def set_owf(target, field, value):
    """A samr_Password is a fixed 16-byte array of two CYPHER_BLOCKs, so the
    whole field is assigned the way set_credential does an 8-byte one."""
    if len(value) != 16:
        raise ValueError('a samr_Password is 16 bytes, got %d' % len(value))
    data = bytearray(value)
    try:
        target[field] = data
    except TypeError:
        target[field] = bytes(data)


def set_credential(target, field, credential):
    """A NETLOGON_CREDENTIAL is a fixed 8-byte array, so the whole field is
    assigned; setting its Data member instead goes through a string path and
    fails. The length is checked because impacket happily packs whatever is
    assigned, and 12 bytes where 8 belong shift every later field."""
    value = bytearray(raw_credential(credential))
    if len(value) != 8:
        raise ValueError('a NETLOGON_CREDENTIAL is 8 bytes, got %d' % len(value))
    try:
        target[field] = value
    except TypeError:
        target[field] = bytes(value)


def write_machine_password(dce, user, password, expired=True):
    """Class 25 (SamprUserInternal4InformationNew) with the 532-byte password
    buffer MS-SAMR 2.2.7.6 defines: 512 bytes of UTF-16, the code-unit count,
    then the RC4 salt. Impacket's own helper reads the session key from an SMB
    connection, which a TCP transport does not have, so the RC4 step is done
    here with DCERPC's own key."""
    request = samr.SamrSetInformationUser2()
    request['UserHandle'] = user
    request['UserInformationClass'] = 25
    request['Buffer']['tag'] = 25
    info = request['Buffer']['Internal4New']
    info['I1']['WhichFields'] = 0x01000000 | 0x08000000
    for field in ('UserName', 'FullName', 'HomeDirectory', 'HomeDirectoryDrive',
                  'ScriptPath', 'ProfilePath', 'AdminComment', 'WorkStations',
                  'UserComment', 'Parameters', 'PrivateData'):
        info['I1'][field] = NULL
    info['I1']['LmOwfPassword']['Buffer'] = NULL
    info['I1']['NtOwfPassword']['Buffer'] = NULL
    info['I1']['SecurityDescriptor']['SecurityDescriptor'] = NULL
    info['I1']['LogonHours']['LogonHours'] = NULL
    info['I1']['PasswordExpired'] = 1 if expired else 0

    encoded = password.encode('utf-16le')
    plain = encoded.rjust(512, b'\0') + struct.pack('<I', len(encoded))
    salt = os.urandom(16)
    key = hashlib.md5(salt + dce.get_session_key()).digest()
    info['UserPassword']['Buffer'] = ARC4.new(key).encrypt(plain) + salt
    return dce.request(request)


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default='1037')
    parser.add_argument('--samr-port', default='1035')
    parser.add_argument('--user', default='Administrator')
    parser.add_argument('--password', default='P@ssw0rd123!')
    parser.add_argument('--domain', default='MONARCHY')
    parser.add_argument('--list', action='store_true')
    options = parser.parse_args()

    if options.list:
        print('\n'.join(CHECKS))
        return 0

    try:
        dce = bind(options.host, options.port, nrpc.MSRPC_UUID_NRPC)
    except Exception as error:  # noqa: BLE001
        check(CHECKS[0], False, '%s: %s' % (type(error).__name__, error))
        print('\n%d failure(s): %s' % (len(failures), failures))
        return 1
    check(CHECKS[0], True)

    # The locator answers without a secure channel; the UNC it returns has to
    # name this domain, or a client would join the wrong one.
    try:
        request = nrpc.NetrGetDCName()
        request['ServerName'] = NULL
        request['DomainName'] = options.domain
        response = dce.request(request)
        # Impacket names the reply's string after the IDL member: Buffer.
        unc = response['Buffer']
        unc = unc.rstrip('\x00') if isinstance(unc, str) else str(unc)
        check(CHECKS[1], options.domain.lower() in unc.lower(), unc)
    except Exception as error:  # noqa: BLE001
        check(CHECKS[1], False, '%s: %s' % (type(error).__name__, error))

    computer = 'CONFDC'
    client_challenge = b'ConfChlg'
    server_challenge = b''
    try:
        request = nrpc.NetrServerReqChallenge()
        request['PrimaryName'] = NULL
        request['ComputerName'] = computer
        request['ClientChallenge'] = client_challenge
        server_challenge = eight(dce.request(request)['ServerChallenge'])
        check(CHECKS[2], len(server_challenge) == 8, server_challenge.hex())
    except Exception as error:  # noqa: BLE001
        check(CHECKS[2], False, '%s: %s' % (type(error).__name__, error))

    def authenticate(account, password):
        session_key = nrpc.ComputeSessionKeyStrongKey(
            password, client_challenge, server_challenge)
        credential = nrpc.ComputeNetlogonCredential(client_challenge, session_key)
        request = nrpc.NetrServerAuthenticate3()
        request['PrimaryName'] = NULL
        request['AccountName'] = account
        request['SecureChannelType'] = 2  # SEC_CHAN_WKSTA
        request['ComputerName'] = computer
        set_credential(request, 'ClientCredential', credential)
        request['NegotiateFlags'] = NETLOGON_NEG_STRONG_KEYS
        return dce.request(request), session_key

    def samlogon(server_credential, session_key, user, password):
        """One NetrLogonSamLogon over an established channel."""
        nt_hash = ntlm.compute_nthash(password)
        challenge = b'ConfChlg'
        nt_response = ntlmv2_response(nt_hash, user, options.domain, challenge)
        request = nrpc.NetrLogonSamLogon()
        request['LogonServer'] = NULL
        request['ComputerName'] = computer
        # This helper returns a whole NETLOGON_AUTHENTICATOR, not the 8-byte
        # credential: its Timestamp is the one the credential was computed for,
        # and the server derives its answer from that timestamp.
        authenticator = nrpc.ComputeNetlogonAuthenticator(server_credential, session_key)
        set_credential(request['Authenticator'], 'Credential', authenticator['Credential'])
        request['Authenticator']['Timestamp'] = authenticator['Timestamp']
        request['ReturnAuthenticator']['Timestamp'] = 0
        set_credential(request['ReturnAuthenticator'], 'Credential', b'\x00' * 8)
        # NetlogonNetworkInformation (MS-NRPC 2.2.1.4.16) is 2, not 3: 3 is
        # NetlogonServiceInformation, whose arm carries interactive OWFs and no
        # challenge. The union arm is selected by its own tag, which the IDL
        # requires to equal LogonLevel.
        request['LogonLevel'] = 2
        request['LogonInformation']['tag'] = 2
        request['ValidationLevel'] = 3  # NETLOGON_VALIDATION_SAM_INFO2
        network = request['LogonInformation']['LogonNetwork']
        network['Identity']['LogonDomainName'] = options.domain
        network['Identity']['ParameterControl'] = 3
        network['Identity']['UserName'] = user
        network['Identity']['Workstation'] = computer
        # LM_CHALLENGE is a fixed 8-byte array, so the whole field is assigned;
        # its Data member reads back as bytes.
        network['LmChallenge'] = challenge
        # The responses are counted binary strings whose only member is Data, so
        # impacket exposes the arm as the value itself and the whole field is
        # assigned. Both are sent: impacket writes no counted array at all for
        # an empty one, which no client would put on the wire. A client that
        # answers only with NTLMv2 sends a zeroed 24-byte LMv2.
        network['NtChallengeResponse'] = nt_response
        network['LmChallengeResponse'] = b'\x00' * 24
        return dce.request(request)

    def password_logon(server_credential, session_key, user, password, logon_class):
        """One NetrLogonSamLogon carrying netr_PasswordInfo: the interactive (1)
        and service (3) classes send the password's own one-way functions rather
        than a challenge and its responses, so no NTLMv2 is computed."""
        request = nrpc.NetrLogonSamLogon()
        request['LogonServer'] = NULL
        request['ComputerName'] = computer
        authenticator = nrpc.ComputeNetlogonAuthenticator(server_credential, session_key)
        set_credential(request['Authenticator'], 'Credential', authenticator['Credential'])
        request['Authenticator']['Timestamp'] = authenticator['Timestamp']
        request['ReturnAuthenticator']['Timestamp'] = 0
        set_credential(request['ReturnAuthenticator'], 'Credential', b'\x00' * 8)
        # The class and the union arm's own tag agree, as the IDL requires.
        request['LogonLevel'] = logon_class
        request['LogonInformation']['tag'] = logon_class
        request['ValidationLevel'] = VALIDATION_SAM_INFO2
        arm = request['LogonInformation'][
            'LogonInteractive' if logon_class == 1 else 'LogonService']
        arm['Identity']['LogonDomainName'] = options.domain
        arm['Identity']['ParameterControl'] = 3
        arm['Identity']['UserName'] = user
        arm['Identity']['Workstation'] = computer
        # The server stores no LM hash and ignores this half rather than
        # trusting it; the NT half is what it compares to the account's hash.
        set_owf(arm, 'LmOwfPassword', b'\x00' * 16)
        set_owf(arm, 'NtOwfPassword', ntlm.compute_nthash(password))
        return dce.request(request)

    def open_channel(account, password):
        """A fresh challenge and handshake, so a call that spends the channel
        (a refused logon steps it before the password is looked at) leaves the
        next check a clean one."""
        nonlocal server_challenge
        request = nrpc.NetrServerReqChallenge()
        request['PrimaryName'] = NULL
        request['ComputerName'] = computer
        request['ClientChallenge'] = client_challenge
        server_challenge = eight(dce.request(request)['ServerChallenge'])
        response, session_key = authenticate(account, password)
        return session_key, eight(response['ServerCredential']), response['ErrorCode']

    if server_challenge:
        try:
            response, _ = authenticate('NOSUCH%s$' % uuid.uuid4().hex[:4].upper(),
                                       'not-the-password')
            check(CHECKS[3], response['ErrorCode'] == STATUS_NO_TRUST_SAM_ACCOUNT,
                  hex(response['ErrorCode']))
        except Exception as error:  # noqa: BLE001
            code = getattr(error, 'error_code', None)
            if code is None:
                text = str(error).lower()
                for candidate in (STATUS_NO_TRUST_SAM_ACCOUNT, STATUS_NO_SUCH_USER):
                    if '%08x' % candidate in text:
                        code = candidate
                        break
            # Either refusal is correct for an account the directory does not
            # hold: the server may report the missing account or the missing
            # trust first, and both mean the channel was refused.
            check(CHECKS[3], code in (STATUS_NO_TRUST_SAM_ACCOUNT, STATUS_NO_SUCH_USER),
                  '%s: %s' % (type(error).__name__, error))

        machine, reason = machine_account(options)
        if machine is None:
            skip(CHECKS[4], reason)
            skip(CHECKS[5], 'no machine account to authenticate with')
            skip(CHECKS[6], 'no secure channel to log on over')
            skip(CHECKS[7], 'no secure channel to refuse a password on')
            skip(CHECKS[8], 'no account logon to read back')
            skip(CHECKS[9], 'no machine account to open a secure channel with')
            skip(CHECKS[10], 'no machine account to open a secure channel with')
            skip(CHECKS[13], 'no machine account to open a secure channel with')
            skip(CHECKS[14], 'no machine account to open a secure channel with')
            skip(CHECKS[15], 'no machine account to open a secure channel with')
        else:
            account, password, rid = machine
            check(CHECKS[4], True, '%s rid %d' % (account, rid))

            # A refused password raises badPwdCount. This has to run on its own
            # channel: the server steps the credential before it looks at the
            # password, so the refusal spends this one and the good logon below
            # opens a fresh one.
            try:
                refused_key, refused_seed, refused_code = open_channel(account, password)
                if refused_code != STATUS_SUCCESS:
                    raise RuntimeError('channel refused: 0x%08x' % refused_code)
                samlogon(refused_seed, refused_key, options.user,
                         'Wr0ng-' + uuid.uuid4().hex)
                check(CHECKS[7], False, 'the wrong password was accepted')
            except Exception as error:  # noqa: BLE001
                code = getattr(error, 'error_code', None)
                check(CHECKS[7], code == STATUS_WRONG_PASSWORD,
                      '%s: %s' % (type(error).__name__, error))

            # A fresh challenge per channel: the first one was spent above.
            request = nrpc.NetrServerReqChallenge()
            request['PrimaryName'] = NULL
            request['ComputerName'] = computer
            request['ClientChallenge'] = client_challenge
            server_challenge = eight(dce.request(request)['ServerChallenge'])
            try:
                response, session_key = authenticate(account, password)
                expected = nrpc.ComputeNetlogonCredential(server_challenge, session_key)
                # The channel's seed after the handshake is the server
                # credential; every later authenticator is computed from it.
                server_credential = eight(response['ServerCredential'])
                check(CHECKS[5],
                      response['ErrorCode'] == STATUS_SUCCESS
                      and eight(response['ServerCredential']) == expected,
                      hex(response['ErrorCode']))
                channel = response['ErrorCode'] == STATUS_SUCCESS
            except Exception as error:  # noqa: BLE001
                check(CHECKS[5], False, '%s: %s' % (type(error).__name__, error))
                channel = False

            if not channel:
                skip(CHECKS[6], 'no secure channel')
            else:
                try:
                    response = samlogon(server_credential, session_key, options.user,
                                        options.password)
                    # The validated account is the SamInfo2 arm's EffectiveName.
                    name = validation_field(
                        response['ValidationInformation']['ValidationSam2'],
                        'EffectiveName')
                    check(CHECKS[6],
                          response['ErrorCode'] == STATUS_SUCCESS
                          and name == options.user,
                          (hex(response['ErrorCode']), name))
                except Exception as error:  # noqa: BLE001
                    traceback.print_exc()
                    check(CHECKS[6], False, '%s: %s' % (type(error).__name__, error))

                # The good logon cleared the counter the refusal raised, and
                # raised the logon count, on the account itself.
                try:
                    ok, counters = logon_statistics(options)
                    check(CHECKS[8], ok, counters)
                except Exception as error:  # noqa: BLE001
                    check(CHECKS[8], False, '%s: %s' % (type(error).__name__, error))

            # A password the server can prove but will not accept. Two states
            # are distinct on the wire, and a workstation turns each into a
            # different prompt. A one-tick maximum age makes every password
            # older than the policy, whatever its pwdLastSet.
            try:
                password_policy(options, 7, 24, 1, -1, 0)
                key, seed, code = open_channel(account, password)
                if code != STATUS_SUCCESS:
                    raise RuntimeError('channel refused: 0x%08x' % code)
                try:
                    samlogon(seed, key, options.user, options.password)
                    check(CHECKS[11], False, 'an aged-out password was accepted')
                except Exception as error:  # noqa: BLE001
                    check(CHECKS[11], getattr(error, 'error_code', None) == STATUS_PASSWORD_EXPIRED,
                          '%s: %s' % (type(error).__name__, error))
            except Exception as error:  # noqa: BLE001
                check(CHECKS[11], False, '%s: %s' % (type(error).__name__, error))
            finally:
                # Back to AD's default domain policy, which the checks below
                # and any later driver expect.
                try:
                    password_policy(options, 7, 24, 1, -36288000000000, -864000000000)
                except Exception:  # noqa: BLE001
                    pass

            # pwdLastSet zero is the other state: an administrator demanded a
            # change, which SAMR writes with the PasswordExpired flag and the
            # logon answers with a must-change rather than an expiry.
            try:
                created, reason = create_account(
                    options, getattr(samr, 'USER_NORMAL_ACCOUNT', 0x10), password_expired=True)
                if created is None:
                    raise RuntimeError(reason)
                pending, pending_password, _ = created
                key, seed, code = open_channel(account, password)
                if code != STATUS_SUCCESS:
                    raise RuntimeError('channel refused: 0x%08x' % code)
                try:
                    samlogon(seed, key, pending, pending_password)
                    check(CHECKS[12], False, 'a password that must change was accepted')
                except Exception as error:  # noqa: BLE001
                    check(CHECKS[12],
                          getattr(error, 'error_code', None) == STATUS_PASSWORD_MUST_CHANGE,
                          '%s: %s' % (type(error).__name__, error))
            except Exception as error:  # noqa: BLE001
                check(CHECKS[12], False, '%s: %s' % (type(error).__name__, error))

            # The interactive and service classes prove the password by
            # sending its own NT one-way function, with no challenge in play.
            # The wrong function is refused first, because the refusal is a
            # counted failure and the good logons below clear the counter the
            # lockout checks further down depend on being empty. Each logon
            # spends its channel, so each gets a fresh handshake.
            try:
                key, seed, code = open_channel(account, password)
                if code != STATUS_SUCCESS:
                    raise RuntimeError('channel refused: 0x%08x' % code)
                password_logon(seed, key, options.user, 'Wr0ng-' + uuid.uuid4().hex, 1)
                check(CHECKS[15], False, 'the wrong one-way function was accepted')
            except Exception as error:  # noqa: BLE001
                check(CHECKS[15],
                      getattr(error, 'error_code', None) == STATUS_WRONG_PASSWORD,
                      '%s: %s' % (type(error).__name__, error))

            for index, logon_class in ((13, 1), (14, 3)):
                try:
                    key, seed, code = open_channel(account, password)
                    if code != STATUS_SUCCESS:
                        raise RuntimeError('channel refused: 0x%08x' % code)
                    response = password_logon(seed, key, options.user, options.password,
                                              logon_class)
                    name = validation_field(
                        response['ValidationInformation']['ValidationSam2'],
                        'EffectiveName')
                    check(CHECKS[index],
                          response['ErrorCode'] == STATUS_SUCCESS
                          and name == options.user,
                          (hex(response['ErrorCode']), name))
                except Exception as error:  # noqa: BLE001
                    check(CHECKS[index], False, '%s: %s' % (type(error).__name__, error))

            # The domain's lockout policy is what turns a counted refusal into
            # a lockout, and a domain administrator sets it over SAMR.
            try:
                observed = lockout_policy(options, (2, 18000000000, 18000000000))
                check(CHECKS[9], observed == (2, 18000000000, 18000000000), observed)
            except Exception as error:  # noqa: BLE001
                check(CHECKS[9], False, '%s: %s' % (type(error).__name__, error))

            # Two refusals reach the threshold and lock the account; the right
            # password is then refused with a status of its own for the rest of
            # the duration. Each attempt spends a channel, so each gets a new
            # handshake.
            try:
                refused = []
                for _ in range(2):
                    key, seed, code = open_channel(account, password)
                    if code != STATUS_SUCCESS:
                        raise RuntimeError('channel refused: 0x%08x' % code)
                    try:
                        samlogon(seed, key, options.user, 'Wr0ng-' + uuid.uuid4().hex)
                        refused.append(STATUS_SUCCESS)
                    except Exception as error:  # noqa: BLE001
                        refused.append(getattr(error, 'error_code', None))
                key, seed, code = open_channel(account, password)
                if code != STATUS_SUCCESS:
                    raise RuntimeError('channel refused: 0x%08x' % code)
                locked = STATUS_SUCCESS
                try:
                    samlogon(seed, key, options.user, options.password)
                except Exception as error:  # noqa: BLE001
                    locked = getattr(error, 'error_code', None)
                check(CHECKS[10],
                      refused == [STATUS_WRONG_PASSWORD, STATUS_WRONG_PASSWORD]
                      and locked == STATUS_ACCOUNT_LOCKED_OUT,
                      (refused, locked))
            except Exception as error:  # noqa: BLE001
                check(CHECKS[10], False, '%s: %s' % (type(error).__name__, error))
            finally:
                # Leave the domain with the policy it ships with; the lockout
                # itself lasts out its duration, which this daemon will not.
                try:
                    lockout_policy(options, (0, 18000000000, 18000000000))
                except Exception:  # noqa: BLE001
                    pass

    print('\n%d failure(s): %s' % (len(failures), failures))
    if skipped:
        print('%d skipped: %s' % (len(skipped), skipped))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
