#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: 2026 Monarchy contributors
"""Ask a Monarchy DC the question a Windows client asks before it joins.

When a client follows a DC's SRV record it verifies the machine at the end of it
with a "ping" — an LDAP search over UDP (CLDAP, RFC 1798) that only a DC hosting
that domain answers. A Windows client that gets no answer reports
ERROR_NO_SUCH_DOMAIN, which is indistinguishable from the domain not existing,
so the join never starts.

Two shapes of that ping are in use, and both are real:

  nt4       filter (&(NtVer=\\06\\00\\00\\00)), attribute NetLogon. Samba's
            ``net ads lookup`` sends exactly this; the bytes it put on the wire
            are pinned below as a self-check, so this script fails if its own
            encoder drifts from a real client.
  windows   filter (&(DnsDomain=<domain>)(NtVer=...)) asking for the locator's
            attributes by name, which is what DsGetDcName's ping looks like.

Nothing here trusts the engine's own encoder: the request is built independently
and the answer is parsed as BER from the bytes that came back.

    scripts/cldap-conformance.py --host <dc> [--port 389] [--domain <dns domain>]

Exit status is 0 only when every check passed.
"""

import argparse
import socket
import struct
import sys

# The datagram Samba 4.24's `net ads lookup` sent to a Monarchy DC, from a
# capture on the wire: message id 0x0000fb3d, baseObject "", scope base,
# filter (&(NtVer=0x00000006)), attributes ["NetLogon"].
SAMBA_PING = bytes.fromhex(
    "3035020300fb3d632e0400"
    "0a01000a0100020100020100010100"
    "a00fa30d04054e74566572040406000000"
    "300a04084e65744c6f676f6e"
)


def ber(tag, payload):
    n = len(payload)
    if n < 0x80:
        return bytes([tag, n]) + payload
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([tag, 0x80 | len(out)]) + out + payload


def integer(value):
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return ber(0x02, body)


def octets(value):
    return ber(0x04, value if isinstance(value, bytes) else value.encode())


def equality(attribute, value):
    return ber(0xA3, octets(attribute) + octets(value))


def and_filter(*parts):
    return ber(0xA0, b"".join(parts))


def message(msg_id, op, body):
    return ber(0x30, integer(msg_id) + ber(op, body))


def search(msg_id, base, scope, filter_der, attributes):
    attrs = ber(0x30, b"".join(octets(a) for a in attributes))
    body = (
        octets(base)
        + ber(0x0A, bytes([scope]))
        + ber(0x0A, b"\x00")          # derefAliases: never
        + integer(0)                  # sizeLimit
        + integer(0)                  # timeLimit
        + ber(0x01, b"\x00")          # typesOnly: false
        + filter_der
        + attrs
    )
    return message(msg_id, 0x63, body)


class Reader:
    def __init__(self, data):
        self.data = data
        self.at = 0

    def eof(self):
        return self.at >= len(self.data)

    def element(self):
        tag = self.data[self.at]
        self.at += 1
        length = self.data[self.at]
        self.at += 1
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(self.data[self.at:self.at + count], "big")
            self.at += count
        value = self.data[self.at:self.at + length]
        self.at += length
        return tag, value


def decode_message(data):
    """Return (message id, [(op, inner bytes), ...]) or raise ValueError."""
    reader = Reader(data)
    tag, body = reader.element()
    if tag != 0x30:
        raise ValueError("not a SEQUENCE")
    reader = Reader(body)
    tag, msg_id = reader.element()
    if tag != 0x02:
        raise ValueError("no message id")
    ops = []
    while not reader.eof():
        op, inner = reader.element()
        ops.append((op, inner))
    return int.from_bytes(msg_id, "big"), ops


def decode_result(inner):
    reader = Reader(inner)
    results = []
    while not reader.eof():
        tag, value = reader.element()
        results.append(int.from_bytes(value, "big") if tag == 0x0A else value)
    return results[0] if results else None


def decode_entry(inner):
    """SearchResultEntry -> (object name, {attribute: [values]})."""
    reader = Reader(inner)
    tag, name = reader.element()
    if tag != 0x04:
        raise ValueError("entry without object name")
    tag, attrs = reader.element()
    if tag != 0x30:
        raise ValueError("entry without attribute sequence")
    reader = Reader(attrs)
    out = {}
    while not reader.eof():
        tag, partial = reader.element()
        if tag != 0x30:
            continue
        partial_reader = Reader(partial)
        _, attr_type = partial_reader.element()
        _, values = partial_reader.element()
        value_reader = Reader(values)
        collected = []
        while not value_reader.eof():
            _, value = value_reader.element()
            collected.append(value)
        out[attr_type.decode("latin-1")] = collected
    return name, out


def ask(host, port, payload, timeout=2.0):
    """Send one datagram and return (source port, reply bytes) or (None, None)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, peer = sock.recvfrom(65535)
        return peer[1], data
    except socket.timeout:
        return None, None
    finally:
        sock.close()


class Run:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            print("  PASS %s" % name)
        else:
            self.failed += 1
            print("  FAIL %s%s" % (name, ("  — " + detail) if detail else ""))
        return ok

    def skip(self, name, why):
        print("  skip %s  — %s" % (name, why))


def main():
    parser = argparse.ArgumentParser(description="CLDAP locator ping conformance")
    parser.add_argument("--host", required=True, help="DC address to ask")
    parser.add_argument("--port", type=int, default=389, help="CLDAP port (default 389)")
    parser.add_argument("--domain", default="", help="DNS domain the DC hosts")
    parser.add_argument("--list", action="store_true", help="print each check as it runs")
    args = parser.parse_args()

    global verbose
    verbose = args.list
    run = Run()
    host, port = args.host, args.port

    if not args.domain:
        print("--domain is required: the locator's ping asserts the domain", file=sys.stderr)
        return 2

    # Self-check: the encoder below has to reproduce the datagram a real client
    # sent, or the vector is not the client's question.
    samba_vector = search(
        0x0000FB3D, "", 0, and_filter(equality("NtVer", b"\x06\x00\x00\x00")), ["NetLogon"]
    )
    run.check(
        "the nt4 vector is the datagram Samba put on the wire",
        samba_vector == SAMBA_PING,
        "encoder drifted from the captured ping",
    )

    print("CLDAP against %s:%d, domain %s" % (host, port, args.domain))

    # 1. The nt4-shaped ping names no domain and asks for NetLogon.
    source, reply = ask(host, port, samba_vector)
    answered = reply is not None
    run.check(
        "a locator ping that names no domain is answered",
        answered,
        "no datagram came back; a client sees ERROR_NO_SUCH_DOMAIN",
    )

    attrs = {}
    msg_id = None
    code = None
    if answered:
        run.check("the reply comes from the port asked", source == port, "from %s" % source)
        try:
            msg_id, ops = decode_message(reply)
            entry_ops = [inner for op, inner in ops if op == 0x64]
            done_ops = [inner for op, inner in ops if op == 0x65]
            if entry_ops:
                _, attrs = decode_entry(entry_ops[0])
            if done_ops:
                code = decode_result(done_ops[0])
            parsed = bool(entry_ops) and code == 0
        except Exception as error:  # noqa: BLE001 - a malformed reply is a failure
            parsed = False
            run.check("the reply parses as an LDAPMessage", False, str(error))
        else:
            run.check("the reply parses as an LDAPMessage", True)
        if parsed:
            run.check("the reply echoes the message id", msg_id == 0x0000FB3D, str(msg_id))

            # The outer SEQUENCE has to account for the datagram exactly. A
            # decoder that skips its own declared length will happily read a
            # truncated answer or one with bytes appended, and two clients can
            # then disagree about how long the same answer is while each walks it
            # consistently — which is a wire bug reported as a counting quirk.
            declared = None
            if reply and reply[0] == 0x30:
                form = reply[1]
                if form & 0x80:
                    width = form & 0x7F
                    declared = 2 + width + int.from_bytes(reply[2:2 + width], "big")
                else:
                    declared = 2 + form
            run.check(
                "the outer SEQUENCE length accounts for the whole datagram",
                declared == len(reply),
                "datagram %d bytes, header declares %r" % (len(reply), declared),
            )
            for name in (
                "DnsDomain",
                "DnsForestName",
                "DcSiteName",
                "NetbiosDomainName",
                "NetbiosComputerName",
                "DnsHostName",
                "NtVer",
                "LdapService",
            ):
                run.check("the answer names %s" % name, name in attrs, "missing")
            run.check(
                "DnsDomain is the domain this DC hosts",
                (attrs.get("DnsDomain") or [b""])[0].decode().lower() == args.domain.lower(),
                (attrs.get("DnsDomain") or [b""])[0].decode(),
            )

            # NtVer in an answer is the DC's own capability mask, not the
            # question repeated. Ask with a mask the DC does not advertise: a
            # reply that changes with the question tells a client it supports
            # whatever it happened to ask for, which is worse than saying
            # nothing because it is a claim about fields the client will parse.
            # Same message id as the vector, so the echo cannot account for a
            # difference: whatever the mask asked, the answer has to be the same
            # bytes. Comparing lengths alone would pass on a different id, which
            # echoes one byte wider, and would miss a field that changed size.
            other = search(
                0x0000FB3D,
                "",
                0,
                and_filter(equality("NtVer", b"\x1f\x00\x00\x00")),
                ["Netlogon"],
            )
            _, other_reply = ask(host, port, other)
            other_ntver = None
            if other_reply:
                try:
                    _, other_ops = decode_message(other_reply)
                    for op, inner in other_ops:
                        if op == 0x64:
                            _, other_attrs = decode_entry(inner)
                            other_ntver = (other_attrs.get("NtVer") or [None])[0]
                except Exception:  # noqa: BLE001 - a malformed reply fails the check below
                    other_ntver = None
            run.check(
                "the answer is the same bytes whatever mask was asked",
                other_reply is not None and other_reply == reply,
                "asked \\x1f: %r bytes, asked \\x06: %d bytes"
                % (len(other_reply) if other_reply else None, len(reply)),
            )
            run.check(
                "the answer advertises the server's NtVer, not the value asked",
                other_reply is not None and other_ntver == (attrs.get("NtVer") or [None])[0],
                "asked \\x1f\\x00\\x00\\x00, answered %r" % other_ntver,
            )
            if verbose:
                for name in sorted(attrs):
                    print("    %s = %r" % (name, attrs[name]))

    # 2. The DsGetDcName-shaped ping asks for the domain by name.
    windows_ping = search(
        0x1234,
        "",
        0,
        and_filter(
            equality("DnsDomain", args.domain),
            equality("NtVer", b"\x06\x00\x00\x00"),
        ),
        ["Netlogon", "DnsDomain", "DnsForestName", "DcSiteName", "HostName", "LdapService"],
    )
    source, reply = ask(host, port, windows_ping)
    run.check(
        "a ping naming this domain is answered",
        reply is not None,
        "no datagram came back",
    )
    if reply is not None:
        try:
            _, ops = decode_message(reply)
            entry_ops = [inner for op, inner in ops if op == 0x64]
            done_ops = [inner for op, inner in ops if op == 0x65]
            result = decode_result(done_ops[0]) if done_ops else None
            named = decode_entry(entry_ops[0])[1] if entry_ops else {}
        except Exception as error:  # noqa: BLE001
            run.check("the named-domain reply parses", False, str(error))
        else:
            run.check("the named-domain reply parses", True)
            run.check("the named-domain reply is success", result == 0, str(result))
            run.check("the named-domain reply carries the domain", "DnsDomain" in named)

    # 3. A ping for a domain this DC does not host must be refused, not answered
    #    as though it did: the client would then trust a server that cannot
    #    authenticate its machines.
    foreign = search(
        0x0042,
        "",
        0,
        and_filter(equality("DnsDomain", "not-" + args.domain)),
        ["Netlogon"],
    )
    _, reply = ask(host, port, foreign)
    if reply is None:
        run.check("a ping for another domain is answered noSuchObject", False, "no reply")
    else:
        try:
            _, ops = decode_message(reply)
            done = [inner for op, inner in ops if op == 0x65]
            result = decode_result(done[0]) if done else None
        except Exception as error:  # noqa: BLE001
            run.check("a ping for another domain is answered noSuchObject", False, str(error))
        else:
            run.check(
                "a ping for another domain is answered noSuchObject",
                result == 32,
                "resultCode %s" % result,
            )

    # 4. Anything that is not a locator ping stays unanswered: RFC 4511 dropped
    #    LDAP over UDP, and answering a subtree search would claim it.
    subtree = search(0x0007, "dc=example,dc=org", 2, and_filter(equality("objectClass", "top")), ["*"])
    _, reply = ask(host, port, subtree, timeout=1.0)
    run.check(
        "a subtree search over UDP is not answered",
        reply is None,
        "the engine answered a search that is not a locator ping",
    )

    print("\n%d checks, %d failing" % (run.passed + run.failed, run.failed))
    return 0 if run.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
