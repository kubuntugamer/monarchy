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


def decode_messages(data):
    """Every LDAPMessage in a datagram: [(message id, [(op, inner bytes)])].

    A CLDAP answer is *several* LDAPMessages concatenated in one datagram — the
    search result entry, then the result — each its own SEQUENCE with its own
    copy of the message id. The concatenation is the framing, so a decoder that
    expects one SEQUENCE around the whole datagram accepts a shape no client
    sends: it reads the id, then the entry and the result as two operations of
    the same message, and reports a well-formed answer for a datagram Samba's
    own decoder rejects outright.
    """
    messages = []
    reader = Reader(data)
    while not reader.eof():
        tag, body = reader.element()
        if tag != 0x30:
            raise ValueError("message %d is not a SEQUENCE" % len(messages))
        body_reader = Reader(body)
        id_tag, msg_id = body_reader.element()
        if id_tag != 0x02:
            raise ValueError("message %d has no message id" % len(messages))
        ops = []
        while not body_reader.eof():
            op, inner = body_reader.element()
            ops.append((op, inner))
        messages.append((int.from_bytes(msg_id, "big"), ops))
    if not messages:
        raise ValueError("empty datagram")
    return messages


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


def search_result(data):
    """(message id, entry attributes or None, result code or None) for an answer."""
    messages = decode_messages(data)
    ids = sorted({msg_id for msg_id, _ in messages})
    if len(ids) != 1:
        raise ValueError("one answer carries message ids %r" % (ids,))
    entry = None
    result = None
    for _, ops in messages:
        for op, inner in ops:
            if op == 0x64:
                entry = decode_entry(inner)[1]
            elif op == 0x65:
                result = decode_result(inner)
    return ids[0], entry, result


def decode_netlogon_ex(blob):
    """Parse NETLOGON_SAM_LOGON_RESPONSE_EX as a client parses it.

    Samba's librpc/idl/nbt.idl definition pushed with NDR_NOALIGN: no padding
    anywhere, one length-prefixed DNS label per string component ending in a
    NUL, and the last eight bytes carrying the capability word plus the two
    legacy tokens a client checks before it believes anything above them. The
    optional IP and closest-site fields are present only when the capability
    word says so, which is why the same blob has to be readable whatever mask
    was asked.
    """
    if len(blob) < 8:
        raise ValueError("blob of %d bytes cannot hold the trailing tokens" % len(blob))
    nt_version = int.from_bytes(blob[-8:-4], "little")
    lmnt_token = int.from_bytes(blob[-4:-2], "little")
    lm20_token = int.from_bytes(blob[-2:], "little")

    at = 0

    def take(count):
        nonlocal at
        if at + count > len(blob):
            raise ValueError("blob ends inside a field at %d" % at)
        value = blob[at:at + count]
        at += count
        return value

    def u16():
        return int.from_bytes(take(2), "little")

    def u32():
        return int.from_bytes(take(4), "little")

    def string():
        nonlocal at
        labels = []
        # A length byte is a label length; 0xC0 marks a pointer to a string
        # already written, which Samba's encoder emits for repeated names.
        while True:
            length = take(1)[0]
            if length == 0:
                return ".".join(labels)
            if length & 0xC0:
                offset = ((length & 0x3F) << 8) | take(1)[0]
                if offset >= len(blob):
                    raise ValueError("pointer to %d is outside the blob" % offset)
                saved, at = at, offset
                labels.append(string())
                at = saved
                return ".".join(label for label in labels if label)
            labels.append(take(length).decode("latin-1"))

    out = {
        "command": u16(),
        "sbz": u16(),
        "server_type": u32(),
        "domain_guid": take(16),
        "forest": string(),
        "dns_domain": string(),
        "pdc_dns_name": string(),
        "domain_name": string(),
        "pdc_name": string(),
        "user_name": string(),
        "server_site": string(),
        "client_site": string(),
    }
    if nt_version & 0x00000008:  # NETLOGON_NT_VERSION_5EX_WITH_IP
        out["sockaddr"] = take(take(1)[0])
    if nt_version & 0x00000010:  # NETLOGON_NT_VERSION_WITH_CLOSEST_SITE
        out["next_closest_site"] = string()
    out["nt_version"] = u32()
    out["lmnt_token"] = u16()
    out["lm20_token"] = u16()
    if at != len(blob):
        raise ValueError("%d unread bytes after the structure" % (len(blob) - at))
    if out["nt_version"] != nt_version:
        raise ValueError(
            "declared nt_version %#x, trailing word %#x" % (out["nt_version"], nt_version)
        )
    out["trailing_nt_version"] = nt_version
    out["trailing_tokens"] = (lmnt_token, lm20_token)
    return out


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
            messages = decode_messages(reply)
            msg_id, attrs, code = search_result(reply)
            parsed = attrs is not None and code == 0
        except Exception as error:  # noqa: BLE001 - a malformed reply is a failure
            messages = []
            parsed = False
            run.check("the reply parses as LDAPMessages", False, str(error))
        else:
            run.check("the reply parses as LDAPMessages", True)
        if parsed:
            run.check("the reply echoes the message id", msg_id == 0x0000FB3D, str(msg_id))

            # The framing, which is the whole point of this section: an answer is
            # the entry message and the result message back to back, each its own
            # SEQUENCE carrying the same id. Wrapping both in one SEQUENCE is not
            # an LDAPMessage — a client reads the id and then finds no result —
            # and it looks well-formed only to a decoder that assumes the same
            # mistake. Rebuilding the datagram from what was decoded is what
            # separates "two messages" from "one message with two operations".
            run.check(
                "the answer is an entry message followed by a result message",
                [sorted(op for op, _ in ops) for _, ops in messages] == [[0x64], [0x65]],
                "operations %r" % ([sorted(op for op, _ in ops) for _, ops in messages],),
            )
            rebuilt = b"".join(
                ber(0x30, integer(found_id) + b"".join(ber(op, inner) for op, inner in ops))
                for found_id, ops in messages
            )
            run.check(
                "the datagram is exactly its messages and nothing else",
                rebuilt == reply,
                "%d bytes rebuilt, %d on the wire" % (len(rebuilt), len(reply)),
            )

            # The attribute list is honoured, and this one is strict for a
            # reason: Samba's locator client refuses any answer whose entry is
            # not exactly one attribute called netlogon (`num_attributes != 1`
            # in libads/netlogon_ping.c), so the blob below is only reachable if
            # the entry carries nothing else.
            run.check(
                "the entry carries exactly the one attribute the ping asked for",
                [name.lower() for name in attrs] == ["netlogon"],
                "attributes %r" % (sorted(attrs),),
            )

            blob = (attrs.get("Netlogon") or [b""])[0]
            try:
                ex = decode_netlogon_ex(blob)
            except Exception as error:  # noqa: BLE001 - an unparseable blob is a failure
                run.check("the Netlogon attribute is a NETLOGON_SAM_LOGON_RESPONSE_EX", False, str(error))
            else:
                run.check("the Netlogon attribute is a NETLOGON_SAM_LOGON_RESPONSE_EX", True)
                run.check(
                    "it is the EX response, not the user-unknown or 2000 form",
                    ex["command"] == 23,
                    "command %d" % ex["command"],
                )
                run.check(
                    "it ends in the two legacy tokens a client checks first",
                    ex["trailing_tokens"] == (0xFFFF, 0xFFFF),
                    repr(ex["trailing_tokens"]),
                )
                # The word is what selects the layout: 5EX picks the EX struct,
                # and without the WITH_IP bit a client reads no address. Both
                # halves have to agree with the bytes actually present, which is
                # why the parser above fails rather than guesses if they do not.
                run.check(
                    "it declares NT_VERSION_1|NT_VERSION_5EX and claims no address field",
                    ex["nt_version"] == 0x00000005,
                    hex(ex["nt_version"]),
                )
                run.check(
                    "it names the domain and forest this DC answers for",
                    ex["dns_domain"].lower() == args.domain.lower()
                    and ex["forest"].lower() == args.domain.lower(),
                    "%s / %s" % (ex["forest"], ex["dns_domain"]),
                )
                run.check(
                    "its DC name is the host inside that domain",
                    ex["pdc_dns_name"].lower().endswith("." + args.domain.lower())
                    and ex["pdc_dns_name"].count(".") == args.domain.count(".") + 1,
                    ex["pdc_dns_name"],
                )
                run.check(
                    "it carries a domain GUID",
                    len(ex["domain_guid"]) == 16 and any(ex["domain_guid"]),
                    ex["domain_guid"].hex(),
                )
                run.check(
                    "it names its site on both sides of the reply",
                    ex["server_site"] != "" and ex["client_site"] != "",
                    "%r / %r" % (ex["server_site"], ex["client_site"]),
                )
                # The flags are claims about services. Only the ones this server
                # runs: DS, LDAP, KDC, GC, writable, and the PDC query it answers.
                # No time service, because there is no NTP server here.
                run.check(
                    "it claims the directory services this DC serves",
                    ex["server_type"] & 0x0010  # DS
                    and ex["server_type"] & 0x0008  # LDAP
                    and ex["server_type"] & 0x0020  # KDC
                    and ex["server_type"] & 0x0004  # GC
                    and ex["server_type"] & 0x0100,  # writable
                    hex(ex["server_type"]),
                )
                run.check(
                    "it claims no time service",
                    not ex["server_type"] & 0x0040,
                    hex(ex["server_type"]),
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
            other_nt_version = None
            if other_reply:
                try:
                    _, other_attrs, _ = search_result(other_reply)
                    other_nt_version = decode_netlogon_ex(
                        (other_attrs.get("Netlogon") or [b""])[0]
                    )["nt_version"]
                except Exception:  # noqa: BLE001 - a malformed reply fails the check below
                    other_nt_version = None
            run.check(
                "the answer is the same bytes whatever mask was asked",
                other_reply is not None and other_reply == reply,
                "asked \\x1f: %r bytes, asked \\x06: %d bytes"
                % (len(other_reply) if other_reply else None, len(reply)),
            )
            run.check(
                "the blob's capability word does not follow the mask asked",
                other_nt_version is not None and other_nt_version == (ex["nt_version"] if parsed else None),
                "asked \\x1f\\x00\\x00\\x00, blob declares %r" % other_nt_version,
            )
            if verbose:
                for name in sorted(attrs):
                    print("    %s = %r" % (name, attrs[name]))

    # 2. The DsGetDcName-shaped ping asks for the domain by name, and names the
    #    attributes it wants. The entry has to carry those and nothing else.
    windows_attributes = [
        "Netlogon",
        "DnsDomain",
        "DnsForestName",
        "DcSiteName",
        "HostName",
        "LdapService",
        "NtVer",
    ]
    windows_ping = search(
        0x1234,
        "",
        0,
        and_filter(
            equality("DnsDomain", args.domain),
            equality("NtVer", b"\x06\x00\x00\x00"),
        ),
        windows_attributes,
    )
    source, reply = ask(host, port, windows_ping)
    run.check(
        "a ping naming this domain is answered",
        reply is not None,
        "no datagram came back",
    )
    if reply is not None:
        try:
            _, named, result = search_result(reply)
        except Exception as error:  # noqa: BLE001
            run.check("the named-domain reply parses", False, str(error))
        else:
            run.check("the named-domain reply parses", True)
            run.check("the named-domain reply is success", result == 0, str(result))
            for name in windows_attributes:
                run.check("the answer names %s when asked" % name, name in named, "missing")
            run.check(
                "the answer carries no attribute that was not asked for",
                {name.lower() for name in named} <= {name.lower() for name in windows_attributes},
                repr(sorted(named)),
            )
            run.check(
                "DnsDomain is the domain this DC hosts",
                (named.get("DnsDomain") or [b""])[0].decode().lower() == args.domain.lower(),
                (named.get("DnsDomain") or [b""])[0].decode(),
            )

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
            _, _, result = search_result(reply)
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
