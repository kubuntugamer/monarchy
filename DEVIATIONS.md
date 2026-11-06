# Monarchy — Accepted Deviations from Microsoft Active Directory

**Date:** 2026-11-04 · **Scope:** 0.1.0 (`engine/`, `backend/`, `ui/`)

This file is the auditable definition of where "1:1 with Microsoft AD" stops. It exists so that
"1:1" is a precise claim rather than a marketing one (see
[`AD-1TO1-CONFORMANCE.md`](AD-1TO1-CONFORMANCE.md) §5.3 and §7.2).

Two rules govern it:

1. **A gap is not a deviation.** Unfinished work is recorded as a gap in the conformance register
   (§2.5) and stays on the backlog. Only behaviour that Monarchy intends *not* to match is listed
   here, with the reason.
2. **No entry may be added to silence a failing test or an inconvenient observation.** If an
   observable difference is a defect, it is a defect here too.

Every entry names the gap it covers, the observable difference a client sees, and why it is
accepted instead of fixed.

---

## D1 — The directory publishes functional level 0 (Windows 2000 behaviour level)

**Gaps:** G1–G7, G9, G13–G16, G18, G21, G22, G27, G28, G31–G33, G35–G39
**Difference:** The root DSE reports `domainFunctionality`, `forestFunctionality` and
`domainControllerFunctionality` as `0`, and `supportedControl` lists only paged results. Microsoft
AD reports a level from 0 (2000) through 7 (2025) and exposes the corresponding behaviour.
**Monarchy:** `engine/LdapServer.cpp:704-718`. The engine implements the FL-0 core — directory,
Kerberos, SAMR, LSAD, Netlogon, DRSR export, the endpoint mapper, SMB 1/2 and DNS — and none of the
features a later level gates: claims and Dynamic Access Control, authentication policies and silos,
PKINIT, DNSSEC, ADWS, GPO client-side extensions, tombstone garbage collection, or
functional-level-gated schema.
**Why accepted:** Claiming a higher level would make Windows clients and tools expect behaviour the
engine does not have, turning a clear "unsupported" into a confusing failure. Level 0 is the honest
encoding of what is implemented. Raising it is a per-feature decision, not a configuration change.
**Consequence for a client:** FL-aware tooling sees a Windows 2000-era DC. Some modern management
tooling refuses to target it, and anything gated on 2003+ behaviour (for example `lastLogonTimestamp`
semantics, `msDS-Behavior-Version`-driven replication features) is unavailable.

## D2 — No SMB Direct / RDMA transport

**Gap:** G29
**Difference:** Microsoft AD file servers can serve SYSVOL and NETLOGON over SMB Direct (RDMA)
when the NIC and OS support it.
**Monarchy:** `engine/Smb2.cpp` implements SMB 2.0.2/2.1 over TCP. There is no RDMA transport and
no plan to add one.
**Why accepted:** RDMA requires kernel-mode NIC drivers and hardware this project cannot test or
ship; it changes no on-the-wire protocol semantics a client depends on, only the transport. A client
that cannot use RDMA falls back to TCP SMB, which is what Monarchy serves.
**Consequence:** SMB over TCP only; no RDMA offload.

## D3 — No WMI/WBEM management surface

**Gap:** G39
**Difference:** Microsoft AD publishes management instrumentation through WMI providers
(`root\MicrosoftActiveDirectory`, `root\cimv2`), which is how much Windows administration and
monitoring tooling inspects a DC.
**Monarchy:** No WMI provider and no WBEM server. Management is through LDAP, the RPC interfaces the
engine implements (`samr`, `lsarpc`, `netlogon`, `drsuapi`, `epmapper`), and the HTTP console.
**Why accepted:** A WBEM stack is a separate server role with its own protocol suite (DSP0200 and
the CIM model), not a directory feature; its absence does not change directory, authentication or
replication behaviour. Windows tooling that requires WMI reports the provider as missing, which is
an accurate result.
**Consequence:** No WMI-based health, inventory or `dcdiag`-style inspection; `scripts/check-dc-health.sh`
covers the local equivalent.

## D4 — Separate server roles are not implemented

**Gaps:** G35 (AD LDS), G36 (AD CS), G37 (AD FS), G38 (AD RMS)
**Difference:** Microsoft ships these as separately installable roles that can share a domain but
are not part of the domain controller service.
**Monarchy:** None of them exists. The DC role is the scope of this project.
**Why accepted:** Each is an independent product with its own protocol surface (LDAP-based instance
management, CEP/CES and SCEP, SAML/OAuth federation, RMS licensing). Calling their absence a
deviation keeps the DC claim honest: Monarchy is a domain controller, not the whole Windows Server
directory stack.
**Consequence:** Certificate enrolment, federation and rights management are unavailable; they must
come from another product.

## D5 — The KDC is Monarchy's own, not the MIT kdb plugin path

**Gap:** G17
**Difference:** Samba's AD DC runs MIT Kerberos with an AD-aware kdb backend; the conformance
register scores that integration.
**Monarchy:** `engine/Kdc.cpp` is its own KDC speaking MS-KILE over the wire.
**Why accepted:** This is not a behavioural deviation at all — it is a different implementation of
the same wire protocol. It is listed so the register's Samba-scoped rows are not read as describing
this tree.
**Consequence:** None on the wire; the KDC is not replaceable by MIT's.

## D6 — Verification oracle: the Microsoft Protocol Test Suites have not been run

**Gap:** none (a proof gap, not a behaviour difference)
**Difference:** The conformance register's L3 acceptance criterion is Microsoft's own Windows
Protocol Test Suites (`ADFamily`, `Kerberos`, `MS-XCA`) plus bidirectional DRS against a real
Windows DC.
**Monarchy:** Everything proven so far is L1 wire interop against independent clients — impacket,
Samba's NDR clients and `smbclient`, MIT krb5, `dig`/`nsupdate`, OpenSSL — and the 20-suite `ctest`
run on 2026-11-05.
**Why listed:** Without this entry, a reader could mistake an unrun suite for a passing one. It is
recorded as a limitation, not accepted as sufficient.
**What closes it:** A Windows host for the WPT harness and a real DC for bidirectional replication.
Neither is reachable from the current development machine.

## D7 — Outbound replication is unauthenticated

**Gap:** G11 (`AD-1TO1-CONFORMANCE.md` §2.5, DRS replication)
**Difference:** A DC pulls a cycle from a partner over an authenticated DCE/RPC bind — NTLMSSP at
`PKT_PRIVACY`, or Kerberos — and a partner refuses `DsGetNCChanges` that carries no verifier.
**Monarchy:** The outbound client (`engine/DrsClient.{h,cpp}`) binds the peer's DRSUAPI endpoint
over `ncacn_ip_tcp`, runs `DsBind`/`DsGetNCChanges` and applies the decoded chain, but sends no
security verifier; a reply that comes back signed is refused rather than read without checking.
An endpoint with an authenticator configured — including this tree's own `DcService` — answers the
first call with an NCA fault (`access denied`).
**Why listed:** The transport, framing, chunking and object decoding are real and tested against
this tree's DC; the authentication leg is missing, so the client cannot yet pull from a peer that
enforces it.
**What closes it:** An initiator-side NTLMSSP (or GSS-API Kerberos) bind in `DrsClient`, with the
per-PDU signing and sealing the server already implements as the acceptor.

---

## Adding an entry

An entry is admissible only if it names the gap ID, the difference a client can observe, the code
that decides the behaviour, and the reason the difference is intended. Anything else is a backlog
item in `AD-1TO1-CONFORMANCE.md` §2.5 or a defect.
