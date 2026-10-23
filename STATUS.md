# Monarchy 0.1.0 — release status

This file is the release contract for 0.1.0. It lists what the build actually
does, how each capability is proven, and what is deliberately **not** claimed.
Anything not listed under "Implemented and verified" is absent, not partial.

Verified on this tree with: `cmake --build build` (clean, no warnings) and
`ctest --output-on-failure` in `build/` → **14/14 suites pass**.

---

## 1. Implemented and verified

| Capability | Implementation | Verification |
|---|---|---|
| Domain provisioning from Monarchy's own code (objects, SIDs, groups, default GPOs, SYSVOL, secrets, DNS zone) | `engine/Provisioner.cpp`, `monarchy-provision` | `monarchy-provision-tests` |
| LDAP server (RFC 4511 subset): bind, search, add, modify, delete, modifyDN, compare, rootDSE | `engine/LdapServer.cpp` | `monarchy-backend-tests`, `monarchy-ui-tests` |
| **StartTLS** (RFC 4511 §4.14.1): the listener accepts plaintext and upgrades the same socket in place, resetting the session to anonymous; the provisioner creates the DC certificate (`private/ldap.crt`, self-signed, CA:TRUE, SANs for the DC FQDN, NetBIOS name, the DC IP and `localhost`), and a domain provisioned without `openssl` refuses StartTLS with `unavailable(52)` instead of answering success without encrypting | `engine/LdapServer.cpp`, `engine/Provisioner.cpp`, `ui/src/mainwindow.cpp` | `monarchy-tls-tests`: TLS handshake against the provisioned certificate, bind and search inside it, plaintext-after-upgrade aborted, and openssl's own `s_client -starttls ldap` verifies the certificate; live, ldap3 verifies it against the same file as CA before binding |
| **LDAP request controls** with paged results (RFC 2696, OID 1.2.840.113556.1.4.319): pages, total count and resume cookie per connection, abandon with size 0, a cookie from another search refused with `unwillingToPerform`; an unknown control is ignored unless the client marks it critical, which is refused with `unavailableCriticalExtension(12)` | `engine/LdapServer.cpp` | `monarchy-ldap-tests` (5 cases); live, ldap3 walks a 22-object domain in 11 pages of 2 with no repeats over StartTLS |
| Group membership (`member` DNs, derived `memberOf`) | `engine/LdapServer.cpp`, `backend/AdminService.cpp` | `monarchy-backend-tests` |
| Password policy and credential storage (salted verifier, NT hash, AES keys), never returned by search | `engine/LdapServer.cpp`, `engine/Krb5.cpp` | `monarchy-backend-tests`, `monarchy-ntlm-tests` |
| NTLMv2 over LDAP SASL (NEGOTIATE/CHALLENGE/AUTHENTICATE) | `engine/Ntlm.cpp`, `engine/LdapServer.cpp` | `monarchy-ntlm-tests` (11 cases) |
| **NTLM message signing and sealing** (MS-NLMP §3.4) over LDAP, RFC 4422 framing | `engine/Ntlm.cpp`, `engine/LdapServer.cpp` | byte-exact vs impacket; signed, sealed and tamper-rejected sessions |
| Kerberos KDC: RC4-HMAC + AES-128/256, pre-auth, TGT/TGS, subkey-sealed replies, AP-REQ/AP-REP | `engine/Kdc.cpp`, `engine/Krb5.cpp`, `engine/Aes.cpp` | `monarchy-kerberos-tests` (18 cases), driven by MIT krb5 |
| PAC: LOGON_INFO, CLIENT_INFO, UPN_DNS_INFO, server+KDC signatures, `readIdentity()`, write authorization from the PAC | `engine/Pac.cpp` | `krb5_pac_verify` / `krb5_pac_get_buffer` (MIT), plus ACL behaviour tests |
| GSSAPI SASL layers (RFC 4752/4121/1964) with wrapped LDAP sessions, RC4 and AES | `engine/LdapServer.cpp` | MIT seals/opens the tokens independently |
| **Cross-realm trust** (direct): referral TGT `krbtgt/PEER@OURS`, inter-realm keys, inbound `krbtgt/OURS@PEER`, PAC re-signed at the boundary | `engine/Kdc.cpp`, `engine/Krb5.cpp` | MIT `kinit` into ALPHA, service ticket from BETA, AP-REQ accepted by BETA's directory |
| DNS server: DC locator records, SRV/A/ANY, RFC 2136 updates, persistence | `engine/DnsServer.cpp` | `monarchy-dns-tests` |
| Monarchy Management Console (MMC-style): tree, results views, property sheets, membership editing, CSV export | `ui/src/` | `monarchy-ui-tests` |
| **DCE/RPC over ncacn_ip_tcp** + NDR marshalling | `engine/Rpc.cpp`, `engine/Ndr.cpp` | `monarchy-samr-tests`, live impacket client |
| **RPC authentication**: NTLMSSP directly (`auth_type` 10) and wrapped in GSS-SPNEGO (`auth_type` 9, what Windows and Samba send) — bind NEGOTIATE/CHALLENGE, the AUTHENTICATE leg in either an `AUTH3` or an `alter_context` PDU, per-PDU signing (level 2) and sealing (level 6) with the NTLM session keys; unauthenticated calls are refused and a failed AUTHENTICATE ends the connection | `engine/Rpc.cpp`, `engine/Ntlm.cpp`, `engine/Asn1.cpp`, `ui/src/mainwindow.cpp` | impacket with credentials walks the full SAMR chain over an authenticated, sealed session, and Samba's own NDR client (`samba.dcerpc.samr`) binds the same endpoint with SPNEGO and completes the exchange; a wrong password is rejected |
| **Kerberos as the RPC security provider** (`auth_type` 16 with a bare AP-REQ, and 9 with it inside GSS-SPNEGO): the bind's AP-REQ is accepted by the KDC, the ack carries the AP-REP with a fresh acceptor subkey, and the initiator's closing AP-REP (in an `AUTH3` or an `alter_context`) completes mutual authentication — it echoes the acceptor's sequence number and opens under the acceptor subkey, or under the ticket session key for clients following the older reading. Every later PDU carries an RFC 4121 CFX token split around the stub (verifier = header, encrypted header copy, checksum, confounder; stub = ciphertext, recombined by the header's rotation), sealed at level 6 and a MIC-signed at level 2, with sequence numbers from the AP-REP checked; SAMR's password buffers key off the ticket session key | `engine/Rpc.cpp`, `engine/Gss.cpp`, `engine/Kdc.cpp`, `ui/src/mainwindow.cpp` | `dceRpcFraming` in `monarchy-kerberos-tests` (token split against an independently built initiator half, tamper and wrong-key rejection, MIC coverage), and impacket over `ncacn_ip_tcp` with Kerberos walks `SamrConnect` → `SamrEnumerateDomainsInSamServer` → `SamrLookupDomainInSamServer` → `SamrOpenDomain` → `SamrEnumerateUsersInDomain` at `PKT_PRIVACY` and at `PKT_INTEGRITY`; NTLM over the same endpoint still passes |
| **One bind_ack result per presentation context**: NDR32 accepted, NDR64 declined with `proposed_transfer_syntaxes_not_supported`, in the order the client offered them | `engine/Rpc.cpp` | `rpcBindAnswersEveryContext` in `monarchy-samr-tests`; a Samba client (which offers both) binds instead of reporting `NT_STATUS_RPC_PROTOCOL_ERROR` |
| **SAMR served by the DC process itself** (`monarchy-ui`, loopback, `samrPort` from `dc.conf`) from the same store LDAP serves: bind, `SamrConnect`, `SamrConnect2`, `SamrConnect4`, `SamrConnect5`, `SamrEnumerateDomainsInSamServer`, `SamrLookupDomainInSamServer`, `SamrOpenDomain`, `SamrQueryInformationDomain` (password, name, role and lockout information), `SamrEnumerateUsersInDomain`, `SamrOpenUser`, `SamrQueryInformationUser2` (classes 4, 6, 8, 16 and 21 — class 4 is the MS-SAMR 2.2.7.5 logon-hours array, class 21 the aggregate that carries it alongside every string, the counters and the country/code page), `SamrLookupNamesInDomain`, `SamrLookupIdsInDomain`, `SamrCloseHandle`, and the write path: `SamrCreateUser2InDomain`, `SamrCreateGroupInDomain`, `SamrOpenGroup`, `SamrEnumerateGroupsInDomain`, `SamrQueryInformationGroup` (classes 1, 2, 3 and 4), `SamrSetInformationGroup` (class 4, the administrative comment, written to the directory), `SamrAddMemberToGroup`, `SamrRemoveMemberFromGroup`, `SamrGetMembersInGroup`, `SamrDeleteUser`, `SamrDeleteGroup` | `engine/Samr.cpp`, `engine/LdapServer.cpp`, `ui/src/mainwindow.cpp` | provisioned `MONARCHY.TEST`, then impacket created a user (RID 1001) and group (1002), added the member, read it back, deleted both — with LDAP showing the same account, SID and `member` at each step; write flow covered by `samrWritesAccountsAndGroups` in `monarchy-samr-tests` |
| **LSAD (lsarpc) served by the DC process itself** (loopback, `lsadPort` from `dc.conf`) from the same store LDAP and SAMR serve, behind the same NTLMSSP/GSS-SPNEGO and Kerberos binds: `LsarOpenPolicy`/`LsarOpenPolicy2`, `LsarClose`, `LsarDeleteObject`, `LsarQueryInformationPolicy`/`…Policy2` for every class MS-LSAD defines (1 audit log, 2 audit events, 3/5/14 domain — primary, account and local account — 4 PD account, 6 server role, 7 replica source, 8 default quota, 9 modification, 10/11 audit-full set and query, 12/13 DNS domain), `LsarLookupNames`/`2`/`3`/`4`, `LsarLookupSids`/`2`/`3`, `LsarEnumAccounts`, `LsarEnumPrivileges` (the 34-privilege catalogue, paged with `STATUS_MORE_ENTRIES` and the closing `STATUS_NO_MORE_ENTRIES`), `LsarLookupPrivValue`/`PrivName`/`PrivDisplayName`, `LsarOpenAccount`, `LsarEnumPrivsAccount`, `LsarAddPrivilegesToAccount`/`RemovePrivilegesFromAccount`, `LsarGetSystemAccessAccount`/`SetSystemAccessAccount`, `LsarEnumAccountRights`/`AddAccountRights`/`RemoveAccountRights` (written to the account's `userRight` in the directory, so LDAP shows them and they survive a restart), `LsarEnumAccountsWithUserRight`, `LsarCreateSecret`/`OpenSecret`/`SetSecret`/`QuerySecret`, `LsarStorePrivateData`/`RetrievePrivateData`, `LsarGetUserName`, `LsarQuerySecurityObject`/`SetSecurityObject` (a self-relative descriptor owned by BUILTIN\Administrators), `LsarQueryDomainInformationPolicy` (QoS, EFS and the Kerberos ticket lifetimes) and `LsarEnumTrustDom`/`EnumTrustedDomainsEx` (empty, as a standalone DC). Each arm is marshalled the way the structure it carries is declared: `lsa_String`/`StringLarge` are Length/MaximumLength plus a deferred varying buffer, `dom_sid2` opens with its conformant sub-authority count, `lsa_DefaultQuotaInfo` pads to the 8-byte hyper, and the trailing `NTSTATUS` lands on a 4-byte boundary with no trailer padding (MS-RPCE 2.2.5.3.4.1 makes trailer alignment a no-op for NDR32) | `engine/Lsad.{h,cpp}`, `ui/src/mainwindow.cpp` | `monarchy-lsad-tests` pins the response bytes for levels 3, 5 and 8, the two single-byte audit arms, `LsarLookupPrivDisplayName`, and the invalid-handle/invalid-class refusals; `scripts/lsad-conformance.py` drives a live endpoint with two independent NDR implementations and exits non-zero on any failure — Samba's `samba.dcerpc.lsa` (pidl's own decoder, the reference the layout is written against) for every policy class, both translation directions, the rights round trip, the privilege calls and the domain policy, and impacket's `lsad`/`lsat` (MS-LSAD straight from the specification) for `GetUserName`, account enumeration and handles, private data and secrets — 50 checks, all passing |
| **SAMR account information writes**: `SamrSetInformationUser` / `SamrSetInformationUser2` for classes 8 (full name), 13 (comment), 16 (account flags), 17 (expiry), 20 (parameters), 21 (the aggregate `SAMPR_USER_ALL_INFORMATION`), 23 and 25 (that structure plus a password buffer) and 24/26 (password alone). Class 21 applies exactly the fields `WhichFields` names — full name, description, comment, home directory and drive, script, profile, workstations, primary group, account flags and expiry, parameters, country and code page, the logon week — and leaves the rest alone; 23/25 and 24/26 carry the password RC4-ciphered under the RPC session key, which `Rpc::Call` carries to the handler | `engine/Samr.cpp`, `engine/Samr.h`, `engine/Rpc.{h,cpp}`, `ui/src/mainwindow.cpp` | provisioned `MONARCHY.AGG`, then impacket over an authenticated, sealed session: `SamrCreateUser2InDomain`, one class-21 write of fourteen fields, every one read back through class 21, the week through class 4 and through the aggregate; class 23 then 25 set the password and the **new password logs in over a fresh sealed NTLM bind while the superseded one is refused**; a truncated structure is refused without writing; LDAP serves the new `displayName`, `homeDirectory` and week and never the hash. `samrWritesTheAggregateUserInformation` and `samrSetsPasswordThroughTheAggregateClasses` cover the same wire forms with captured bytes, including the `SAMPR_FIELD_OWF_PWD` hash path. The class 24/26 buffer is read from the end of the 512-byte block, which is where Samba's `extract_pw_from_buffer` and impacket's client both put it |

| **SMB2 with named pipes** (`ncacn_np`) served by the DC process on `smbPort` (445 by default): dialect negotiation (2.0.2/2.1), session setup carrying SPNEGO/NTLMSSP verified by the same authenticator SAMR and LSAD use, SMB2 signing (HMAC-SHA256 over the exported session key, including the key-exchange RC4 step), tree connect to `IPC$`, and create/write/read/close on `\pipe\samr`, `\pipe\lsarpc` and `\pipe\epmapper`. Each pipe is a headless channel into that interface's own `RpcServer`, so bind negotiation, dispatch and faults are the TCP endpoint's code; the authenticated SMB session's principal authorises the calls, as on Windows | `engine/Smb2.{h,cpp}`, `engine/Rpc.{h,cpp}` (`RpcServer::Channel`), `ui/src/mainwindow.cpp` | `monarchy-smb-tests` (6 cases) pins negotiation, the tree connect, pipe open/close and a full DCE/RPC bind carried through a pipe. Live against a provisioned DC: impacket over `ncacn_np` on `\pipe\samr` enumerates the domain and on `\pipe\lsarpc` opens the policy and reads the account domain (status 0), and Samba's own `smbclient -L` authenticates with NTLMSSP and signing and lists the server |
| **Endpoint mapper** (`ncacn_epm`, `e1af8308-5d1f-11c9-91a4-08002b14a0fa` v3.0) served on `epmPort` (135 by default): `ept_lookup` with the all-elements, by-interface and paging inquiries, `ept_map`, `ept_lookup_handle_free`, and the management opnums refused with `EPMAPPER_STATUS_CANT_PERFORM_OP`. Every answer is built from the ports the endpoints actually bound, so a discovered port is always one that accepts a connection, and the tower is encoded the way C706 appendix L defines it — five floors, little-endian lengths, big-endian TCP port and IPv4 address — rather than by NDR. Each interface is advertised twice: an `ncacn_ip_tcp` tower and an `ncacn_np` tower naming its pipe, and `ept_map` answers with the transport the caller asked for rather than the first entry that matched the UUID | `engine/Epm.{h,cpp}`, `ui/src/mainwindow.cpp`, `engine/Provisioner.cpp` | `monarchy-epm-tests` (9 cases) pins the tower's five floors and byte order, the lookup reply layout against the bytes impacket's own marshaller produces, both handle marshallings a client may use, paging, `ept_map` against a captured impacket request, and the refusals.Live: `hept_lookup` returns `lsarpc → ncacn_ip_tcp:127.0.0.1[1036]`,
`samr → …[1035]`, `epmapper → …[1135]`, and `hept_map` resolves the same towers |
| **DRSR (MS-DRSR) replication, served by the DC process itself** (`drsPort`
1038 on loopback, behind the same NTLMSSP/GSS-SPNEGO and Kerberos
authenticator as SAMR, advertised over the endpoint mapper): `DsBind`/`
DsUnbind` — the handle plus the extension words advertising GETCHGREQ
V5/V8/V10 and GETCHGREPLY V6 — `DsGetNCChanges` answered in V6 for V8/V10
requests: the canonical 19-entry MS-DRSR §5.12.2 schema prefix table, the
usnvec echo, up-to-date cursors, `cNumBytes` over the object list, a batch
capped at `cMaxObjects` with `fMoreData` for the rest, and the object chain
marshalled the way the peer walks it (REPLENTINFLIST → ENTINF → ATTRBLOCK →
interleaved ATTR triples → per-value conformant arrays, DSNAME with its
conformant string head). `EXOP_REPL_OBJ` targets one object by DN, GUID or
SID; `DsReplicaSync`/`DsUpdateRefs` are answered as the lifecycle calls a
cycle makes. `DsCrackNames` translates FQDN, canonical, NT4 (with and
without the domain), UPN, display name, GUID, SID and DNS-domain forms
against the same directory, and `DsGetDomainControllerInfo` (levels 1/2/3
plus the connection arm) describes this DC — level 2 carrying the NTDS
Settings GUID a DCSync client pulls with. Password material (`unicodePwd`,
`supplementalCredentials`) is deliberately not served: replication-level
conformance, not secret export. | `engine/Drs.{h,cpp}`,
`ui/src/mainwindow.cpp` (listen + endpoint-mapper entry) |
`monarchy-drs-tests` (5 cases: the bind extensions, a whole V6 reply walked
field by field — every object, its attribute list and its values — level-2
DC info pinned, FQDN→canonical pinned, and the refusals); live,
`scripts/drs-conformance.py` drives the DCSync-shaped sequence over
impacket's independent NDR implementation against the DC process's own
endpoint behind an authenticated NTLMSSP bind at `PKT_PRIVACY` — the same
authenticator path SAMR and LSAD use (6 checks, non-zero exit on any
failure) |

## 2. Not implemented — not claimed, not stubbed

- **SAMR beyond the calls above**: aliases; `SamrSetInformationDomain` (the
  password policy is reported but not settable over RPC); `SamrSetInformationGroup`
  classes 1–3 (renaming a group and setting its SE_GROUP_* attribute set have no
  directory attribute behind them, so they are refused rather than accepted and
  dropped); and the bad-password and logon counters, which are always reported
  as zero because nothing counts them.
- **Logon-hour enforcement**: a week written over SAMR is stored and reported
  back, but nothing consults it when an account logs on, so it does not yet
  restrict anything. The directory keeps it as a hex string rather than the
  binary attribute AD stores, because every attribute in this store is text.
- **LSAD trusted domains**: enumeration answers "no trusts" and creation is
  refused with `STATUS_NOT_SUPPORTED`, because a trust is only real once
  Netlogon carries its secure channel; recording one would make every later
  authentication through it fail with no explanation. `LsarSetInformationPolicy`
  sets the modification time and the audit-full flag and refuses the rest (the
  domain name and SID are reported, not settable), as does
  `LsarSetDomainInformationPolicy` (the Kerberos lifetimes are reported, not
  settable). `LsarCreateAccount` answers `STATUS_NOT_SUPPORTED`: MS-LSAD 3.1.4.5.1
  has accounts created through SAMR.
- **LSAD state that is not part of the store**: LSA secrets and private data live
  in the serving process (they are not persisted, and nothing encrypts them at
  rest), and the per-account system-access mask is per handle rather than
  written to the directory.
- **DRSR `DsReplicaAdd`** (opnum 25): with one DC and one naming context
  there is no replica to add, so the call is refused with
  `ERROR_INVALID_PARAMETER` rather than accepted and silently dropped.
- **Netlogon** (`reference/specs/samba-netlogon.idl` is on disk as the basis
  for the remaining slice; see §3.6).
- **SMB2 beyond the pipe transport**: dialects 2.0.2 and 2.1 only (no SMB 3.x,
  so no preauth integrity, no encryption, no multi-channel); only the `IPC$`
  share exists, so a directory browse is empty; SMB1 is not answered, which
  means a client that insists on an SMB1 negotiation rather than falling back
  to SMB2 cannot connect; and `smbPort` defaults to 445, which needs
  `CAP_NET_BIND_SERVICE` or root like the endpoint mapper.
- **The endpoint mapper's limits**: it binds `epmPort` (135 by default), and
  binding 135 needs `CAP_NET_BIND_SERVICE` or root: an unprivileged console
  reports that on the status bar and the endpoints stay reachable by explicit
  port, which is the same trade a non-root Samba makes. The reply layout is
  verified against impacket's decoder and against Samba's DCE client at bind
  time; Samba's pidl decoder has not been driven through a lookup here (its
  python binding cannot construct the call's `policy_handle`), so an interop
  report from a pidl client would be worth having.
- **PKINIT** (needs an X.509/CMS path and a CA), **S4U2Self/S4U2Proxy**.
- **Multi-hop/transitive trusts**, transited-realm encoding beyond one hop, SID
  filtering, selective authentication, trust-password rotation.
- **PAC read authorization** (writes are authorized from the PAC; reads are not
  yet), PAC credential/delegation/claims buffers.
- GPO editing and CSE processing, SYSVOL over SMB, multi-DC replication (the
  KCC), DNSP, reverse zones, schema LDF import, ADWS.

## 3. Distance to 1:1, in dependency order

The gaps above are not independent. Working outward from what exists:

1. ~~RPC authentication~~ — NTLMSSP and Kerberos are both in, with signing and
   sealing, and Kerberos shares the KDC's acceptor the LDAP path uses.
2. ~~SAMR writes~~ — create/delete user and group, members, every information
   class including the aggregate 21/23/25 writes and the logon week. Remaining
   here: aliases, and setting the domain policy over RPC.
3. ~~Endpoint mapper~~ — `ept_lookup`/`ept_map` answer on `epmPort`, so a client
   can now discover a port instead of being told one.
4. ~~SMB2 server + named pipes~~ — `\\dc\pipe\samr`, `\pipe\lsarpc` and
   `\pipe\epmapper` carry DCE/RPC into the same endpoints the TCP ports serve;
   the remaining work here is SMB 3.x (encryption, preauth) and a real share.
5. ~~LSAD~~ — the policy calls, both translation directions, account rights,
   privileges, secrets and the policy security descriptor, verified against
   Samba's reference NDR decoder and impacket by `scripts/lsad-conformance.py`.
   Remaining here: trusted-domain creation, which needs Netlogon first.
6. **Netlogon**: secure channel, DC locator, domain join, machine passwords.
7. ~~DRSR~~ — `DsBind`/`DsGetNCChanges`/`DsReplicaSync` plus `DsCrackNames`
   and `DsGetDomainControllerInfo` are served and verified (§1). What
   remains is `DsReplicaAdd` and the multi-DC half: replication between two
   Monarchy DCs (and with Samba/Windows DCs), which is what makes a domain a
   domain rather than one server.

After those: GPO/SYSVOL over SMB, FSMO, sites and the KCC, interdomain trust
replication, WINS-era name resolution if 2000 parity is taken literally, and the
schema/LDF import path. Each block is landed the way SAMR was: against the
IDL in `reference/specs/`, driven by an independent client, with the CI suite
extended in the same change.

## 4. Security posture

Development directory service, not a hardened DC. LDAP is plaintext unless the
client asks for StartTLS (there is no dedicated LDAPS port, and no client
certificate is requested), DNS updates have no TSIG or ACL, and RPC has no
authorization model beyond "the bind authenticated": any account that
authenticates can administer. The RPC endpoints therefore bind `127.0.0.1`
only (`samrPort` 1035, `lsadPort` 1036 and `drsPort` 1038 by default). Do not
expose ports 1389/1053/1035/1036/1038 to untrusted networks, and do not move
the RPC endpoints off loopback until per-account RPC authorization exists.

## 5. Third-party references

Protocol references used to derive wire formats (Samba IDLs under GPL-3.0-or-later,
impacket under Apache-2.0 as an independent client oracle) are held in
`reference/specs/` with provenance in `reference/specs/README.md` and
`CREDITS-INDEX.md`. Nothing from them is linked into the engine or console.
