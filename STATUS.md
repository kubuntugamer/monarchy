# Monarchy 0.1.0 — release status

This file is the release contract for 0.1.0. It lists what the build actually
does, how each capability is proven, and what is deliberately **not** claimed.
Anything not listed under "Implemented and verified" is absent, not partial.

Verified on this tree with `scripts/ci.sh` — a fresh configure, a build that
emits no warnings, and every suite → **20/20 suites pass**. `scripts/ci.sh
--conformance` goes further: it provisions a throwaway domain, starts the daemon
on free ports and drives the running DC with impacket's own DRSR and LSAD NDR
clients, so a reply only this tree's encoder understands fails the check.

---

## 1. Implemented and verified

| Capability | Implementation | Verification |
|---|---|---|
| Domain provisioning from Monarchy's own code (objects, SIDs, groups, default GPOs, SYSVOL, secrets, DNS zone) | `engine/Provisioner.cpp`, `monarchy-provision` | `monarchy-provision-tests` |
| LDAP server (RFC 4511 subset): bind, search, add, modify, delete, modifyDN, compare, rootDSE | `engine/LdapServer.cpp` | `monarchy-backend-tests`, `monarchy-ui-tests` |
| **Published DSA identity and Global Catalog**: the root DSE names the agent a client reached, from the same `dc.conf` that names the realm — `dnsHostName`, `serverName`/`dsServiceName` pointing at the provisioned `CN=NTDS Settings` object, `ldapServiceName`, `isSynchronized`, the Windows 2000 behavior levels, and only the paged-results control this server answers — and `isGlobalCatalogReady` is TRUE only while the catalog listener is up. The catalog is the **same store on `gcPort` 3268**, not a copy, so a write on 389 is visible on the catalog port with no replication step. Provisioning creates the `NTDS Settings` object (`nTDSDSA`, `options` IS_GC, `invocationId`, `hasMasterNCs`) and the `CN=Partitions` cross-ref container, so the FSMO owners on the domain, the schema NC and the partitions container all name an object the directory holds; the default GPOs' `gPCFileSysPath` is the domain's SYSVOL share | `engine/LdapServer.{h,cpp}`, `engine/DcService.cpp`, `engine/Provisioner.cpp` | `publishesItsIdentityAndGlobalCatalog` and `buildsDomainFromScratch` in `monarchy-provision-tests` (root DSE fields, catalog up/down, and the same accounts returned over the catalog port as over LDAP) |
| **StartTLS** (RFC 4511 §4.14.1): the listener accepts plaintext and upgrades the same socket in place, resetting the session to anonymous; the provisioner creates the DC certificate (`private/ldap.crt`, self-signed, CA:TRUE, SANs for the DC FQDN, NetBIOS name, the DC IP and `localhost`), and a domain provisioned without `openssl` refuses StartTLS with `unavailable(52)` instead of answering success without encrypting | `engine/LdapServer.cpp`, `engine/Provisioner.cpp`, `ui/src/mainwindow.cpp` | `monarchy-tls-tests`: TLS handshake against the provisioned certificate, bind and search inside it, plaintext-after-upgrade aborted, and openssl's own `s_client -starttls ldap` verifies the certificate; live, ldap3 verifies it against the same file as CA before binding |
| **LDAP request controls** with paged results (RFC 2696, OID 1.2.840.113556.1.4.319): pages, total count and resume cookie per connection, abandon with size 0, a cookie from another search refused with `unwillingToPerform`; an unknown control is ignored unless the client marks it critical, which is refused with `unavailableCriticalExtension(12)` | `engine/LdapServer.cpp` | `monarchy-ldap-tests` (5 cases); live, ldap3 walks a 22-object domain in 11 pages of 2 with no repeats over StartTLS |
| Group membership (`member` DNs, derived `memberOf`) | `engine/LdapServer.cpp`, `backend/AdminService.cpp` | `monarchy-backend-tests` |
| Password policy and credential storage (salted verifier, NT hash, AES keys), never returned by search | `engine/LdapServer.cpp`, `engine/Krb5.cpp` | `monarchy-backend-tests`, `monarchy-ntlm-tests` |
| NTLMv2 over LDAP SASL (NEGOTIATE/CHALLENGE/AUTHENTICATE) | `engine/Ntlm.cpp`, `engine/LdapServer.cpp` | `monarchy-ntlm-tests` (11 cases) |
| **NTLM message signing and sealing** (MS-NLMP §3.4) over LDAP, RFC 4422 framing | `engine/Ntlm.cpp`, `engine/LdapServer.cpp` | byte-exact vs impacket; signed, sealed and tamper-rejected sessions |
| Kerberos KDC: RC4-HMAC + AES-128/256, pre-auth, TGT/TGS, subkey-sealed replies, AP-REQ/AP-REP | `engine/Kdc.cpp`, `engine/Krb5.cpp`, `engine/Aes.cpp` | `monarchy-kerberos-tests` (18 cases), driven by MIT krb5 |
| **kpasswd (RFC 3244)**, the change-password service on 464 that the zone's `_kpasswd` locators name: TCP (four-octet length prefix) and UDP, request versions 0x0001 (the password in the KRB-PRIV) and 0xff80 (`ChangePasswdData`, which can name another account). The AP-REQ's `kadmin/changepw` ticket is verified by the KDC's own acceptor, the KRB-PRIV is opened under the authenticator's subsession key, the reply's AP-REP under the ticket session key, and the answer carries RFC 3244 result codes — including `SOFTERROR` with the policy's reason and `ACCESSDENIED` for a non-administrator naming another account. The write goes through the same password path as LDAP and SAMR, so Kerberos keys, the NT hash and the simple-bind verifier move together | `engine/Kpasswd.{h,cpp}`, `engine/Kdc.cpp`, `engine/DcService.cpp` | `monarchy-kpasswd-tests` (4 cases) driven by MIT's `krb5_change_password` and `krb5_set_password`, which verify the AP-REP and the KRB-PRIV key independently: own-password change with the new password opening a TGT and the old one refused, the NT hash following, a weak password refused with `SOFTERROR` and the old credential intact, an administrator setting another account's password, and a standard user refused `ACCESSDENIED` |
| PAC: LOGON_INFO, CLIENT_INFO, UPN_DNS_INFO, server+KDC signatures, `readIdentity()`, write authorization from the PAC | `engine/Pac.cpp` | `krb5_pac_verify` / `krb5_pac_get_buffer` (MIT), plus ACL behaviour tests |
| GSSAPI SASL layers (RFC 4752/4121/1964) with wrapped LDAP sessions, RC4 and AES | `engine/LdapServer.cpp` | MIT seals/opens the tokens independently |
| **Cross-realm trust** (direct): referral TGT `krbtgt/PEER@OURS`, inter-realm keys, inbound `krbtgt/OURS@PEER`, PAC re-signed at the boundary | `engine/Kdc.cpp`, `engine/Krb5.cpp` | MIT `kinit` into ALPHA, service ticket from BETA, AP-REQ accepted by BETA's directory |
| **Workstation logon restriction**: the `userWorkstations` list an account carries (the "Log On To" list) is enforced, not merely stored and returned. Netlogon's `NetrLogonSamLogon` answers `STATUS_INVALID_WORKSTATION` when the verified account names workstations and the caller's `NETLOGON_LOGON_INFO` workstation is not among them; matching is case-insensitive after trimming, a blank entry names nobody, an account with no value is unrestricted, and a restricted account whose caller names no workstation is refused rather than waved through. The check sits after the password and after the week, so a wrong password is still answered as a wrong password. It is not applied to the LDAP or Kerberos paths, because neither carries a workstation name the directory can trust | `engine/WorkstationRestriction.{h,cpp}`, `engine/Netlogon.cpp` | `monarchy-workstation-tests` (the list parsing, blank entries, unset and unnamed cases), `refusesALogonFromAnotherWorkstation` and `allowsALogonFromAListedWorkstation` in `monarchy-netlogon-tests` |
| **Account logon hours**: the 21-byte week an account carries is enforced at logon, not merely stored and reported. The KDC refuses an AS-REQ outside it with `KDC_ERR_CLIENT_REVOKED`, LDAP refuses simple and NTLM binds with `invalidCredentials(49)`, and Netlogon's `NetrLogonSamLogon` answers `STATUS_ACCOUNT_RESTRICTION` without stamping `lastLogon` — every check sits after the password is verified, so a refused hour is indistinguishable from a wrong password. Bits count in UTC from Sunday 00:00; an account with no value is unrestricted, and a value shorter than 21 bytes says nothing about the hours it does not cover | `engine/LogonHours.{h,cpp}`, `engine/Kdc.cpp`, `engine/LdapServer.cpp`, `engine/Netlogon.cpp` | `monarchy-logonhours-tests` (the week mapping, all 168 bits, both boundaries, unset and truncated values), `refusesALogonOutsideLogonHours` in `monarchy-netlogon-tests`; live, MIT `kinit` against a provisioned DC is refused `Client's credentials have been revoked` when the week excludes the current hour and succeeds when it includes it, and an LDAP simple bind answers 49 and 0 for the same two weeks |
| DNS server: DC locator records, SRV/A/ANY, RFC 2136 updates, persistence, and locator self-repair on start (a zone that predates a served endpoint gets its locator back, at the port the daemon actually binds); UDP/TCP with a caching forwarding resolver for out-of-zone names | `engine/DnsServer.cpp`, `engine/DcService.cpp` | `monarchy-dns-tests` (`publishesAdServiceRecords`, `repairsAdZoneLocators`) |
| Monarchy Management Console (MMC-style): tree, results views, property sheets, membership editing, CSV export | `ui/src/` | `monarchy-ui-tests` |
| **DCE/RPC over ncacn_ip_tcp** + NDR marshalling | `engine/Rpc.cpp`, `engine/Ndr.cpp` | `monarchy-samr-tests`, live impacket client |
| **RPC authentication**: NTLMSSP directly (`auth_type` 10) and wrapped in GSS-SPNEGO (`auth_type` 9, what Windows and Samba send) — bind NEGOTIATE/CHALLENGE, the AUTHENTICATE leg in either an `AUTH3` or an `alter_context` PDU, per-PDU signing (level 2) and sealing (level 6) with the NTLM session keys; unauthenticated calls are refused and a failed AUTHENTICATE ends the connection | `engine/Rpc.cpp`, `engine/Ntlm.cpp`, `engine/Asn1.cpp`, `ui/src/mainwindow.cpp` | impacket with credentials walks the full SAMR chain over an authenticated, sealed session, and Samba's own NDR client (`samba.dcerpc.samr`) binds the same endpoint with SPNEGO and completes the exchange; a wrong password is rejected |
| **Kerberos as the RPC security provider** (`auth_type` 16 with a bare AP-REQ, and 9 with it inside GSS-SPNEGO): the bind's AP-REQ is accepted by the KDC, the ack carries the AP-REP with a fresh acceptor subkey, and the initiator's closing AP-REP (in an `AUTH3` or an `alter_context`) completes mutual authentication — it echoes the acceptor's sequence number and opens under the acceptor subkey, or under the ticket session key for clients following the older reading. Every later PDU carries an RFC 4121 CFX token split around the stub (verifier = header, encrypted header copy, checksum, confounder; stub = ciphertext, recombined by the header's rotation), sealed at level 6 and a MIC-signed at level 2, with sequence numbers from the AP-REP checked; SAMR's password buffers key off the ticket session key | `engine/Rpc.cpp`, `engine/Gss.cpp`, `engine/Kdc.cpp`, `ui/src/mainwindow.cpp` | `dceRpcFraming` in `monarchy-kerberos-tests` (token split against an independently built initiator half, tamper and wrong-key rejection, MIC coverage), and impacket over `ncacn_ip_tcp` with Kerberos walks `SamrConnect` → `SamrEnumerateDomainsInSamServer` → `SamrLookupDomainInSamServer` → `SamrOpenDomain` → `SamrEnumerateUsersInDomain` at `PKT_PRIVACY` and at `PKT_INTEGRITY`; NTLM over the same endpoint still passes |
| **One bind_ack result per presentation context**: NDR32 accepted, NDR64 declined with `proposed_transfer_syntaxes_not_supported`, in the order the client offered them | `engine/Rpc.cpp` | `rpcBindAnswersEveryContext` in `monarchy-samr-tests`; a Samba client (which offers both) binds instead of reporting `NT_STATUS_RPC_PROTOCOL_ERROR` |
| **SAMR served by the DC process itself** (`monarchy-ui`, loopback, `samrPort` from `dc.conf`) from the same store LDAP serves: bind, `SamrConnect`, `SamrConnect2`, `SamrConnect4`, `SamrConnect5`, `SamrEnumerateDomainsInSamServer`, `SamrLookupDomainInSamServer`, `SamrOpenDomain`, `SamrQueryInformationDomain` (password, name, role and lockout information), `SamrEnumerateUsersInDomain`, `SamrOpenUser`, `SamrQueryInformationUser2` (classes 4, 6, 8, 16 and 21 — class 4 is the MS-SAMR 2.2.7.5 logon-hours array, class 21 the aggregate that carries it alongside every string, the counters and the country/code page), `SamrLookupNamesInDomain`, `SamrLookupIdsInDomain`, `SamrCloseHandle`, and the write path: `SamrCreateUser2InDomain`, `SamrCreateGroupInDomain`, `SamrOpenGroup`, `SamrEnumerateGroupsInDomain`, `SamrQueryInformationGroup` (classes 1, 2, 3 and 4), `SamrSetInformationGroup` (class 4, the administrative comment, written to the directory), `SamrSetInformationDomain` (class 1, the password policy — minimum length, remembered passwords, the `pwdProperties` flags and the two ages — and class 12, the account lockout policy, both written to the domain object the logon and password paths read), `SamrAddMemberToGroup`, `SamrRemoveMemberFromGroup`, `SamrGetMembersInGroup`, `SamrDeleteUser`, `SamrDeleteGroup`, `SamrLookupDomainInSamServer`/`SamrOpenDomain` on `BUILTIN` as well as the account domain, and the alias half of the interface — `SamrCreateAliasInDomain`, `SamrEnumerateAliasesInDomain`, `SamrOpenAlias`, `SamrQueryInformationAlias` (classes 1–3), `SamrSetInformationAlias` (class 3, the comment), `SamrAddMemberToAlias`, `SamrRemoveMemberFromAlias`, `SamrGetMembersInAlias` and `SamrDeleteAlias`, which AD backs with domain-local group objects | `engine/Samr.cpp`, `engine/LdapServer.cpp`, `ui/src/mainwindow.cpp` | provisioned `MONARCHY.TEST`, then impacket created a user (RID 1001) and group (1002), added the member, read it back, deleted both — with LDAP showing the same account, SID and `member` at each step; `scripts/samr-conformance.py` then covered the alias lifecycle, the password policy read back and written (AD's default 7 / 24 / complexity / 42 days / 1 day, then a set, then a refusal of a maximum age shorter than the minimum, then the default restored) and the `BUILTIN` domain over the same sealed session — 31 checks, all passing, and repeated runs leave nothing behind; the write flow is covered by `samrWritesAccountsAndGroups`, the policy by `samrServesTheDomainPasswordPolicy` and the `BUILTIN` answers by `samrServesTheBuiltinDomain` in `monarchy-samr-tests` |
| **Netlogon (MS-NRPC) served by the DC process itself**: `netlogonPort` (1037 by default; provisioning writes it and `drsPort` to `dc.conf`, so a second DC on the same host can move both), loopback, advertised by the endpoint mapper on `ncacn_ip_tcp` and `ncacn_np:\\pipe\\netlogon` and carried by the SMB2 pipe host. `NetrServerReqChallenge` (a challenge with no entropy is refused), `NetrServerAuthenticate`/`…2`/`…3` at all three crypto strengths this server negotiates — legacy 64-bit DES, strong-key MD4 and AES session keys — with the credential chain and RID, `NetrServerPasswordSet2` (the 512-byte buffer decrypted under the channel's session key, the UTF-16 terminator trimmed by code unit, and only the new NT hash written to the machine account), `NetrLogonSamLogon`, `…WithFlags` and `…Ex` validating an NTLMv2 response against the account's stored hash and answering validation level 3 (`NETLOGON_VALIDATION_SAM_INFO2`), and answering the interactive (1) and service (3) classes, whose `netr_PasswordInfo` carries the password's own NT one-way function rather than a challenge and is matched to the stored hash in constant time (the LM function beside it is ignored, not trusted, because no LM hash is stored, and a caller that sends only that half is refused) — a successful validation stamps `lastLogon` and `logonCount` on the account and refreshes the replicated `lastLogonTimestamp` only when it is older than the 14-day window MS-ADTS sets — the trust channel — a partner DC's `NetrServerAuthenticate3` against `<TRUST>$` is verified with the inbound secret of the `trustedDomain` object, an outbound-only trust is not an account, and `NetrLogonGetTrustRid` reports the RID of the disabled trust account LSAD creates beside the trust — and the locator calls: `NetrGetDCName`, `NetrDSRGetDcNameEx2` and the older `NetrGetAnyDCName` answer this DC's UNC name, address, domain, site and the `NBT_SERVER_DS|KDC|TIMESERV|WRITABLE|GC` flags, `NetrDSRGetSiteName` names the site, and a domain this DC does not serve is refused | `engine/Netlogon.{h,cpp}`, `engine/DcService.cpp`, `engine/Epm.*`, `engine/Smb2.*` | `monarchy-netlogon-tests` (13 cases: an independently computed client half for every crypto level, both authenticate opnums, the full channel → `SamLogon` path, the interactive and service password logons with a wrong one-way function refused, the logon stamps written back, `PasswordSet2` writing exactly the new hash, the trust channel opened with the stored trust secret and refused for an outbound-only trust, the trust-account RID and its refusal for an unknown domain, a forged credential and an unknown account refused, and the locator calls, legacy any-DC and site-name included, with their refusals) |
| **LSAD (lsarpc) served by the DC process itself** (loopback, `lsadPort` from `dc.conf`) from the same store LDAP and SAMR serve, behind the same NTLMSSP/GSS-SPNEGO and Kerberos binds: `LsarOpenPolicy`/`LsarOpenPolicy2`, `LsarClose`, `LsarDeleteObject`, `LsarQueryInformationPolicy`/`…Policy2` for every class MS-LSAD defines (1 audit log, 2 audit events, 3/5/14 domain — primary, account and local account — 4 PD account, 6 server role, 7 replica source, 8 default quota, 9 modification, 10/11 audit-full set and query, 12/13 DNS domain), `LsarLookupNames`/`2`/`3`/`4`, `LsarLookupSids`/`2`/`3`, `LsarEnumAccounts` (every account in the domain rather than only the SIDs carrying a `userRight`, groups excluded, paged against `PreferedMaximumLength` with `STATUS_MORE_ENTRIES` and the returned context), `LsarEnumPrivileges` (the 34-privilege catalogue, paged with `STATUS_MORE_ENTRIES` and the closing `STATUS_NO_MORE_ENTRIES`), `LsarLookupPrivValue`/`PrivName`/`PrivDisplayName`, `LsarOpenAccount`, `LsarEnumPrivsAccount`, `LsarAddPrivilegesToAccount`/`RemovePrivilegesFromAccount`, `LsarGetSystemAccessAccount`/`SetSystemAccessAccount`, `LsarEnumAccountRights`/`AddAccountRights`/`RemoveAccountRights` (written to the account's `userRight` in the directory, so LDAP shows them and they survive a restart), `LsarEnumAccountsWithUserRight`, `LsarCreateSecret`/`OpenSecret`/`SetSecret`/`QuerySecret`, `LsarStorePrivateData`/`RetrievePrivateData`, `LsarGetUserName`, `LsarQuerySecurityObject`/`SetSecurityObject` (a self-relative descriptor owned by BUILTIN\Administrators), `LsarQueryDomainInformationPolicy` (QoS, EFS and the Kerberos ticket lifetimes) and the trusted-domain calls: `LsarCreateTrustedDomain`/`…Ex`/`…Ex2`, `LsarOpenTrustedDomain`/`…ByName`, `LsarQueryTrustedDomainInfo` (level 1 name, 6 info-ex, 7 auth info and 8 full info) and `…ByName`, `LsarSetInformationTrustedDomain`/`SetTrustedDomainInfoByName` (level 7 auth info: a new clear secret and the inter-realm keys re-derived from it), `LsarEnumTrustDom`/`EnumTrustedDomainsEx`, `LsarDeleteTrustedDomain` and `LsarCloseTrustedDomainEx`. A trust is stored as the `trustedDomain` object a Windows DC keeps in `CN=System`, so the partner, flat name, SID, direction, type and attributes are what an LDAP search returns and they survive a restart; a clear trust secret is also turned into the inter-realm `krbtgt` keys, as Windows does, and creation of a duplicate is a name collision rather than a second trust. Each arm is marshalled the way the structure it carries is declared: `lsa_String`/`StringLarge` are Length/MaximumLength plus a deferred varying buffer, `dom_sid2` opens with its conformant sub-authority count, `lsa_DefaultQuotaInfo` pads to the 8-byte hyper, and the trailing `NTSTATUS` lands on a 4-byte boundary with no trailer padding (MS-RPCE 2.2.5.3.4.1 makes trailer alignment a no-op for NDR32) | `engine/Lsad.{h,cpp}`, `ui/src/mainwindow.cpp` | `monarchy-lsad-tests` pins the response bytes for levels 3, 5 and 8, the two single-byte audit arms, `LsarLookupPrivDisplayName`, and the invalid-handle/invalid-class refusals; `scripts/lsad-conformance.py` drives a live endpoint with two independent NDR implementations and exits non-zero on any failure — Samba's `samba.dcerpc.lsa` (pidl's own decoder, the reference the layout is written against) for every policy class, both translation directions, the rights round trip, the privilege calls and the domain policy, and impacket's `lsad`/`lsat` (MS-LSAD straight from the specification) for `GetUserName`, account enumeration and handles, private data and secrets — 50 checks, all passing |
| **SAMR account information writes**: `SamrSetInformationUser` / `SamrSetInformationUser2` for classes 8 (full name), 13 (comment), 16 (account flags), 17 (expiry), 20 (parameters), 21 (the aggregate `SAMPR_USER_ALL_INFORMATION`), 23 and 25 (that structure plus a password buffer) and 24/26 (password alone). Class 21 applies exactly the fields `WhichFields` names — full name, description, comment, home directory and drive, script, profile, workstations, primary group, account flags and expiry, parameters, country and code page, the logon week — and leaves the rest alone; 23/25 and 24/26 carry the password RC4-ciphered under the RPC session key, which `Rpc::Call` carries to the handler | `engine/Samr.cpp`, `engine/Samr.h`, `engine/Rpc.{h,cpp}`, `ui/src/mainwindow.cpp` | provisioned `MONARCHY.AGG`, then impacket over an authenticated, sealed session: `SamrCreateUser2InDomain`, one class-21 write of fourteen fields, every one read back through class 21, the week through class 4 and through the aggregate; class 23 then 25 set the password and the **new password logs in over a fresh sealed NTLM bind while the superseded one is refused**; a truncated structure is refused without writing; LDAP serves the new `displayName`, `homeDirectory` and week and never the hash. `samrWritesTheAggregateUserInformation` and `samrSetsPasswordThroughTheAggregateClasses` cover the same wire forms with captured bytes, including the `SAMPR_FIELD_OWF_PWD` hash path. The class 24/26 buffer is read from the end of the 512-byte block, which is where Samba's `extract_pw_from_buffer` and impacket's client both put it |
| **Domain password policy**: the policy is the domain object's own state under the attribute names AD uses — `minPwdLength`, `pwdHistoryLength`, `pwdProperties` and the two ages — seeded by the provisioner with AD's default domain policy (7 characters, 24 remembered passwords, complexity on, 42 days, 1 day) and read by every password write: LDAP `unicodePwd`/`userPassword` both on add and on modify, SAMR's plaintext password classes (23/25/24/26) and its hash classes (`SamrSetInformationUser` class 18, through `setNtHash`), and kpasswd, which writes through the same path. A password must reach `minPwdLength`, use three of the four character classes while `DOMAIN_PASSWORD_COMPLEX` is set, and differ from the account's current password and the last `pwdHistoryLength` remembered ones — the remembered NT hashes are kept on the account as an attribute a search never returns. A refused password leaves the previous credential in place, and the refusal reaches the client as `constraintViolation` over LDAP and `STATUS_PASSWORD_RESTRICTION` over SAMR. Both ages are reported and settable, and `maxPwdAge` is **enforced at logon** by all three authenticating paths, with the code each one's clients act on: an LDAP bind (simple and NTLM SASL) answers `invalidCredentials(49)` after the password has been proved; the KDC answers `KDC_ERR_KEY_EXPIRED` to an AS-REQ, except one that names `kadmin/changepw`, which stays reachable so an expired account can still change its password through kpasswd; and Netlogon answers `STATUS_PASSWORD_EXPIRED`, or `STATUS_PASSWORD_MUST_CHANGE` when `pwdLastSet` is zero. `DONT_EXPIRE_PASSWORD` on the account overrides the age, and SAMR's class 21 aggregate now computes `PasswordExpired`, `PasswordCanChange` and `PasswordMustChange` from the same policy instead of reporting constants. `minPwdAge` is not enforced — nothing refuses a change that comes too soon, because the only self-change path is kpasswd and it shares the write path with an administrator's reset — and the AD rule that a password may not contain the account name is not applied | `engine/LdapServer.{h,cpp}`, `engine/Samr.cpp`, `engine/Provisioner.cpp` | `enforcesTheDomainPasswordPolicy` in `monarchy-ldap-tests` (the 12-character floor, a letters-only password refused while complexity is on, the current and previous passwords refused, then a policy of no history and no complexity letting them back in), `samrServesTheDomainPasswordPolicy` in `monarchy-samr-tests` (the class 1 wire form against a stored policy, the write reaching every attribute, a maximum age shorter than the minimum refused with `STATUS_INVALID_PARAMETER` and nothing written, and zero accepted as "never expires"), three checks in `scripts/samr-conformance.py` against a live daemon (the default policy read through impacket, a set read back, and the impossible policy refused with the previous policy intact); `refusesAnExpiredPassword`, `refusesAPasswordThatMustChange` and `allowsAnAgedPasswordThatNeverExpires` in `monarchy-netlogon-tests`; `refusesAnExpiredPasswordAtBind` in `monarchy-ldap-tests`; `rejectsExpiredPassword` in `monarchy-kerberos-tests`, which drives MIT's `kinit`; `changesAnExpiredPassword` in `monarchy-kpasswd-tests`, which proves the expired account can still reach `kadmin/changepw` and that the new password opens a TGT; and two checks in `scripts/netlogon-conformance.py` against a live daemon — `STATUS_PASSWORD_EXPIRED` for a one-tick `maxPwdAge`, `STATUS_PASSWORD_MUST_CHANGE` for a SAMR-written `PasswordExpired` account |

| **SMB2 with named pipes** (`ncacn_np`) and the domain's disk shares served by the DC process on `smbPort` (445 by default): dialect negotiation (2.0.2/2.1), session setup carrying SPNEGO/NTLMSSP verified by the same authenticator SAMR and LSAD use, SMB2 signing (HMAC-SHA256 over the exported session key, including the key-exchange RC4 step), tree connect to `IPC$`, and create/write/read/close on `\pipe\samr`, `\pipe\lsarpc`, `\pipe\netlogon` and `\pipe\epmapper`. Each pipe is a headless channel into that interface's own `RpcServer`, so bind negotiation, dispatch and faults are the TCP endpoint's code; the authenticated SMB session's principal authorises the calls, as on Windows. `\\dc\SYSVOL` maps to the directory holding the domain folder (as `%SystemRoot%\SYSVOL\sysvol` does) and `\\dc\NETLOGON` to that domain's `scripts`; both are read-only and only exist for an authenticated session. A disk share serves create, positional read, `QUERY_DIRECTORY` (`FILE_DIRECTORY_INFORMATION`, `…FULL…`, `…BOTH…`, `FILE_NAMES` and the ID variants, `.`/`..` included, drained across calls to `STATUS_NO_MORE_FILES`), `QUERY_INFO` (basic, standard, internal, EA, access, position, mode, all, network-open, ID and the filesystem volume/size/full-size/attribute classes) and close, resolves each path component case-insensitively inside the share root, refuses `..` instead of normalising it, and answers every write, set-info and delete with `STATUS_ACCESS_DENIED` | `engine/Smb2.{h,cpp}`, `engine/Rpc.{h,cpp}` (`RpcServer::Channel`), `engine/DcService.cpp` | `monarchy-smb-tests` (7 cases) pins negotiation, the tree connect, pipe open/close, a full DCE/RPC bind carried through a pipe, and the SYSVOL share: an anonymous connect refused, an authenticated one answered as a read-only disk share, a GPO file read at an offset, a directory listing parsed and drained, and write plus delete-on-close refused. Live against a provisioned DC: impacket over `ncacn_np` on `\pipe\samr` enumerates the domain and on `\pipe\lsarpc` opens the policy and reads the account domain (status 0), and Samba's `smbclient` authenticates with NTLMSSP, lists SYSVOL recursively, fetches a policy's `registry.pol` that matches the file on disk byte for byte, is refused `ACCESS_DENIED` on a write, refused on a `..` path, and refused a share for an unauthenticated session |
| **SMB1 disk shares** (NT LM 0.12): `\\dc\SYSVOL` and `\\dc\NETLOGON` over the dialect Windows 2000 speaks — authenticated tree connect, `NT_CREATE_ANDX` by case-insensitive path (the client's `NameLength` may include the UTF-16 terminator), positional `READ_ANDX`, `TRANS2 QUERY_FILE_INFORMATION` and `QUERY_PATH_INFORMATION` for basic, standard and all information (a 2000 client asks by file id before it reads), and close; unauthenticated sessions are refused and every write, mkdir, delete and set-info is answered with access denied | `engine/Smb1.{h,cpp}`, `engine/SmbPaths.h` | `monarchy-smb1-tests` (8 cases); live, Samba's `smbclient -m NT1` fetches a GPO's `GPT.INI` and a NETLOGON logon script byte for byte, and an anonymous session is refused with logon failure |
| **Endpoint mapper** (`ncacn_epm`, `e1af8308-5d1f-11c9-91a4-08002b14a0fa` v3.0) served on `epmPort` (135 by default): `ept_lookup` with the all-elements, by-interface and paging inquiries, `ept_map`, `ept_lookup_handle_free`, and the management opnums refused with `EPMAPPER_STATUS_CANT_PERFORM_OP`. Every answer is built from the ports the endpoints actually bound, so a discovered port is always one that accepts a connection, and the tower is encoded the way C706 appendix L defines it — five floors, little-endian lengths, big-endian TCP port and IPv4 address — rather than by NDR. Each interface is advertised twice: an `ncacn_ip_tcp` tower and an `ncacn_np` tower naming its pipe, and `ept_map` answers with the transport the caller asked for rather than the first entry that matched the UUID | `engine/Epm.{h,cpp}`, `ui/src/mainwindow.cpp`, `engine/Provisioner.cpp` | `monarchy-epm-tests` (9 cases) pins the tower's five floors and byte order, the lookup reply layout against the bytes impacket's own marshaller produces, both handle marshallings a client may use, paging, `ept_map` against a captured impacket request, and the refusals.Live: `hept_lookup` returns `lsarpc → ncacn_ip_tcp:127.0.0.1[1036]`,
`samr → …[1035]`, `epmapper → …[1135]`, and `hept_map` resolves the same towers |
| **Deletion tombstones**: `removeObject` keeps the deleted object instead of erasing it — `isDeleted` TRUE, `whenChanged` stamped, a fresh `uSNChanged` so the deletion sorts after everything a cursor has passed, the surviving attributes limited to `objectGUID`, `objectSid` and `whenCreated`, and the RDN mangled to `<rdn>\0ADEL:<guid>` so the original name is free for a new object. LDAP keeps hiding them (`objects()` is unchanged); the DCSync export now carries them with ATTRTYP `0x00090003` (BOOLEAN, one byte) and `0x00020003` (`whenChanged` as a FILETIME), so a partner learns about the deletion instead of silently keeping a stale object, and DRS orders objects by the store's own `uSNChanged` rather than a derived hash. Tombstone lifetime and garbage collection are not implemented, and tombstones live in memory with the rest of the store | `engine/LdapServer.{h,cpp}`, `engine/Drs.cpp`, `engine/DcService.cpp` | `deletedObjectsReplicateAsTombstones` in `monarchy-drs-tests` (the tombstone in the store, then the same deletion read back out of the DRS chain: isDeleted, whenChanged, stripped description and account name, retained GUID) |
| **Replication apply path**: `LdapServer::applyReplication` takes one cycle's objects — the same list `DsGetNCChanges` exports, tombstones included — and converges a second store: a live object is created, or updated in place when matched by `objectGUID` (DN as the fallback), an `isDeleted` entry removes the local copy and is kept as a tombstone, a second application of the same cycle changes nothing, and a stale live copy of an already-deleted object is refused rather than resurrected (AD requires the recycle-bin operation for that). The root DSE is derived and never applied. The network half is `engine/DrsClient.{h,cpp}`: it binds a peer's DRSUAPI endpoint over `ncacn_ip_tcp`, runs `DsBind`/`DsGetNCChanges`, decodes the V6 chain into the same object list and feeds `applyReplication`, chunking while `fMoreData` is set. `engine/ReplicationAgent.{h,cpp}` is the DRA half: given a partner in `dc.conf` (`replicaHost`, `replicaPort`, `replicaDomain`, `replicaUser`, `replicaNamingContext`, `replicaIntervalSeconds`, with the password taken from `private/secrets.json` — the owner-only file that also holds the administrator verifier — and an inline `replicaPassword` still accepted but reported as misplaced) the daemon pulls on that schedule and applies each cycle to its own store, with a cursor that moves only over changes the store has taken. `DsReplicaAdd` (opnum 5) registers a source for this NC and announces it, so the daemon's agent pulls from a link that was either configured in `dc.conf` or registered over the wire, `DsReplicaDel` (opnum 6) retires it again by address, `DsReplicaMod` (opnum 7) changes a link's address, replica flags or schedule in place, `DsReplicaGetInfo` (opnum 19) answers the NEIGHBORS view with the registered link's naming context, source DSA DN and GUID, address and replica flags, and the client authenticates with NTLMSSP — a signed, sealed session at privacy level — when given a password, refusing a wrong one at the first call, and finds a partner's dynamic port through the endpoint mapper; Kerberos as the initiator is still missing (D7) | `engine/LdapServer.{h,cpp}` | `monarchy-replication-tests` (4 cases: creation from another store, deletion carried as a tombstone, idempotence, and no resurrection from a stale live copy) |
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
SID; `DsReplicaSync` (opnum 2) and `DsUpdateRefs` (opnum 4) are answered as the
lifecycle calls a cycle makes. `DsCrackNames` translates FQDN, canonical, NT4 (with and
without the domain), UPN, display name, GUID, SID and DNS-domain forms
against the same directory, and `DsGetDomainControllerInfo` (levels 1/2/3
plus the connection arm) describes this DC — level 2 carrying the NTDS
Settings GUID a DCSync client pulls with. Password material (`unicodePwd`,
`supplementalCredentials`) is deliberately not served: replication-level
conformance, not secret export. | `engine/Drs.{h,cpp}`,
`ui/src/mainwindow.cpp` (listen + endpoint-mapper entry) |
`monarchy-drs-tests` (6 cases: the bind extensions, a whole V6 reply walked
field by field — every object, its attribute list and its values — level-2
DC info pinned, FQDN→canonical pinned, a deleted object read back as a
tombstone, and the refusals); live,
`scripts/drs-conformance.py` drives the DCSync-shaped sequence over
impacket's independent NDR implementation against the DC process's own
endpoint behind an authenticated NTLMSSP bind at `PKT_PRIVACY` — the same
authenticator path SAMR and LSAD use (6 checks, non-zero exit on any
failure) |

## 2. Not implemented — not claimed, not stubbed

- **SAMR beyond the calls above**: `SamrSetInformationDomain` beyond classes 1
  and 12 (the general and logon information classes are reported but not
  settable over RPC, and there is no fine-grained password policy — a PSO on a
  user or group — so the domain policy is the only one applied);
  `SamrSetInformationGroup` classes 1–3 and
  `SamrSetInformationAlias` classes 1–2 (renaming a group or alias and setting
  its SE_GROUP_* attribute set have no directory attribute behind them, so they
  are refused rather than accepted and dropped); and writing to `BUILTIN`: the
  domain (S-1-5-32) is enumerated, its sixteen well-known aliases can be opened,
  queried and have their members read, but a create, delete, rename or member
  change there returns `STATUS_NOT_SUPPORTED`, because AD keeps that domain in a
  naming context of its own and this server derives it from the SID table Lsad
  already resolves rather than storing it.
- **LSAD trusted domains beyond the object and its secret**: the trust, its
  SID, direction, names and the inter-realm keys derived from its clear secret
  are stored, reported and rewritable, but a trust still is not a working
  secure channel: `LsarQueryForestTrustInfo` has nothing to return, the
  the internal-encryption query levels are refused with
  `STATUS_INVALID_INFO_CLASS` rather than guessed at, nothing rolls the password
  automatically the way a DC does every 30 days, and no Windows or Samba DC has
  been driven through
  establishing a trust against this endpoint. Authentication through a trust
  therefore rests on the keys and the partner's own trust, not on a channel
  this DC has proved. `LsarSetInformationPolicy`
  sets the modification time and the audit-full flag and refuses the rest (the
  domain name and SID are reported, not settable), as does
  `LsarSetDomainInformationPolicy` (the Kerberos lifetimes are reported, not
  settable). `LsarCreateAccount` answers `STATUS_NOT_SUPPORTED`: MS-LSAD 3.1.4.5.1
  has accounts created through SAMR.
- **LSAD state that is not part of the store**: LSA secrets and private data live
  in the serving process (they are not persisted, and nothing encrypts them at
  rest), and the per-account system-access mask is per handle rather than
  written to the directory.
- **DRSR link schedules**: `DsReplicaMod` (opnum 7) changes a registered
  link's address, replica flags and schedule, and the schedule now gates the
  pull: a link whose flags carry `DRSUAPI_DRS_PER_SYNC` is pulled only inside the
  15-minute slots its `REPLTIMES` sets (Sunday 00:00 UTC first, most significant
  bit first, re-checked at least daily), while a link without that flag keeps
  `replicaIntervalSeconds`. `DsReplicaGetInfo` NEIGHBORS has no schedule member
  in MS-DRSR, so the schedule cannot be read back over the wire, and no per-link
  sync history is kept: that reply's USNs, timestamps and failure counters are
  zero because they are unmeasured, not because a sync succeeded. `DsReplicaDel` with
  `DRS_NO_SOURCE` (which expunges a whole NC) is
  refused, and the `UpdateRefs` notification AD sends to the peer on removal is
  not sent. A source added at level 1 of `DsReplicaAdd` carries no source DSA
  GUID, so `DsReplicaMod` matches that link by address.
- **Netlogon beyond the calls above**: no Windows or Samba member has been
  driven through a domain join against this endpoint in this tree, so the
  client half is proven by `monarchy-netlogon-tests` rather than by a real
  join. Netlogon RPC security (`NETLOGON_NEG_AUTHENTICATED_RPC` / schannel at
  the DCE/RPC layer) is not implemented, so the trust channel a partner's DC
  would open (`NetrServerAuthenticate3` against the trust account, then
  `NetrSetTrustedDomainAuthInfo`) is not served; a partner can authenticate its
  trust channel and read the trust account's RID.
- **SMB beyond the pipe transport**: SMB2 dialects 2.0.2 and 2.1 only (no SMB
  3.x, so no preauth integrity, no encryption, no multi-channel). SMB1 is
  answered for NT LM 0.12 (`engine/Smb1.{h,cpp}`): negotiate, extended session
  setup with NTLMSSP in SPNEGO, tree connect to `IPC$`, NT create on a pipe,
  and write/read/transact over it, which is the transport a Windows 2000
  workstation needs for a domain join. SMB1 signing is not implemented (the
  server answers `SecurityMode` without the signature bits), so a client whose
  policy makes signing mandatory, such as Samba's default client, is refused.
  SMB1 also serves the disk shares (`SYSVOL`, `NETLOGON`) the way SMB2 does:
  authenticated tree connect, case-insensitive path resolution, positional
  reads and the TRANS2 query a client makes before reading, with every write,
  mkdir, rename, delete and set-info refused. SMB1 has no directory
  enumeration (`TRANS2 FIND_FIRST2`), so a client can fetch a file it names but
  cannot list a directory; GPO and logon-script delivery only reads named
  paths, so both work. The disk shares are read-only on either dialect: a GPO
  is delivered but not edited over SMB.
  `smbPort` defaults to 445, which needs `CAP_NET_BIND_SERVICE` or root like the
  endpoint mapper.
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
2. ~~SAMR writes~~ — create/delete user, group and alias, members in both, every
   information class including the aggregate 21/23/25 writes and the logon
   week, the domain password and lockout policies, the `BUILTIN` domain with
   its sixteen well-known aliases. Remaining   here: the general and logon
   information classes, fine-grained (per-user) password policies, the minimum
   password age, and writing to `BUILTIN`.
3. ~~Endpoint mapper~~ — `ept_lookup`/`ept_map` answer on `epmPort`, so a client
   can now discover a port instead of being told one.
4. ~~SMB2 server + named pipes + SYSVOL/NETLOGON shares~~ — `\\dc\pipe\samr`,
   `\pipe\lsarpc`, `\pipe\netlogon` and `\pipe\epmapper` carry DCE/RPC into the
   same endpoints the TCP ports serve, and `\\dc\SYSVOL` / `\\dc\NETLOGON` serve
   the domain's GPOs and logon scripts read-only to authenticated sessions. The
   remaining work here is SMB 3.x (encryption, preauth) and write access.
5. ~~LSAD~~ — the policy calls, both translation directions, account rights,
   privileges, secrets and the policy security descriptor, verified against
   Samba's reference NDR decoder and impacket by `scripts/lsad-conformance.py`.
   Remaining here: trust-password rotation and the Netlogon trust channel.
6. ~~Netlogon~~ — secure channel, machine-password write, SamLogon validation
   and the DC locator are served and verified (§1). Remaining here: a real
   member's join flow, RPC-layer schannel, and trust creation over the channel.
7. ~~DRSR~~ — `DsBind`/`DsGetNCChanges`/`DsReplicaSync` plus `DsCrackNames`
   and `DsGetDomainControllerInfo` are served and verified (§1). A pull side now exists — `ReplicationAgent` takes a partner from
   `dc.conf` or a wire `DsReplicaAdd` on a timer and applies what it fetches —
   so what remains is the KCC's topology, and proving the path against Samba or
   Windows peers, which is what makes a domain a domain rather than one server.

After those: GPO/SYSVOL over SMB, FSMO, sites and the KCC, interdomain trust
replication, WINS-era name resolution if 2000 parity is taken literally, and the
schema/LDF import path. Each block is landed the way SAMR was: against the
IDL in `reference/specs/`, driven by an independent client, with the CI suite
(`scripts/ci.sh`, which `.github/workflows/ci.yml` runs) extended in the same
change.

## 4. Security posture

Development directory service, not a hardened DC. LDAP is plaintext unless the
client asks for StartTLS (there is no dedicated LDAPS port, and no client
certificate is requested), and an unbound session may read only the root DSE:
a search with a non-empty base answers `insufficientAccessRights(50)`, a failed
bind leaves the connection anonymous, and StartTLS resets it (RFC 4511 §4.14.1).
DNS updates have no TSIG or ACL, and RPC has no
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
