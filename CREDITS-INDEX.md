# Monarchy — Credits & Provenance Index

> **Purpose.** One place that answers "whose code or design is in here, under what
> terms, and where is the boundary?" for every file shipped by this repository.
>
> **Audit date:** 2026-10-20 · **Scope:** all of `backend/`, `engine/`, `ui/`,
> `scripts/`, `reference/`, the build files and the bundled resources
> (27 source files, 6,687 lines of C++). · **Method:** file inventory,
> attribution-header scan, build-file dependency read, and a source-level review
> of every module. Companion to
> [`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md)
> (patent/licence position) and [`AD-IMPLEMENTATION-BLUEPRINT.md`](AD-IMPLEMENTATION-BLUEPRINT.md)
> (the 13 reference trees and the module licence matrix in §C.9).
>
> **Not legal advice.** The licence names below were read from the licence files in
> the local reference trees or from the upstream project; obligations attached to
> redistribution must be confirmed by counsel before a release.

**Status key**

| Status | Meaning |
|---|---|
| **LINKED** | A build-time or run-time dependency: the code is used as a library, not copied. |
| **REFERENCE** | Studied for behaviour, data names or layout. **No source was copied.** |
| **PLANNED** | Named in the roadmap as a future source of derived code; nothing used yet. |
| **ORIGINAL** | Written for Monarchy; no upstream origin. |

---

## 0. Summary

| Category | What is actually in this repository |
|---|---|
| **Application, backend and engine C++** | **ORIGINAL.** No third-party source files, headers, licence notices or copied functions were found. Every module was written against published specifications and reference behaviour. |
| **Build-time code** | Qt 6 (LGPL-3.0), CMake (BSD-3-Clause), optionally OpenLDAP `libldap`/`liblber` (OpenLDAP Public License 2.8) and Cyrus SASL `libsasl2` (BSD-style). |
| **Behaviour / data-name references** | Samba 4.24.7 (GPL-3.0), OpenLDAP 2.6/2.7 (OPL-2.8), OpenRSAT 0.4.519 (GPL-3.0). Reference only. |
| **Specifications** | RFC 4511/4512/4514/4517, RFC 1034/1035/2782/2136, RFC 4120/3961/4757/4178, RFC 2104/1320, MS-ADTS, MS-ADSC, MS-ADA1–3, MS-NLMP. |
| **Artwork, stylesheet, icons** | **ORIGINAL.** Icons are drawn at run time with `QPainter`; the QSS is hand-written. No Microsoft or third-party image is bundled. |
| **Fonts** | None bundled. Optional Selawik lookup (SIL OFL-1.1); falls back to system DejaVu Sans. |
| **Reference images** | `reference/IMAGE-URL-INDEX.tsv` stores **URLs only** (1,971 rows). No image is downloaded or redistributed. |

**Bottom line:** this tree contains no GPL-derived source. The GPL-3.0 projects in
§2 are design references. No Samba code, library, package or process is used:
provisioning is implemented in `engine/Provisioner.cpp`, and
`scripts/provision-monarchy.sh` merely runs the built `monarchy-provision` binary.

---

## 1. Directly used code (LINKED)

| Project | Used for | Licence | Linkage | Notes / obligations |
|---|---|---|---|---|
| **Qt 6** (6.5+) — <https://www.qt.io/> | Application framework: `Widgets`, `Core`, `Gui`, `PrintSupport`, `Concurrent`, `Network`, `Test` | **LGPL-3.0** (or GPL-3.0 / commercial) | Shared libraries, dynamically linked | Dynamic linking under LGPL-3.0; keep the ability to relink, ship the licence text, and state Qt use. No Qt source is modified or bundled. |
| **OpenLDAP client** — `libldap`, `liblber` | Real LDAP backend when `-DMONARCHY_WITH_LDAP=ON` | **OpenLDAP Public License 2.8** | Dynamically linked, optional | Per-file copyright notices must be retained on redistribution of the library; this project only links it. Used by `backend/ConnectionService.cpp`, `backend/DirectoryService.cpp`. |
| **Cyrus SASL** — `libsasl2` | SASL/GSSAPI support pulled in by OpenLDAP | **BSD-style (CMU)** | Dynamically linked when present, optional | Linked only if `find_library(SASL2_LIBRARY)` succeeds. |
| **MIT krb5** — `libkrb5`, `libgssapi_krb5` | Independent Kerberos client in `monarchy-kerberos-tests` (the equivalent of `kinit` + GSS-API) to drive the KDC and the SASL bind | **MIT** | Dynamically linked, test executable only, optional | Detected by `find_library` in `ui/CMakeLists.txt`; the engine and the application never link it. If absent, those tests are not compiled and the rest of the suite still builds. |
| **CMake** (3.16+) — <https://cmake.org/> | Build system | **BSD-3-Clause** | Build-time only | Not part of the shipped binary. |
| **C++17 standard library / compiler runtime** | Language and runtime | Toolchain-specific | — | No attribution requirement beyond the toolchain's own. |

No other library is linked. The default build (`MONARCHY_WITH_LDAP=OFF`) needs only Qt 6.

---

## 2. Project register — what each reference project contributed

The 13 trees analysed in `AD-IMPLEMENTATION-BLUEPRINT.md` live **outside** this
repository, in separate source checkouts. Their version numbers are pinned in
that document; this table records what each one means *for this codebase*.

| # | Project | Version reviewed | Licence | Status here | Contribution to Monarchy |
|---|---|---|---|---|---|
| 1 | **Samba** (AD DC) | 4.24.7 | GPL-3.0 | **REFERENCE** (engine behaviour), **PLANNED** (protocol engine) | AD object model, container layout, `sAMAccountName`/`userAccountControl` conventions, DNS zone shape, provision object set and RID conventions. Also the Phase-A engine in `AD-FULL-IMPLEMENTATION-PLAN.md`. No Samba source is present and none is executed: provisioning is native. |
| 2 | **OpenLDAP** | 2.6.13 / 2.6.15 / 2.7.1 | OpenLDAP Public License 2.8 | **LINKED** (client lib), **REFERENCE** (server semantics) | LDAP filter/scope behaviour, result codes, attribute handling; the wire client speaks to it directly. |
| 3 | **MIT krb5** | 1.22.1 / 1.22.2 | MIT | **REFERENCE** (RFC 4120 message shapes, pre-auth and error encoding), **LINKED** (interop test client only) | The KDC is Monarchy's own Qt/C++ code (`engine/Kdc.cpp`); MIT krb5 supplies the independent client that proves it interoperates. No MIT source is present and the engine links no Kerberos library. |
| 4 | **Cyrus SASL** | 2.1.28 | BSD-style (CMU) | **LINKED** (transitive, optional) | Provides GSSAPI/SPNEGO to the OpenLDAP client build. |
| 5 | **Heimdal** | 7.8.0 | BSD-3-Clause | **PLANNED** | Reference for a future KDC; not used. |
| 6 | **FreeIPA** | 4.13.4 | GPL-3.0 | **REFERENCE** | Comparison point for an integrated Linux IAM stack; no code. |
| 7 | **389-ds** | 3.3.1 | GPL-3.0+ (OpenSSL linking exception) with MIT portions | **REFERENCE** | LDAP server design comparison (replication, memberof); no code. |
| 8 | **SSSD** | 2.13.1 | GPL-3.0+ | **REFERENCE** | Client-side AD integration behaviour; no code. |
| 9 | **Kanidm** | 1.11.2 | MPL-2.0 | **REFERENCE** | Lightweight IDM design comparison; no code. |
| 10 | **LLDAP** | 0.6.3 | GPL-3.0 | **REFERENCE** | Minimal LDAP server design comparison; no code. |
| 11 | **glauth** | 2.5.4 | MIT | **REFERENCE** | Config-driven LDAP server comparison; no code. |
| 12 | **Apache Directory Server** | 2.0.0-M11 | Apache-2.0 | **REFERENCE** | LDAP schema/engine comparison; no code. |
| 13 | **OpenRSAT** | 0.4.519 | GPL-3.0 | **REFERENCE** (console design) | The console's visual/workflow reference — tree + results pane, property tabs, AD management verbs. The Qt implementation is original; no Pascal code was ported. |

---

## 3. Behavioural derivation map (what was "hybridized")

These rows record where a module's behaviour came from. **No row copies source.**

| Monarchy area | Files | Derived from | What was carried over |
|---|---|---|---|
| LDAP wire client (BER encode/decode, bind, search, modify, add, delete) | `backend/LdapClient.cpp` | RFC 4511/4515; OpenLDAP client behaviour | Message shapes, attribute value handling, result-code mapping, filter-string parsing and BER filter encoding. Hand-written BER codec. |
| LDAP server (parser, scopes, filters, root DSE, persistence) | `engine/LdapServer.cpp` | RFC 4511/4512/4514/4515; OpenLDAP `slapd` behaviour; Samba `ldap_server/` | Scope boundaries, AND/OR/NOT and substring filter semantics, root-DSE attributes, AD-style attribute names, linked `member`/`memberOf` maintenance (MS-ADTS §3.1.1.5), and `unicodePwd` policy/verifier handling. |
| Directory object mapping, writable-attribute filtering | `backend/DirectoryService.cpp` | MS-ADTS; Samba `dsdb`; ADUC columns | Which attributes are user-writable, container assignment for users/groups/computers/OUs, DN construction. |
| Create/reset operations | `backend/AdminService.cpp` | ADUC workflows; `samba-tool` conventions | Required attributes per object class (`sAMAccountName`, `userAccountControl` 512, `groupType`, `dNSHostName`). |
| NTLMSSP / NTLMv2 authentication | `engine/Ntlm.cpp` | MS-NLMP §3.1.5 (NTOWFv1, NTLMv2 response), RFC 2104 (HMAC), RFC 1320 (MD4) | Message layout (NEGOTIATE/CHALLENGE/AUTHENTICATE), NTLMv2 response-key derivation and proof computation, TargetInfo AV pairs. Written from the specification; no code copied. |
| Kerberos KDC (AS/TGS, pre-authentication, tickets, AP-REQ/AP-REP) | `engine/Kdc.cpp`, `engine/Krb5.cpp`, `engine/Asn1.cpp` | RFC 4120 (message formats, `KDCOptions`, error codes), RFC 3961/4757 (RC4-HMAC string-to-key and encryption), RFC 3962 (AES string-to-key, CTS, HMAC-SHA1-96), RFC 4121 (CFX tokens), RFC 4178 (SPNEGO); MIT krb5 client behaviour | AS-REQ/TGS-REQ field layout, PA-ENC-TIMESTAMP pre-authentication with etype-info2 salt hints, EncTicketPart/EncASRepPart/EncTGSRepPart encryption usages (RC4-HMAC key usages 1/2/8, and 12 for the AP-REP), Authenticator checks for TGS (usage 7) and AP-REQ (usage 11), AP-REP mutual authentication and the GSS-API token framing a SASL client emits. Hand-written DER codec; ticket and error shapes were confirmed byte-for-byte against MIT krb5 (including the RFC 4120 `KRB-ERROR` optional fields). No code copied. |
| Privilege Attribute Certificate | `engine/Pac.cpp`, `engine/Pac.h` | MS-PAC §2.3–2.8, 2.11 | PACTYPE/PAC_INFO_BUFFER layout, KERB_VALIDATION_INFO fixed fields and offset patching, PAC_CLIENT_INFO, PAC_UPN_DNS_INFO, AD-IF-RELEVANT { AD-WIN2K-PAC } authorization-data, server and KDC checksums over the zeroed PAC (key usage 17), the RID/SID encoding, and the group RIDs the directory authorizes writes from. Verified against MIT's `krb5_pac_verify` and `krb5_pac_get_buffer`. No code copied. |
| SASL GSSAPI / GSS-SPNEGO bind and security layers | `engine/LdapServer.cpp` | RFC 4752/4422 (SASL), RFC 4757 §7 (RC4 GSS sealing), RFC 1964 (legacy token format), RFC 4121 (CFX Wrap tokens), RFC 4178 (SPNEGO); MS-ADTS LDAP SASL behaviour | Bind stage machine (client token → AP-REP → security-layer negotiation → success), SPNEGO wrapper around the Kerberos OID, the three-layer offer, and the per-message wrap tokens in both formats: confounder/padding, sequence-number and checksum derivation, direction key usages (22/24) and the length-prefixed SASL buffer framing. Tokens are checked against MIT's `gss_wrap`/`gss_unwrap`. |
| DNS zone and dynamic update | `engine/DnsServer.cpp` | RFC 1034/1035/2782/2136; Samba `dns_server/`, MS-ADTS §6.1.1.2 | Full DC locator record set (`_ldap._tcp` for domain/`dc._msdcs`/site-`_sites._msdcs`, `_kerberos`, `_kpasswd`, `_gc`, PDC), SOA serialing, UPDATE prerequisites and update classes with their result codes. Wire formats are hand-written; no code copied. |
| Domain provisioning | `engine/Provisioner.cpp` | MS-ADTS naming contexts; Samba `provision.py` object set | Which objects a new domain starts with, default containers, well-known RID allocation (500/502/512/513/515/516/518-520), DC computer object shape, `dc.conf`/SYSVOL layout, initial DNS zone, and the two default GPOs with their `gPLink`/`gPCFileSysPath`/`GPT.INI` conventions. No code copied; the provisioner is written against the object model. |
| Console layout, navigation, view modes, CSV export | `ui/src/consoleview.cpp`, `ui/src/mainwindow.cpp`, `ui/src/resultsmodel.cpp` | MMC 3.0 / ADUC (layout); OpenRSAT (workflow) | Tree + results-pane split, Details/Large Icons/Small Icons/List, Back/Forward/Up, filter, column sorting. Original Qt widgets. |
| Property sheets | `ui/src/propertysheet.cpp` | ADUC property tabs | Tab order and field set (General, Address, Account, Profile, Organization, Member Of, Object, Attribute Editor). Original widgets. |
| Icons and palette | `ui/src/objecticons.cpp`, `ui/resources/styles/mmc.qss` | Classic MMC palette (`#ece9d8`) | Colour values and icon *style* only; shapes are original `QPainter` paths. |
| Sample directory | `backend/SampleData.cpp` | ADUC demo data shape | Object names/types only; fictional content. |

If a future change copies actual code from any of these projects, move the row to
§4 and follow the recording rules in §8.

---

## 4. Copied / adapted code register

**Currently empty.** No file in this repository contains code copied or adapted
from another project.

| File | Upstream project | Version / commit | Licence | What changed |
|---|---|---|---|---|
| *(none)* | — | — | — | — |

This table is the only place where derived code may be declared. A row here also
requires the upstream copyright header to be kept in the file and the licence
text to be added to `LICENSES/`.

---

## 5. Specifications implemented

Specifications are not code and carry no copyright in their *rules*; the documents
themselves are cited for provenance of behaviour.

| Area | Specification | Where implemented |
|---|---|---|
| LDAP v3 protocol | [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511) | `backend/LdapClient.cpp`, `engine/LdapServer.cpp` |
| LDAP naming, schema, matching rules | [RFC 4512](https://www.rfc-editor.org/rfc/rfc4512), [RFC 4514](https://www.rfc-editor.org/rfc/rfc4514), [RFC 4517](https://www.rfc-editor.org/rfc/rfc4517) | `engine/LdapServer.cpp`, `backend/DirectoryService.cpp` |
| AD data model and LDAP behaviour | [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) | attribute semantics, naming contexts, root DSE |
| AD schema classes / attributes | [MS-ADSC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/), MS-ADA1–3 | `objectClass` values and attribute names throughout |
| AD protocol map | [MS-ADOD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adod/) | scope decisions in the planning documents |
| DNS | [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034), [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035), [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782), [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136) | `engine/DnsServer.cpp` |
| Kerberos v5 | [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) | `engine/Kdc.cpp`, `engine/Krb5.cpp` |
| Kerberos cryptography (RC4-HMAC) | [RFC 3961](https://www.rfc-editor.org/rfc/rfc3961), [RFC 4757](https://www.rfc-editor.org/rfc/rfc4757) | `engine/Krb5.cpp` |
| Kerberos cryptography (AES-128/256) | [RFC 3962](https://www.rfc-editor.org/rfc/rfc3962), [RFC 3961](https://www.rfc-editor.org/rfc/rfc3961) | `engine/Aes.cpp`, `engine/Krb5.cpp` |
| Privilege Attribute Certificate | [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) | `engine/Pac.cpp` |
| GSS-API per-message tokens | [RFC 4121](https://www.rfc-editor.org/rfc/rfc4121), [RFC 1964](https://www.rfc-editor.org/rfc/rfc1964), [RFC 4757 §7](https://www.rfc-editor.org/rfc/rfc4757) | `engine/LdapServer.cpp` |
| SASL and SPNEGO | [RFC 4422](https://www.rfc-editor.org/rfc/rfc4422), [RFC 4752](https://www.rfc-editor.org/rfc/rfc4752), [RFC 4178](https://www.rfc-editor.org/rfc/rfc4178) | `engine/LdapServer.cpp` |
| HMAC and MD4 (NTLM/NTOWFv1) | [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104), [RFC 1320](https://www.rfc-editor.org/rfc/rfc1320), [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/) | `engine/Ntlm.cpp` |
| NTLM session security (§3.4) | [MS-NLMP §3.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/) §3.4.4–3.4.5 | `engine/Ntlm.cpp`, `engine/LdapServer.cpp` — exported session key, per-direction signing/sealing keys, MAC, stateful RC4 and signed/sealed LDAP sessions; key and token bytes cross-checked against impacket's independent implementation |
| SAMR / LSAD / DRSR / Netlogon wire formats | Samba `librpc/idl/{samr,lsa,drsuapi,netlogon,security}.idl` (GPL-3.0-or-later), held in `reference/specs/`; impacket `dcerpc/v5/{samr,lsad}.py` (Apache-2.0) as an independent client oracle | `engine/Samr.cpp`, `engine/Rpc.cpp`, `engine/Ndr.cpp` |
| DCE/RPC and NDR framing | [MS-RPCE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/), DCE 1.1 RPC | `engine/Rpc.cpp`, `engine/Ndr.cpp` |
| Endpoint mapper (port 135) | [DCE 1.1 RPC ch. 6, appx L/O](https://pubs.opengroup.org/onlinepubs/9629399/chap6.htm); Samba `librpc/idl/epmapper.idl` (GPL-3.0-or-later) and impacket `dcerpc/v5/epm.py` (Apache-2.0), held in `reference/specs/` | Not implemented — the references are held so the port-135 gap in [`STATUS.md`](STATUS.md) §2 can be closed against the wire format rather than from memory |
| Cross-realm trusts | [RFC 4120 §3.3.3](https://www.rfc-editor.org/rfc/rfc4120), [MS-PAC §4.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) | `engine/Kdc.cpp` (referral tickets, inter-realm keys), `engine/Krb5.cpp` (`findTrustPrincipal`, `storeTrustKeys`) |

Patent and licensing status of the AD protocol family (OSP, Interoperability
Principles pledge, RAND, expiry) is catalogued in
[`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md).

---

## 6. Artwork, fonts and reference images

| Asset | Origin | Licence | Bundled? |
|---|---|---|---|
| Object icons (user, group, computer, OU, domain, etc.) | **Original** `QPainter` drawing in `ui/src/objecticons.cpp` | GPL-3.0-or-later | Yes — generated at run time, no image files |
| `mmc.qss` stylesheet | **Original** hand-written QSS emulating the classic MMC palette | GPL-3.0-or-later | Yes |
| **Selawik** font (`microsoft/Selawik`) | Microsoft, an open replacement for Segoe UI | **SIL OFL-1.1** | **No** — `ui/src/main.cpp` looks for `:/fonts/Selawik-*.ttf` and silently falls back; no font file is in `resources.qrc` |
| **DejaVu Sans** | DejaVu project (Bitstream Vera / Arev licences) | Permissive | **No** — used only if installed on the host |
| Reference console screenshots | Microsoft Learn documentation images, indexed in `reference/IMAGE-URL-INDEX.tsv` (repos: `MicrosoftDocs/windowsserverdocs`, `MicrosoftDocs/SupportArticles-docs`, `microsoft/win32`) | Documentation **CC BY 4.0**; code samples **MIT** (per repository `LICENSE` / `LICENSE-CODE`) | **No** — URLs only; nothing downloaded |

If an image, icon or font is ever added to `ui/resources/`, record its source,
author, licence and retrieval date in this table first.

---

## 7. Trademarks and naming

| Mark | Owner | How Monarchy uses it |
|---|---|---|
| *Active Directory*, *Active Directory Users and Computers*, *Microsoft Management Console*, *Windows* | Microsoft Corporation | **Nominative only** — to state what the software interoperates with or emulates. No Microsoft logo, icon, screenshot, `.msc` file or product name is shipped. The product is **Monarchy** — its console is the *Monarchy Management Console* — not "Active Directory". |
| *Samba* | The Samba Team | Nominative reference to a separate project. |
| *Qt* | The Qt Company | Nominative reference to the framework. |
| *OpenLDAP* | The OpenLDAP Foundation | Nominative reference to the library. |

The console deliberately reproduces MMC *layout and behaviour* using its own code
and artwork. That is design-level emulation, not a claim of affiliation or
endorsement; see `AD-CONSOLE-IMAGE-INDEX.md` §0 and
`AD-LICENSING-PATENT-CITATION-INDEX.md` §13 before shipping a look-alike build.

---

## 8. Authorship

| Contribution | Credit |
|---|---|
| Source code, tests, build files, documentation | The **Monarchy project** contributors, 2026 |
| Outbound licence | **GPL-3.0-or-later** — full text in [`LICENSE`](LICENSE), SPDX identifiers in every file |
| Reference research and specification mapping | `AD-RESEARCH-INDEX.md`, `AD-IMPLEMENTATION-BLUEPRINT.md`, `AD-1TO1-CONFORMANCE.md` and the companion planning documents in this repository |
| Drafting assistance | Portions of the implementation were drafted with AI coding assistance (Freebuff / Codebuff, 2026-10-19 → 2026-10-20) and reviewed, corrected and tested by the project. No AI-generated code is copied from a third-party repository. |

### Recording rules for future derivation

1. **Copying a file?** Keep the upstream copyright and licence header verbatim,
   add the file to §4 with project, version/tag, commit, licence and the list of
   changes, and add the licence text under `LICENSES/`.
2. **Adapting a function?** Same rule, plus a comment at the function stating the
   upstream file and commit.
3. **Studying behaviour?** Use §3; never let a REFERENCE row silently become a
   copy. If in doubt, treat it as copied.
4. **GPL-3.0 sources (Samba, OpenRSAT, 389-ds, FreeIPA, LLDAP, SSSD):** keep any
   derived code in a separate directory/library with a documented boundary. Do not
   paste it into the permissively-licensed core.
5. **Schema data:** attribute names, OIDs and object-class definitions are protocol
   facts, but the LDF *files* shipped by Samba are GPL-3.0. Importing them makes
   those data files GPL-3.0 and must be recorded in §4.

---

## 9. Audit evidence

Checks run on 2026-10-20 against this working tree:

| Check | Result |
|---|---|
| Attribution-header scan (`grep -rniE` for copyright, licence, derived, adapted, ported, Samba, OpenLDAP) over `ui/`, `backend/`, `engine/`, the build files and `scripts/` | No third-party attribution headers or copied notices. Matches are the project's own comments plus the `MONARCHY_WITH_LDAP`/`MONARCHY_WITH_SAMBA` option names. |
| File inventory of the repository (excluding build directories) | 31 source files across `backend/`, `engine/`, `ui/src/` and `ui/tests/`, all authored for Monarchy; no vendored source tree. |
| `ui/resources/resources.qrc` | References only `styles/mmc.qss`; no images or fonts bundled. |
| SPDX identifiers | `SPDX-License-Identifier: GPL-3.0-or-later` on all 31 sources, both CMake files, the QSS, the QRC and `scripts/provision-monarchy.sh` (35 files), matching [`LICENSE`](LICENSE). |
| `ui/src/objecticons.cpp` | Icons constructed from `QPainterPath`/`QPainter` calls at run time. |
| Upstream-identifier scan (`tevent`, `slapd`, `dom_sid`, `ldb_`, `ndr_`, `talloc`, `GPL`) | No hits. The only upstream identifiers are OpenLDAP's public API types (`berval`, `ldap_get_values_len`) inside `#ifdef MONARCHY_WITH_LDAP` blocks — ordinary library use, not ported code. |
| `CMakeLists.txt`, `ui/CMakeLists.txt` | Dependencies limited to Qt 6 and, optionally, `ldap`/`lber`/`sasl2`; `krb5`/`gssapi_krb5` are linked into the Kerberos test executable only. |
| `scripts/provision-monarchy.sh` | Runs the built `monarchy-provision` (found via `MONARCHY_PROVISION_BIN`, the build directory, or `PATH`); no Samba, no external provisioner, no hard-coded path. |

**Known gaps in this index**

- The reference trees live outside the repository, so the versions in §2 are
  pinned from the blueprint rather than from a submodule lock file.
- The Microsoft reference-image index records repository-level licences; per-image
  terms were not verified because no image is redistributed.
