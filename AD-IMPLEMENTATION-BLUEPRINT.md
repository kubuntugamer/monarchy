# Monarchy Implementation Blueprint
## Mapping every AD specification to the best available source code, and how to modularize it

**Companion to:** [`AD-RESEARCH-INDEX.md`](AD-RESEARCH-INDEX.md) (Part 1 = AD/MS specs, Part 2 = Linux-AD projects, Parts 3–4 = local trees & upstream comparison, §4.6–4.7 = acquisition record).

**Date:** 2026-10-19 · **Method:** read-only source analysis of all 13 project trees in the research checkout (`ADclone/`), mapped against the Microsoft Open Specifications listed in the index (Part 1.2). Every path cited below was verified to exist in the local trees.

**Maturity legend used throughout:** ✅ complete · 🟡 partial · ❌ absent (or client-only/reference-only).

**The 13 trees analysed**

| # | Project | Local tree | License |
|---|---|---|---|
| 1 | Samba (AD DC) | `samba-4.24.7/` | GPL-3.0 |
| 2 | OpenLDAP | `openldap-2.6.15/`, `openldap-2.7.1/` | OpenLDAP Public License 2.8 |
| 3 | MIT krb5 | `krb5-1.22.2/` | MIT |
| 4 | Cyrus SASL | `cyrus-sasl2-2.1.28+dfsg1/` | BSD-style (CMU) |
| 5 | Heimdal | `heimdal-7.8.0/` | BSD-3-Clause |
| 6 | FreeIPA | `freeipa-4.13.4/` | GPL-3.0 |
| 7 | 389-ds | `389-ds-base-3.3.1/` | GPL-3.0+/MPL-2.0/MIT mix |
| 8 | SSSD | `sssd-2.13.1/` | GPL-3.0+ |
| 9 | Kanidm | `kanidm-1.11.2/` | MPL-2.0 |
| 10 | LLDAP | `lldap-0.6.3/` | GPL-3.0-only |
| 11 | glauth | `glauth-GLAuth-v2.5.4/` | MIT |
| 12 | Apache Directory Server | `apacheds-parent-2.0.0-M11/` | Apache-2.0 |
| 13 | OpenRSAT | `OpenRSAT-0.4.519/` | GPL-3.0 |

> **Bottom line up front:** Samba is the *only* project that implements the AD protocols (ADTS/DRSR/SAMR/NRPC/KILE+…). Therefore the honest blueprint is **"Samba's protocol engine, re-cut into modules with stable interfaces"**, using the other 12 projects (a) as the *replacement* for specific Samba-internal subsystems where a better-maintained or differently-licensed implementation exists (LDAP storage, SASL, KDC via `--with-system-mitkrb5`), (b) as *reference implementations* for gaps, and (c) as *clients/tooling*. Part B states this explicitly per spec; Part C shows how to do it.

---

# Part A — Specification-by-specification analysis

Each entry: **what the spec requires → the best code → supporting code → gaps → verdict** (`ADOPT` = use this code, `ADAPT` = use with modification, `REFERENCE` = use as design reference only, `ABSENT` = must be written).

---

## Layer 1 — Directory data model, schema, LDAP

### A.1 [MS-DTYP] — Windows data types, SIDs, security descriptors, ACLs

**Requirement.** The foundational types every other spec builds on: `SID`, `GUID`, `OBJECT_TYPE`/`OBJECT_TYPE_LIST`, `ACCESS_MASK`, `SECURITY_DESCRIPTOR`, `ACL`/`ACE` (basic, object, callback, mandatory-label), `SDDL` grammar, well-known SIDs/privileges, group membership evaluation, conditional ACEs.

**Best code — Samba ✅**
- `libcli/security/dom_sid.c` — SID parse/format/compare, well-known SIDs, `<SID=…>` string form.
- `libcli/security/create_descriptor.c`, `libcli/security/sddl.c` — SECURITY_DESCRIPTOR construction + the full SDDL parser/serializer.
- `libcli/security/access_check.c` — the AD access-check algorithm (object/attribute grants, generic mappings, trustee/SID recursion, `MAXIMUM_ALLOWED`).
- `libcli/security/conditional_ace.c` (+ `.l`/`.y` grammar) — **conditional ACEs are implemented here and almost nowhere else in open source**.
- `libcli/security/claims-conversions.c`, `claims_transformation.l/.y` — [MS-ADTS] compound-identity claims.
- `libcli/security/privileges.c` — LSA privilege table/checks.
- `librpc/idl/security.idl` (+ `security.cnf`) — the wire types regenerated as NDR.

**Supporting.** MIT krb5: none (uses opaque SID handling for PAC only). 389-ds: stores `objectSid` as bytes, no ACL model. OpenLDAP: none. Windows/POSIX mapping glue exists in Samba (`libcli/security` + `source4/libcli/security`).

**Gaps.** Samba's conditional-ACE and claims support is complete but the *schema-side* integration (msDS-Claims-*) is newer; no independent implementation to cross-check against.

**Verdict: `ADOPT`** — this module alone justifies basing Monarchy on Samba; reimplementing SDDL + conditional ACEs would be months of work for zero gain.

---

### A.2 [MS-ADSC] / [MS-ADA1-3] — Schema classes & attributes

**Requirement.** The exact `classSchema`/`attributeSchema` definitions, syntaxes, OID mappings, `systemFlags`/`searchFlags`, `schemaIDGUID`, `linkID` for back-links, `isMemberOfPartialAttributeSet` (GC partial set), `defaultHidingValue`, index flags.

**Best code — Samba ✅ (LDIF ground truth) + Samba schema engine ✅**
- Schema data: `source4/setup/ad-schema/` — the genuine Microsoft LDF imports, per release: `Attributes_for_AD_DS__Windows_Server_2008_R2.ldf` … `AD_DS_Attributes_Windows_Server_v1903.ldf` (+ matching `Classes_*`), plus the raw `MS-AD_Schema_2K8*.txt` exports. **This is the canonical AD schema, in-tree.**
- Engine: `source4/dsdb/schema/` — `schema_init.c` (load/validate), `schema_syntax.c` (syntaxes), `schema_query.c`, `schema_set.c`, `schema_prefixmap.c` (OID prefix maps), `schema_inferiors.c` (subclass closure), `schema_info_attr.c`, `schema_filtered.c`. (Note `schema_convert_to_ol.c` — a converter to the *OpenLDAP schema format*, a ready-made bridge if the OpenLDAP engine path is ever explored.)

**Supporting.** OpenLDAP `servers/slapd/schema/msuser.schema` — a hand-written AD-compatible user/group schema, useful as a *portable* AD schema for a non-Samba directory; OpenLDAP `servers/slapd/ad.c` even has an `msad_range_hack` flag for ranged retrieval. 389-ds ships **no** AD schema (only standard RFC schemas — verified: no `msuser`/`objectSid` in `ldap/schema/`).

**Gaps.** Schema bytes are AD-version-specific; Monarchy would need a schema-update pathway (Samba has one via `schema_update` / LDF replay).

**Verdict: `ADOPT`** (Samba LDFs + engine). Keep `msuser.schema` as the schema for any pure-OpenLDAP variant.

---

### A.3 [MS-ADTS] — LDAP service and AD extensions  *(the anchor spec)*

**Requirement.** LDAPv3 as used by AD plus the AD-specific surface: `dirSync` control, `LDAP_SERVER_NOTIFICATION`, `SHOW_DELETED`/`SD_FLAGS`, `EXTENDED_DN` (`<GUID=…>`/`<SID=…>` DN forms), `SORT`/`VLV`, `PAGED_RESULTS`, `GET_STATS`, `LAZY_COMMIT`, `QUOTA`; ranged attribute retrieval (`member;range=0-1499`); `rootDSE` attributes (`supportedControl`, `supportedCapabilities`, `highestCommittedUSN`, `dsServiceName`, `namingContexts`); FSMO roles; tombstones/deleted-objects; GC partial-attribute-set behaviour; KCC/site topology; schema partition; `nTDSDSA`/`msDS-*` config.

**Best code — Samba ✅ (both the protocol front end and the AD semantics engine)**
- Protocol front end: `source4/ldap_server/ldap_server.c`, `ldap_backend.c`, `ldap_bind.c`, `ldap_extended.c`; control codecs and the registered-control list in `source4/libcli/ldap/ldap_controls.c` (`samba_ldap_control_handlers()`, `ldap_known_controls[]`).
- AD semantics: the LDB module stack under `source4/dsdb/samdb/ldb_modules/` (63 modules), wired in `samba_dsdb.c`: `rootdse`, `dsdb_schema`, `objectclass`, `samba_dsdb`, `repl_meta_data`, `extended_dn`, `show_deleted`, `acl`, `ranged_results`, `descriptor`, `linked_attributes`, `dirsync`, `replicated_objects`, `fix_*`, `samba3sid`, `instancetype`, `operational`, `samldb`, `fsmo`, `kcc`, `vLV`, `partition`, `topology`, `paged_results`, `subtree_rename`, `unique_objectid`, `winsdb`, `scripting`, `encrypted_secrets`, `dns_notify`, `group_audit`, `audit_log`, `iNetOrgPerson`, `notify`, `password_hash`, `unix_convert`, `objectguid`, `group_audit`…
- KCC: `source4/dsdb/kcc/kcc_connection.c`, `kcc_service.c`, `kcc_drs_replica_info.c`, `kcc_periodic.c`, `garbage_collect_tombstones.c` + `samba_kcc` (Python) — site/intersite topology, ISTG, replication connections.

**Supporting.**
- 389-ds ✅ LDAP engine (`ldap/servers/slapd/{bind,search,add,delete,modrdn}.c`, plugin framework `plugin.c`/`slapi-plugin.h`, paged results, server-side sort, USN plugin, Retro Changelog) — but **no server-side `dirSync`**, no show-deleted, no AD DN forms, no ranged results (verified: `dirsync` appears only in 389-ds's *replication plugin* as a Windows **client**).
- OpenLDAP ✅ protocol core (`servers/slapd/`), `syncprov` overlay (persistent search/sync protocol — *not* dirSync), `memberof`, `refint`, `ppolicy`, `dds`, `dynlist`, `translucent`; `ad.c` has the ranged-attribute `msad_range_hack`.
- ApacheDS ✅ Java `protocol-ldap` module — a clean *reference* implementation of LDAPv3 + schema subsystem (`core-api/core-integ`, `server-config`).
- Kanidm 🟡 `server/lib/src/idm/ldap.rs` — read-only LDAP gateway with explicit AD-flavoured compatibility mapping; useful as a *modern design reference* for schema translation but not AD-wire-compatible.
- LLDAP 🟡 `crates/ldap` — minimal LDAP handler; reference for schema-translation ergonomics only.
- glauth 🟡 `v2/pkg/handler/ldap.go`, `ldapopshelper.go` — lightweight search/bind only.

**Gaps (relative to MS-ADTS).** Samba covers the AD surface very well; known deltas are around the *edges*: some newer controls (e.g. `SDFlags` variants), certain schema versions, and `dirSync` behaviours at the GC. ApacheDS/389-ds/OpenLDAP **cannot** serve as drop-in AD LDAP front ends — they lack the AD control set.

**Verdict: `ADOPT`** Samba `ldap_server/` + `dsdb` stack. Use ApacheDS/389-ds/OpenLDAP as **reference** for the LDAP service core if Monarchy ever wants a non-GPL front end, but that is a large, permanent compatibility liability.

---

## Layer 2 — Replication

### A.4 [MS-DRSR] — Directory Replication Service (DRSUAPI)

**Requirement.** The AD replication wire protocol: `IDL_DRSBind/DRSUnbind`, `DRSGetNCChanges` (`DS_REPLICA_SYNC`), replication cursors (`uptodatevector`, `highwatermark`), `DRSUpdateRefs`, `DRSReplicaAdd/Modify/Del/DelEx`, `DRSWriteSPN`, `DRSGetMemberships`, `DRSVerifyNames`, `DRSCrackNames`, `DRSAddEntry`, `DRSGetReplInfo`, `DRSExecuteKCC`; NDR encoding + **MSZIP and XPRESS (LZXPRESS + Huffman) compression**; `repsFrom`/`repsTo`, `USN`/`invocationId`, linked-value replication, conflict resolution, tombstone lifetime, garbage collection.

**Best code — Samba ✅ (the only implementation)**
- RPC surface: `source4/rpc_server/drsuapi/dcesrv_drsuapi.c` (`IDL_DRSBind` etc.), `getncchanges.c` (the big one), `addentry.c`, `updaterefs.c`, `writespn.c`, `drsutil.c`.
- Replication engine: `source4/dsdb/repl/` (`drepl_service.c`, `drepl_partitions.c`, `drepl_replica.c`, `drepl_notify.c`, `replicated_objects.c`, `repl_meta_data` in `ldb_modules`), `source4/dsdb/kcc/`.
- IDL: `librpc/idl/drsuapi.idl`; NDR compression: `librpc/ndr/ndr_compression.c`.

**Supporting / gap-critical detail.**
- **XPRESS is *disabled* in Samba**: `source4/dsdb/repl/drepl_service.c:122` → `#if 0 /* we don't support XPRESS compression yet */` and the `DRSUAPI_SUPPORTED_EXTENSION_XPRESS_COMPRESS` bit is commented out. MSZIP is implemented.
- **The XPRESS code already exists in-tree elsewhere**: `lib/compression/lzxpress.c`, `lzxpress_huffman.c`. Wiring these into `getncchanges` is a *contained* task — the single most valuable, lowest-risk gap to close.
- 389-ds ✅ has its own replication (`ldap/servers/plugins/replication/repl5_*.c`) and even a Windows-interop connector (`windows_connection.c`, `windows_private.c`) — but it speaks 389-ds's changelog-based protocol, **not DRSR**. Conceptually comparable (multi-master, per-entry CSN, conflict resolution) yet wire-incompatible.
- OpenLDAP `syncprov` = RFC 4533 sync replication, not DRSR.

**Verdict: `ADOPT`** Samba DRSR. Everything else here is `REFERENCE` (389-ds for conflict-resolution ideas). **Close the XPRESS gap by reusing `lib/compression/`.**

---

## Layer 3 — Authentication, Kerberos, PAC

### A.5 [MS-KILE] — Kerberos extensions for AD

**Requirement.** AD-specific KDC/KDC-client behaviour: `krbtgt` key handling, machine-account keys, AES/RC4 enctypes, **authorization-data (PAC) in tickets**, `AD-IF-RELEVANT`/`AD-WIN2K-PAC` padata, referral tickets for cross-domain TGTs, ticket flags, `msDS-SupportedEncryptionTypes`, account/password policies from the directory, claims (`AD-CLAIMS`), authentication policies/silos (`AD-AUTHN-POLICY`), FAST, and the KDC reading account state from the *directory*.

**Best code — Samba's KDC glue ✅ over an embedded Heimdal 7.99.1 fork**
- Glue + AD policy: `source4/kdc/` — `db-glue.c`, `hdb-samba4.c`, `kdc-glue.c`, `sdb.c`, `sdb_to_hdb.c`, `sdb_to_kdb.c`, `wdc-samba4.c`, `ad_claims.c`, `authn_policy_util.c` (authentication policies/silos), `kpasswd_glue.c`.
- **The KDC algorithm core lives in `third_party/heimdal/` (Samba fork, version 7.99.1 — *not* upstream 7.8.0)**: `kdc/kerberos5.c`, `kdc/pkinit.c`, `lib/hdb/`, `lib/krb5/`, plus `kdc/nt-principal` canonicalization and `wind` (RFC 3454 stringprep) for AD name form.

**Alternative — MIT krb5 🟡 with Samba's `--with-system-mitkrb5` seam**
- `krb5-1.22.2/src/kdc/` (KDC), `src/lib/krb5/krb/` (client), `src/plugins/kdb/ldap/` (`kdb_ldap`), `src/plugins/preauth/pkinit/`.
- Samba side of the seam: `source4/kdc/mit-kdb/kdb_samba.c` (+ `kdb_samba_change_pwd.c`), `source4/kdc/mit_kdc_irpc.c`, `source4/kdc/kdc-service-mit.c`, `mit_samba.c` — Samba implements the *MIT kdb vtable* over its LDB.
- **MIT krb5 1.22.2 does have PAC**: `src/lib/krb5/krb/pac.c`, `pac_sign.c`, and `kdb.h` exposes `krb5_db_issue_pac` — i.e. PAC signing/verification is in-tree. But AD *policy* (authn silos, claims, msDS-SupportedEncryptionTypes semantics) is the part MIT lacks and Samba's glue supplies.
- Samba's own `selftest/knownfail_mit_kdc.d/` documents the deltas of the MIT path vs the embedded-Heimdal path (e.g. device-authentication tests are known failures) — the MIT seam is functional but **experimental**.

**Supporting.** Heimdal 7.8.0 standalone (`heimdal-7.8.0/kdc/kerberos5.c`, `lib/hdb/`) is the *upstream* of Samba's fork — the diff tells you exactly what Samba had to change for AD. FreeIPA uses MIT krb5 + `ipa-kdb` (`freeipa-4.13.4/daemons/ipa-kdb/`), a different kdb plugin, and consumes MS-PAC through `ipa_kdb_mspac.c`.

**Verdict: `ADAPT`.** Ship the embedded-Heimdal path by default (it is the complete one); treat the **MIT path as the strategic modularization seam** (below), because it cleanly separates "KDC algorithm" (MIT, permissive license) from "AD policy/DB" (Samba glue).

---

### A.6 [MS-PAC] — Privilege Attribute Certificate

**Requirement.** PAC layout (`PAC_INFO_BUFFER` types): `LOGON_INFO`, `CREDENTIAL_INFO` (+`PAC_CREDENTIAL_DATA`, NTLM supplemental creds), `UPN_DNS_INFO`, `CLIENT_INFO`, `DEVICE_INFO`, `REQUESTOR`/`ATTRIBUTES_INFO` (claims), `S4U_DELEGATION_INFO`; server/privsvr **checksums** (keyed, incl. AES and RC4 variants); PAC in `authorization-data`; PAC-less tickets (`AD-WIN2K-PAC` omission) for certain S4U cases.

**Best code — Samba's PAC builder ✅ + Heimdal PAC ✅**
- Samba: `source4/kdc/pac-glue.c`, `pac-blobs.c` (build/validate), `librpc/idl/` PAC types via `security.idl`/`kile`.
- Heimdal core: PAC ASN.1 + signing in `third_party/heimdal/lib/krb5/` (and upstream `heimdal-7.8.0/`).

**Supporting.** MIT krb5 ✅ — `src/lib/krb5/krb/pac.c`, `pac_sign.c`; plus `src/include/kdb.h` `krb5_db_issue_pac` hook. FreeIPA consumes the PAC (`daemons/ipa-kdb/ipa_kdb_mspac.c`), SSSD consumes+parses it (`sssd-2.13.1/src/providers/ad/ad_pac_common.c`, `src/responder/pac/`) to derive group SIDs for POSIX mapping. ApacheDS has none.

**Verdict: `ADOPT`** Samba/Heimdal PAC; **MIT's `pac.c` is the cleanest isolated reference** if the MIT-KDC path is taken. SSSD's consumer-side parser is worth reading for the client module.

---

### A.7 [MS-SFU] — S4U2Self / S4U2Proxy constrained delegation

**Requirement.** Protocol transition (`S4U2Self`, `PA-FOR-USER` with the `Kerberos:…`/`NT-PRINCIPAL` name type), constrained delegation (`S4U2Proxy`, `PA-FOR-USER`/transited encoding as `AD-IF-RELEVANT`), `msDS-AllowedToDelegateTo`, `TRUSTED_TO_AUTH_FOR_DELEGATION`, RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`), and the PAC transformations for each.

**Best code — Samba ✅ over Heimdal**
- Samba policy enforcement: `source4/kdc/sdb.c` / `samba_kdc.c`-side account checks (allowed-to-delegate-to, UAC flags), `source4/kdc/db-glue.c`.
- Algorithm: `third_party/heimdal/kdc/kerberos5.c` (S4U branches), upstream reference `heimdal-7.8.0/kdc/kerberos5.c`.

**Supporting.** MIT krb5 ✅ has S4U: `src/kdc/do_tgs_req.c`, `src/lib/krb5/krb/s4u_creds.c`. FreeIPA/SSSD consume delegation results only.

**Verdict: `ADOPT`** Samba+Heimdal; MIT is a viable alternate implementation.

---

### A.8 [MS-NLMP] — NTLM authentication

**Requirement.** `NEGOTIATE`/`CHALLENGE`/`AUTHENTICATE` messages, NTLMv1/v2, `NTLMSSP` flags, target info, MIC, key exchange, session security (sign/seal), `NTOWFv1/v2`, and the *server-side* verification; plus its use inside SPNEGO and its role as fallback in LDAP/RPC.

**Best code — Samba ✅**
- `libcli/auth/` — `ntlm_check.c` (server-side NTLM response verification), `smbencrypt.c` (NTOWF/hash primitives), `schannel.h`/`schannel_proto.h`/`schannel_state*.c` (Netlogon secure channel, closely related), `netlogon_creds_cli.c`, `credentials.c`.
- Wire types: `librpc/idl/ntlmssp.idl`; gensec backend wiring in `auth/gensec/` (`gensec_ntlmssp*`).
- Samba also implements NTLM **inside SASL/SPNEGO** (`gensec_spnego`).

**Supporting.** **Cyrus SASL ✅ `plugins/ntlm.c`** — a standalone NTLM SASL mechanism, the only permissively-licensed NTLM server implementation here; useful when you want NTLM without Samba (with the caveat that it historically lacks NTLMv2 session-security polish). ApacheDS: none. 389-ds/OpenLDAP: none (delegate to SASL).

**Verdict: `ADOPT`** Samba `libcli/auth` for the AD-faithful path; `ADAPT` Cyrus `ntlm.c` only for a Samba-free build.

---

### A.9 [MS-SPNG] / [MS-ADTS] channel binding

**Requirement.** SPNEGO negotiation (`NegTokenInit/Resp`), and **channel binding** (`tls-server-end-point`) for LDAP/RPC over TLS — required by hardened AD for NTLM relay protection.

**Best code — Samba ✅ / Cyrus SASL ✅ (with Debian patch)**
- Samba: `auth/gensec/spnego.c`, `gensec_gssapi`, and the LDAP/RPC TLS hooks in `source4/ldap_server/ldap_bind.c`.
- Cyrus SASL: `plugins/gssapi.c`, `plugins/gs2.c`, `plugins/gs2_token.c`; configure switch `HAVE_GSS_SPNEGO` (`m4/sasl2.m4:357`). The local Debian tree carries **patch `0034-channel-binding-gssapi-gss-spnego.patch`** (plus `0035-*` for `max-ssf=0` on GSS-SPNEGO) — so the channel-binding support that upstream Cyrus lacks is *already* present in `cyrus-sasl2-2.1.28+dfsg1`.

**Verdict: `ADOPT`.** Samba for AD-faithful SPNEGO; take the patched Cyrus `gssapi.c`/`gs2.c` when SASL is the entry point.

---

### A.10 PKINIT / [MS-KILE] PKINIT extensions

**Requirement.** Certificate-based pre-auth (smartcard/`PKINIT`), the MS extensions (`MS-PKCA`, `PAC` in PKINIT, `altSecurityIdentities` mapping, `msUPN`, KDC cert validation), and smartcard logon semantics.

**Best code — Heimdal ✅ (permissive) / MIT ✅**
- Heimdal: `heimdal-7.8.0/lib/hx509/`, `kdc/pkinit.c`; Samba's fork: `third_party/heimdal/kdc/pkinit.c`.
- MIT krb5: `krb5-1.22.2/src/plugins/preauth/pkinit/` — the most actively maintained PKINIT in open source.

**Verdict: `ADOPT`** MIT `pkinit` (if MIT path) or Heimdal `hx509`/`pkinit` (embedded path).

---

## Layer 4 — RPC and administrative protocols

### A.11 [MS-RPCE] — DCE/RPC runtime

**Requirement.** Connection-oriented DCE/RPC over TCP/ncacn_np/ncacn_http; NDR/NDR64 transfer syntax, `UUID` binding, `alter_context`, auth levels (`PKT_PRIVACY`/`INTEGRITY`), SPNEGO/NTLM/Kerberos auth trailer, fault/PDU types, the endpoint mapper.

**Best code — Samba ✅**
- `librpc/rpc/` (dcerpc runtime), `librpc/ndr/` (NDR + NDR64), `librpc/idl/` (all interfaces), `source4/rpc_server/dcerpc_server.c` + `source4/rpc_server/epmapper/`, and the generated `*_c.c`/`*_s.c` stubs.

**Supporting.** ApacheDS 🟡 has Java Kerberos/LDAP but not a general RPCE stack (it implements LDAP/Kerberos/DNS directly). 389-ds/OpenLDAP: none.

**Verdict: `ADOPT`** Samba `librpc`.

---

### A.12 [MS-SAMR] / [MS-SAMS] — SAM RPC & SAM data model

**Requirement.** `SamrConnect/OpenDomain/EnumerateUsers/…`, `SamrCreateUser2InDomain`, password set/change, `SamrQueryInformationUser2` (`USER_INFO_*`, incl. `USER_INFORMATION_CLASS` 16/21/23), `SamrSetInformationUser2`, group membership, domain/`SamrQueryDomainInfo`, aliases, `SamrLookupNames`/`LookupIds`, and the SAM data model (RID allocation, `sAMAccountName` uniqueness, group type semantics, `userAccountControl`).

**Best code — Samba ✅**
- RPC: `source4/rpc_server/samr/` (`dcesrv_samr.c`, `samr_util.c`, …).
- Data model: `source4/dsdb/samdb/ldb_modules/samldb.c` (RID/`rIDSet` allocation, account rules), `source4/samdb`.

**Supporting.** FreeIPA `daemons/ipa-sam/ipa_sam.c` — implements *parts* of the SAM RPC vtable for Windows compatibility (with Samba's `samba_wdc`/`libsamba-policy` as the bridge). 389-ds stores `ntUser*` attributes but no SAMR.

**Verdict: `ADOPT`** Samba.

---

### A.13 [MS-LSAD] / [MS-LSAT] — LSA policy and SID/name translation

**Requirement.** `LsarOpenPolicy2/QueryInformationPolicy/SetInformationPolicy` (domain policy, `LsarQueryDomainInformationPolicy`), `LsarLookupNames`/`LsarLookupSids` (SID↔name, `LsapLookupSids2`), account rights (`LsarAddAccountRights`/`EnumerateAccountRights`), trusted domain enumeration, SID translation to POSIX (via idmap).

**Best code — Samba ✅**
- `source4/rpc_server/lsa/` (`dcesrv_lsa.c`, `lsa_lookup.c`), plus `source3/winbindd/` idmap for POSIX translation, `libcli/security/dom_sid.c`.
- `librpc/idl/lsa.idl`.

**Supporting.** FreeIPA `ipaserver/dcerpc.py`, `ipaserver/plugins/trust.py`, `daemons/ipa-slapi-plugins/ipa-extdom-extop/` (the **extdom** extended-op plugin), `ipaserver/plugins/idviews.py` + SSSD `idviews` — these provide SID→POSIX across the trust, but they *call Samba's* netlogon/lsa rather than implement them.

**Verdict: `ADOPT`** Samba.

---

### A.14 [MS-NRPC] — Netlogon Remote Protocol

**Requirement.** Secure channel establishment (machine account, `NetrServerAuthenticate3`, `NetrServerPasswordSet2` with the `Netlogon Credential` cipher + `NL_AUTH_MESSAGE`/`NL_AUTH_SIGNATURE`), `NetrLogonSamLogon*` (interactive/network), `DsrGetDcName(Ex)`, `NetrGetAnyDCName`, `NetrEnumerateTrustedDomains`, `DsrGetSiteName`, `DsrGetDcSiteCoverage`, `NetrLogonGetCapabilities`, `NetrServerTrustPasswordsGet`, `DsrUpdateReadOnlyServerDnsRecords`, DNS update for DC locator.

**Best code — Samba ✅**
- `source4/rpc_server/netlogon/` — `dcesrv_netr_LogonSamLogon*.c`, `dcesrv_netr_ServerAuthenticate*.c`, `netlogon.c`, and `source4/rpc_server/netlogon/` trust code; `source4/auth/` secure-channel state; `libcli/auth/netlogon_creds_cli.c`, `schannel_state_tdb.c`.
- Wire types: `librpc/idl/netlogon.idl`.

**Supporting.** FreeIPA again *delegates* to Samba (`ipaserver/dcerpc.py` → `samba.wdc`/netlogon for the AD trust). 389-ds Windows replication setup talks to netlogon but does not implement it.

**Verdict: `ADOPT`** Samba.

---

### A.15 [MS-DSSP] — Directory Services Setup / DC locator

**Requirement.** `DsrGetDcNameEx2` (workstation DC discovery: flags, site weighting, `DsGetDcNext`-style behaviour) — functionally the same netlogon surface; Monarchy needs the *responder* side so Linux/Windows clients locate the DC, and the *resolver* side for `samba-tool`/SSSD.

**Best code — Samba ✅** (via `source4/rpc_server/netlogon/`) — the `netr` `Dsr*` set plus `source4/dsdb/dns/` SRV/locator logic; IDL `librpc/idl/dssetup.idl` (the DsSetup *RPC* interface is separate and thin).

**Supporting.** OpenRSAT (`submodules/pltis_djoin`, `grid_ja`…) implements **offline domain join** semantics on the *client* side — useful to test DC-locator behaviour.

**Verdict: `ADOPT`** Samba.

---

## Layer 5 — Policy, SYSVOL, time, DNS

### A.16 [MS-GPOL] / [MS-GPSI] — Group Policy

**Requirement.** *Server side:* storing/versioning GPOs in SYSVOL, `gPLink`/`gPOptions` on sites/domains/OUs, `gPCFileSysPath`, GPO version numbers, security filtering. *Client side (GPSI):* SOM discovery (site→domain→OU), `gpt.ini` parsing, `GPT.INI`/CSE extensions (MS-GPREG, MS-GPPREF, MS-GPSB), ACL-based applicability.

**Best code — split: Samba for server, SSSD for client**
- Server: `libgpo/` (`gpo_ldap.c`, `gpo_ini.c`, `gpo_sec.c`, `gpo_fetch.c`, `gpo_util.c`) + the `gPLink`/ACL handling in the `dsdb` LDB modules; RPC `winreg` for policy access (`source4/rpc_server/winreg/`). *There is no `rpc_server/gpo`* — GPOL is file+LDAP, not RPC.
- Client: **SSSD ✅** `sssd-2.13.1/src/providers/ad/ad_gpo.c`, `ad_gpo_child.c`, `ad_gpo_ndr.c` (+ `ad_gpo.h`) — a real MS-GPOL client implementation (SOM/GPLink discovery, security filtering, `gpt.ini`, access-control decisions) in C. This is the most complete *GPO client* in the Linux world.

**Supporting.** OpenRSAT `ugplink.pas` for GPLink editing.

**Verdict: `ADOPT`** Samba (server) + **`ADOPT`/`ADAPT` SSSD `ad_gpo*` (client)**. Note this is the one place where the *best* code is *not* Samba.

---

### A.17 [MS-FRS1] / [MS-FRS2] — File Replication Service

**Requirement.** `FRS1` (legacy) and `FRS2`/`DFSR` (RDC-based, `RdcGetChanges` etc.) SYSVOL replication between DCs.

**Best code — ❌ none.** No local project implements FRS1/FRS2. Samba's model is different: **SYSVOL is replicated by piggybacking on DRS** (`DRSGetNCChanges` + the SYSVOL reparse/`getncchanges` "extended operation" `/MS-DFSR`?), not by DFSR RPC.

**Verdict: `ABSENT`** (FRS2 RPC must be written if true DFSR interop is required) — but note the *pragmatic* path is Samba's DRS-based SYSVOL, which interoperates with Windows DCs in practice for `--realm`-joined setups. Track this as a known deviation.

---

### A.18 [MS-SMB2] — SYSVOL/NETLOGON shares

**Requirement.** Enough SMB2/3 to serve `\\domain\SYSVOL` and `\\domain\NETLOGON`, with Kerberos/NTLM auth, DFS referral handling, and ACLs.

**Best code — Samba ✅** — `source4/smbd/`, `source3/smbd/`, `source4/smb_server/`, `source3/winbindd/`; shares provisioned by `source4/setup/`/`python/samba/provision/`.

**Verdict: `ADOPT`** Samba.

---

### A.19 [MS-W32T] — Windows Time Service

**Requirement.** `MS-W32T` RPC (time provider, `w32time` service interface) and the AD-integrated time hierarchy aligned to `PdcEmulator`; plus the NTP authentication path used by domain members (`MS-SNTP`).

**Best code — Samba 🟡 (partial)**
- `librpc/idl/w32time.idl` exists (IDL present), `source4/ntp_signd/` implements **NTP signed (MS-SNTP)** — the domain `NTPSIGNED` extension used by Windows members.
- No full `MS-W32T` RPC service (the `w32time` provider list/`W32TimeRpc`).

**Supporting.** ApacheDS `protocol-ntp` (Java) is a plain NTP reference, not MS-W32T.

**Verdict: `ADAPT`** — use Samba `ntp_signd` for MS-SNTP; `MS-W32T` RPC itself is a small `ABSENT` item.

---

### A.20 DNS (MS-DNSP / AD-integrated DNS)

**Requirement.** SRV records for DC locator (`_ldap._tcp.<site>._sites.dc._msdcs`, `_kerberos`, `_gc`), AD-integrated zones, dynamic updates (GSSTSIG/GSS-TSIG), `DNS_RPC` interface (`IDL_Dnssrv`), zone/record management.

**Best code — Samba ✅**
- `source4/dns_server/` (`dns_server.c`, `dns_utils.c`, `dlz`-style AD zone storage in DSDB as `dnsZone`/`dnsNode`), `source4/rpc_server/dnsserver/`, `source4/dsdb/dns/`; IDL `librpc/idl/dnsserver.idl`; GSS-TSIG via `gensec`.
- Zone records stored natively in AD (`dnsRecord`), which is what makes AD-integrated DNS work.

**Verdict: `ADOPT`** Samba. (External BIND as a *secondary* is fine; the AD-integrated zone mirroring must be Samba's.)

---

## Layer 6 — Overview, tooling, administration

### A.21 [MS-ADOD] / [MS-DOCO] — protocol overview & cross-reference

No code; these are the map used to order Part A/B. **Verdict: `REFERENCE`.**

### A.22 Administration & tooling (not a wire spec, but required)

**Requirement.** DC provisioning, `samba-tool`-class CLI, user/group/OU administration, GPO editing, DNS/zone admin, replication status/monitoring, and a GUI to replace RSAT.

**Best available.**
- Samba: `python/samba/netcmd/` (`samba-tool` domain/dbcheck/drs/gpo 5-dns/fsmo/…), `source4/setup/`.
- **OpenRSAT ✅** (`OpenRSAT-0.4.519-git/`) — Free Pascal/Lazarus GUI that *speaks AD wire protocols* (LDAP/ADSI, DNS, GPLink editors). Notably, its `submodules/pltis_djoin` implements **offline domain join**. This is the natural GUI shell for Monarchy.
- SSSD + `realmd`-style tooling for *clients*; FreeIPA's `ipa` CLI/Web UI is a model for integrated management (but its own, non-AD protocol).

**Verdict: `ADOPT`** Samba `samba-tool` (CLI) + **`ADAPT` OpenRSAT (GUI)**.

### A.23 The MMC console host & the 1:1 UI layer

**Requirement.** A **1:1 look and behaviour for the Microsoft Management Console (MMC)** and its AD snap-ins —
ADUC (`dsa.msc`), Sites & Services (`dssite.msc`), Domains & Trusts (`domain.msc`), Schema (`schmmgmt.msc`), GPMC
(`gpmc.msc`), DNS Manager (`dnsmgmt.msc`) — i.e. console tree + results pane + standard MMC toolbar + status bar +
tabbed property sheets, loading `.msc` console files.

**What MMC actually is.** A **snap-in host**: a generic frame (tree, results pane, toolbar, menus, property sheets)
plus registered COM snap-ins, driven by an XML-ish `.msc` console file. The host model, the snap-in API and the
`.msc` format are **documented and functional**, so the host may be reimplemented freely. No wire protocol is
involved — the snap-ins talk to Monarchy over LDAP/DCE-RPC/RPC-from the backend.

**Best available.**
- **OpenRSAT ✅** — the strongest *behaviour reference*: a Lazarus GUI that speaks the AD wire protocols (ADSI/LDAP,
  DNS, `gPLink` editors, offline domain join via `pltis_djoin`). It is *not* an MMC host (no `.msc`, no console-tree
  frame), so it supplies snap-in **logic**, not the host.
- Samba `python/samba/netcmd/` — CLI equivalents of most snap-in operations (authoritative for *what* each dialog does).
- 389-ds console (Java) and FreeIPA's Web UI — models for integrated management, but neither is MMC-compatible.
- **No open MMC-compatible host exists** → this is an `ABSENT` component to write.

**How to build it (all legally clean — see [`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md) §13).**
Qt is the shortest path: `ad-mmc` renders the standard console with `QTreeWidget`/`QTableView` + a Windows-like
`QStyle`/QSS; snap-ins are plain widgets registered per snap-in GUID; consoles are `.msc` files. **Reuse the layout
idiom; author your own artwork.** Icons come from an open set; fonts are metric-compatible OFL faces (Selawik).
The console-image index ([`AD-CONSOLE-IMAGE-INDEX.md`](AD-CONSOLE-IMAGE-INDEX.md)) is the visual specification —
**reference only, never shipped as assets.**

**Verdict: `ABSENT` → write `ad-mmc` (+ `ad-snapins`, `ad-icons`), using OpenRSAT and the console-image index as
behaviour/layout references.**

---

# Part B — Correlational index: spec → best code → verdict

**Legend.** *Primary* = the code to build the Monarchy module from. *Secondary* = alternative/reference. Verdict: `ADOPT` (use as-is) · `ADAPT` (use with changes) · `REFERENCE` (design only) · `ABSENT` (write new).

| Spec | Requirement (short) | Primary code (project → path) | Secondary / reference | Verdict | Monarchy module |
|---|---|---|---|---|---|
| **MS-DTYP** | SIDs, SD, SDDL, ACEs, claims | **Samba** `libcli/security/` (`dom_sid.c`, `sddl.c`, `access_check.c`, `conditional_ace.c`, `claims-conversions.*`, `privileges.c`) + `librpc/idl/security.idl` | FreeIPA/389-ds (no SID ACLs) | `ADOPT` | `libadt` |
| **MS-ADSC/ADA** | Schema classes/attrs | **Samba** `source4/setup/ad-schema/*.ldf` (to v1903) + `source4/dsdb/schema/` | OpenLDAP `msuser.schema` (portable subset) | `ADOPT` | `ad-schema` |
| **MS-ADTS** | LDAP + AD extensions, KCC | **Samba** `source4/ldap_server/` + `source4/dsdb/samdb/ldb_modules/` + `source4/dsdb/kcc/` | ApacheDS `protocol-ldap`; 389-ds `slapd`; OpenLDAP `syncprov`/`ppolicy` | `ADOPT` | `ad-ldap` + `ad-kcc` |
| **MS-DRSR** | DRS replication | **Samba** `source4/rpc_server/drsuapi/` + `source4/dsdb/repl/` + `librpc/idl/drsuapi.idl` | 389-ds `repl5_*` (design only) | `ADOPT` (+ close XPRESS via `lib/compression/`) | `ad-repl` |
| **MS-KILE** | Krb extensions, AD policy | **Samba** `source4/kdc/` (`db-glue.c`, `ad_claims.c`, `authn_policy_util.c`) over `third_party/heimdal/` | **MIT krb5** `src/kdc/` + seam `source4/kdc/mit-kdb/`; Heimdal 7.8.0 standalone | `ADAPT` (Heimdal default, MIT as modular seam) | `ad-kdc` |
| **MS-PAC** | PAC build/sign | **Samba** `source4/kdc/pac-glue.c`, `pac-blobs.c`; Heimdal `lib/krb5/` | MIT `src/lib/krb5/krb/pac.c`; SSSD `ad_pac_common.c` (consumer) | `ADOPT` | `ad-pac` |
| **MS-SFU** | S4U delegation | **Samba** `source4/kdc/` policy + Heimdal `kdc/kerberos5.c` | MIT `s4u_creds.c` | `ADOPT` | `ad-kdc` |
| **MS-NLMP** | NTLM | **Samba** `libcli/auth/` (`ntlm_check.c`, `smbencrypt.c`) + `librpc/idl/ntlmssp.idl` | Cyrus SASL `plugins/ntlm.c` | `ADOPT` (`ADAPT` Cyrus if SASL-only) | `ad-auth` |
| **MS-SPNG** / channel binding | SPNEGO + CBT | **Samba** `auth/gensec/spnego.c`, `ldap_bind.c` | Cyrus `plugins/gssapi.c`+`gs2.c` (Debian patch 0034/0035) | `ADOPT` | `ad-auth` |
| **PKINIT** | Smartcard pre-auth | **MIT** `src/plugins/preauth/pkinit/` | Heimdal `lib/hx509/`, `kdc/pkinit.c` | `ADOPT` | `ad-kdc` |
| **MS-RPCE** | DCE/RPC + NDR | **Samba** `librpc/rpc/`, `librpc/ndr/`, `source4/rpc_server/dcerpc_server.c`, `epmapper/` | — | `ADOPT` | `libdcerpc` |
| **MS-SAMR/SAMS** | SAM RPC + model | **Samba** `source4/rpc_server/samr/` + `dsdb/.../samldb.c` | FreeIPA `daemons/ipa-sam/ipa_sam.c` | `ADOPT` | `ad-samr` |
| **MS-LSAD/LSAT** | LSA policy + SID↔name | **Samba** `source4/rpc_server/lsa/` + `winbindd` idmap | FreeIPA `extdom`/`dcerpc.py` | `ADOPT` | `ad-lsa` |
| **MS-NRPC** | Netlogon/secure channel | **Samba** `source4/rpc_server/netlogon/` + `libcli/auth/schannel*` | FreeIPA `dcerpc.py` (client) | `ADOPT` | `ad-netlogon` |
| **MS-DSSP** | DC locator | **Samba** `source4/rpc_server/netlogon/` (`Dsr*`) + `source4/dsdb/dns/` | OpenRSAT `pltis_djoin` (client) | `ADOPT` | `ad-netlogon` |
| **MS-GPOL/GPSI** | GPO server + client | **Samba** `libgpo/` + `dsdb` gPLink (server) · **SSSD** `src/providers/ad/ad_gpo*.c` (client) | OpenRSAT `ugplink.pas` | `ADOPT` (both) | `ad-gpo` + `ad-gpo-client` |
| **MS-FRS1/2** | SYSVOL replication | — (**none**) | Samba's DRS-based SYSVOL as the pragmatic model | `ABSENT` | `ad-frs` (future) |
| **MS-SMB2** | SYSVOL/NETLOGON | **Samba** `source4/smbd/`, `source3/smbd/`, `source3/winbindd/` | — | `ADOPT` | `ad-smb` (or system Samba) |
| **MS-W32T** | Time service | **Samba** `source4/ntp_signd` (MS-SNTP) + `librpc/idl/w32time.idl` | ApacheDS `protocol-ntp` (plain NTP) | `ADAPT` | `ad-time` |
| **DNS (AD-integrated)** | SRV/locator, DNSP | **Samba** `source4/dns_server/` + `rpc_server/dnsserver/` + `dsdb/dns/` | ApacheDS `protocol-dns` | `ADOPT` | `ad-dns` |
| **MS-ADOD/DOCO** | Overview | — | the specs themselves | `REFERENCE` | — |
| **Admin/GUI** | Provisioning/CLI/GUI | **Samba** `python/samba/netcmd/` | **OpenRSAT** (GUI), FreeIPA `ipa` (model) | `ADOPT` + `ADAPT` | `ad-tool` + `ad-gui` |

---

## B.1 Reuse heat map — what each project actually contributes

| Project | Contributes to Monarchy as | Specs covered | Verdict |
|---|---|---|---|
| **Samba** | The protocol engine: LDAP front end, dsdb semantics, DRS, KDC glue, SAMR/LSA/NRPC, GPO server, DNS, SMB2, RPCE/NDR, security types, tooling | ADTS, ADSC, DRSR, KILE, PAC, SFU, SAMR, LSAD, NRPC, DSSP, GPOL, W32T, DNSP, SMB2, RPCE, DTYP | **Core — `ADOPT`** |
| **MIT krb5** | KDC algorithm + PKINIT + `kdb_ldap`; the modularization seam | KILE, PAC, SFU, PKINIT | `ADAPT` (strategic alternate KDC) |
| **Heimdal** | Upstream of Samba's embedded KDC; permissive BKDC/hx509 | KILE, PAC, SFU, PKINIT | `REFERENCE` / alternate |
| **Cyrus SASL** | GSSAPI/GS2/NTLM SASL mechanisms + channel binding | NLMP, SPNG, channel binding | `ADOPT` (auth front end) |
| **OpenLDAP** | Portable LDAP engine + `msuser.schema` + overlays (`syncprov`, `ppolicy`, `memberof`, `refint`, `dds`) | ADTS (partial), password policy | `REFERENCE` / alternate LDAP |
| **389-ds** | LDAP engine internals + plugin architecture + replication design | ADTS (partial), DRSR (design only) | `REFERENCE` |
| **FreeIPA** | Trust/DCE integration, `ipa-kdb` + `ipa-sam` (Samba-backed), extdom, integrated mgmt model | NRPC/SAMR/LSA (delegated), KILE | `REFERENCE` (integration patterns) |
| **SSSD** | **GPO client**, PAC consumer, AD/LDAP providers, id mapping | GPOL/GPSI, PAC (client), LSAT (client) | `ADOPT` (client module) |
| **Kanidm** | Modern Rust IDM design; read-only LDAP gateway, schema translation | ADTS (reference) | `REFERENCE` |
| **LLDAP** | Minimal LDAP provider; schema translation ergonomics | ADTS (reference) | `REFERENCE` |
| **glauth** | Lightweight Go LDAP handler | ADTS (reference) | `REFERENCE` |
| **Apache DS** | Java LDAP/Kerberos/DNS/changepw protocol modules + schema subsystem | ADTS, DNS, KILE (reference) | `REFERENCE` |
| **OpenRSAT** | **AD admin GUI** + offline domain join | DSSP/DC-locator (client), GPOL editing | `ADAPT` (GUI) |

**"Who wins each spec" one-liner.** DTYP/ADSC/ADTS/DRSR/SAMR/LSAD/NRPC/DSSP/GPOL-server/DNSP/SMB2/RPCE → **Samba**. KILE/PAC/SFU/PKINIT → **Samba-glue + Heimdal**, with **MIT** as the modular alternate. GPOL-client → **SSSD**. NLMP/SPNG → **Samba** (Cyrus as the standalone alternate). FRS2/W32T-RPC → **nobody** (write new). GUI → **OpenRSAT**.

---

# Part C — Modularization blueprint

## C.1 Design principles

1. **Protocol engine stays Samba-derived.** Since every AD protocol is only implemented in Samba, Monarchy is a *restructure* of Samba, not a rewrite. Rewriting DRSR/SAMR/NRPC from scratch is not a credible plan; the deliverable value is in **clean interfaces, swappable subsystems, and packaging**.
2. **One module = one wire spec (or one cohesive subsystem).** Each module owns its IDL and its RPC endpoint(s); no module reaches into another's storage.
3. **Interfaces at three levels, in order of preference:**
   - **C library + public header** (for in-process, trusted code),
   - **IRPC message** (Samba's internal RPC, for the DC process family — already used, e.g. `mit_kdc_irpc`),
   - **DCE/RPC or unix-socket daemon** (for optional/out-of-process or differently-licensed components).
4. **License boundaries must be explicit.** GPL-3.0 (Samba) code must not link into non-GPL code unless the whole work is GPL-3.0. The permissive parts (MIT krb5, Heimdal BSD, Cyrus BSD, glauth MIT, ApacheDS Apache-2.0, OpenLDAP OPL) can be linked more freely. 389-ds/SSSD/FreeIPA/Kanidm/LLDAP/OpenRSAT are GPL-3.0 or MPL-2.0 — treat as separate processes (MPL) or GPL-compatible (GPL).
5. **Storage is an internal detail; the wire is the contract.** Keep an AD engine (Samba `dsdb`/LDB) as the default store, but define a `DirectoryProvider` interface so a 389-ds/OpenLDAP-backed variant is *possible* even though it will not be AD-complete.
6. **Config is declarative and versioned** (the schema + functional-level are data, not code).

## C.2 Component catalogue

Naming: `lib*` = linkable library; `ad-*` = subsystem module; `monarchy-*` = process/daemon.

| Module | Responsibility | Built from | Interface | License |
|---|---|---|---|---|
| **`libadt`** | SID/GUID/SD/SDDL/ACL/privileges/claims types & algorithms | Samba `libcli/security/`, `librpc/idl/security.idl` (+ NDR generators) | C lib, header `libadt.h` | GPL-3.0 |
| **`libdcerpc`** | DCE/RPC + NDR/NDR64 runtime, endpoint mapper client | Samba `librpc/rpc/`, `librpc/ndr/`, `librpc/idl/` | C lib + generated stubs | GPL-3.0 |
| **`libldb-ad`** | LDB store + AD LDB module stack | Samba `lib/ldb/`, `source4/dsdb/` | C lib (LDB API) | GPL-3.0 |
| **`ad-schema`** | Schema data + engine; LDF import/update | Samba `source4/setup/ad-schema/`, `source4/dsdb/schema/` | C lib + CLI | GPL-3.0 |
| **`ad-ldap`** | LDAP server front end + AD control set | Samba `source4/ldap_server/`, `source4/libcli/ldap/ldap_controls.c` | TCP/unix socket (daemon) | GPL-3.0 |
| **`ad-kcc`** | Site/conn topologies, replication graph | Samba `source4/dsdb/kcc/` | C lib | GPL-3.0 |
| **`ad-repl`** | DRSUAPI server + replication engine (+ **new** XPRESS) | Samba `source4/rpc_server/drsuapi/`, `source4/dsdb/repl/`, **`lib/compression/lzxpress*`** | DCE/RPC endpoint + C lib | GPL-3.0 |
| **`ad-kdc`** | KDC policy/DB glue; PAC/S4U/authn-policy | Samba `source4/kdc/` (minus algorithm) | **KDB vtable** (Heimdal native *or* MIT `--with-system-mitkrb5`) | GPL-3.0 glue; MIT/BSD core |
| **`ad-pac`** | PAC build/validate | Samba `source4/kdc/pac-glue.c` | C lib | GPL-3.0 |
| **`ad-auth`** | NTLM + SPNEGO + secure channel + SASL front end | Samba `libcli/auth/`, `auth/gensec/`; Cyrus SASL (optional) | C lib / SASL `.so` | GPL-3.0 (+BSD plugin) |
| **`ad-netlogon`** | NRPC + DSSP DC-locator | Samba `source4/rpc_server/netlogon/` | DCE/RPC endpoint | GPL-3.0 |
| **`ad-lsa`**, **`ad-samr`** | LSAD/LSAT, SAMR | Samba `source4/rpc_server/{lsa,samr}/` | DCE/RPC endpoints | GPL-3.0 |
| **`ad-gpo`** (server) | GPO storage/SOM/gPLink/versioning | Samba `libgpo/` + dsdb hooks | C lib + SMB/LDAP | GPL-3.0 |
| **`ad-gpo-client`** | GPO retrieval + applicability | **SSSD** `src/providers/ad/ad_gpo*.c` | C lib | GPL-3.0+ |
| **`ad-dns`** | AD-integrated DNS + DNSP RPC | Samba `source4/dns_server/`, `rpc_server/dnsserver/` | TCP/UDP + RPC | GPL-3.0 |
| **`ad-time`** | MS-SNTP + (new) MS-W32T RPC | Samba `source4/ntp_signd`, `librpc/idl/w32time.idl` | socket + RPC | GPL-3.0 |
| **`ad-smb`** | SYSVOL/NETLOGON shares | Samba `source4/smbd/`, `source3/smbd/` (or system Samba) | SMB2/3 | GPL-3.0 |
| **`ad-frs`** | SYSVOL replication (DRS-based today; FRS2 *new*) | Samba DRS-SYSVOL; `ABSENT` for DFSR RPC | C lib/RPC | GPL-3.0 |
| **`ad-tool`** | CLI provisioning/admin | Samba `python/samba/netcmd/` | CLI (Python) | GPL-3.0 |
| **`ad-gui`** | GUI administration | **OpenRSAT** | Client app | GPL-3.0 |
| **`ad-mmc`** | MMC-compatible console host: `.msc` loader, console tree, results pane, standard toolbar, snap-in registration | **new** (Qt) — idiom only, no MS code/assets | Client app + `.msc` format | GPL-3.0 |
| **`ad-snapins`** | RSAT-equivalent snap-ins (ADUC/ADSS/ADDT/Schema/GPMC/DNS) | **new** over `ad-ldap`/`ad-repl`/`ad-gpo`; OpenRSAT as behaviour reference | Runs inside `ad-mmc` | GPL-3.0 |
| **`ad-icons`** | Own icon theme, Windows-like shape language | **new** / open themes (Adwaita, Breeze) | Theme directory | OFL/LGPL/CC0 |
| **`ad-client`** | POSIX integration (nss/pam/idmap/GPO) | **SSSD** + Samba `winbindd` | NSS/PAM modules | GPL-3.0+ |

## C.3 Interface contracts (the important ones)

```
                     ┌───────────────────────────────────────────────┐
   LDAP clients ────►│ ad-ldap  (single "directory" process family)   │
   (AD controls)     │   ├── libldb-ad ── ad-schema ── libadt         │
                     │   ├── ad-kcc                                    │
                     │   └── IRPC to ad-repl / ad-kdc / ad-lsa …       │
                     └───────────────────────────────────────────────┘
   DRS peers  ──────► ad-repl    (DRSUAPI endpoint, uses libldb-ad)
   Kerberos   ──────► ad-kdc     (KDB vtable → libldb-ad; PAC via ad-pac)
   Netlogon   ──────► ad-netlogon (NRPC + DC locator)
   SAMR/LSA   ──────► ad-samr / ad-lsa
   DNS/GC     ──────► ad-dns
   SMB        ──────► ad-smb     (SYSVOL/NETLOGON)
   admin      ──────► ad-tool / ad-gui
```

**Key contracts to freeze (interfaces, not implementations):**

1. **`DirectoryProvider`** (C header) — the seam that lets `ad-ldap`, `ad-repl`, `ad-kdc`, `ad-samr`, `ad-lsa`, `ad-netlogon` share one store. Default implementation = `libldb-ad` (Samba dsdb). A 389-ds/OpenLDAP adapter is *possible* to add behind it, but must expose AD semantics (controls, DN forms, ranged retrieval) that those engines lack.
2. **`KdbBackend`** — the MIT `kdb` vtable (already implemented by Samba as `source4/kdc/mit-kdb/kdb_samba.c`) **or** Heimdal's HDB vtable (`source4/kdc/hdb-samba4.c`). Choosing this interface is the single decision that determines whether the KDC core is MIT (permissive) or Heimdal (permissive, Samba-forked).
3. **`ReplTransport`** — DRS is one implementation; the interface allows future FRS2/SYSVOL transports.
4. **`PacProvider`** — build/validate; consumers (`ad-client`, SMB, LDAP) call it.
5. **`AuthMechanism`** — gensec-style: NTLM, SPNEGO, Kerberos, SASL(GSSAPI/GS2), PKINIT — so Cyrus SASL or an external mechanism can plug in.
6. **`GpoProvider`** — server storage vs client retrieval/applicability are cleanly split (Samba vs SSSD).

## C.4 Dependency graph (build-time)

```
libadt ─┬─ libdcerpc ─┬─ ad-netlogon ─┐
        │             ├─ ad-lsa       │
        │             ├─ ad-samr      ├── all link libldb-ad
        │             └─ ad-repl      │   (DirectoryProvider)
        ├─ ad-schema ─── libldb-ad ───┘
        ├─ ad-pac ────── ad-kdc
        └─ ad-auth ───── ad-ldap / ad-smb
ad-kcc ── ad-repl / ad-ldap
ad-dns, ad-time, ad-smb, ad-gpo  (independent servers)
ad-client (SSSD-derived)  ← depends only on LDAP/Kerberos wire, not on libldb-ad
ad-tool / ad-gui          ← CLI/RPC clients
```

## C.5 Build strategies (three options)

**Option A — "Samba, re-cut" (recommended default).**
Build Samba as today, but converge its internal module boundaries onto the catalogue above, expose the headers in C.3, and ship `ad-client`/`ad-gui`/`ad-tool` around it. Zero protocol risk; the work is refactoring-facing (headers, IRPC boundaries, packaging), not reimplementation.
*Pros:* everything works (DRSR, PAC, all controls). *Cons:* the whole DC remains GPL-3.0 (fine for a GPL Monarchy; a problem only if permissive licensing is a hard requirement).

**Option B — "Split KDC seam" (recommended if license/provenance separation matters).**
Option A but with `ad-kdc` built on **MIT krb5 + `--with-system-mitkrb5`** (`source4/kdc/mit-kdb/kdb_samba.c`). The KDC *algorithm* becomes MIT; Samba's GPL-3.0 glue (directory policy, PAC, claims) stays behind the kdb vtable — a clean process/module boundary.
*Pros:* clearly separated, better-maintained Kerberos core, PKINIT from MIT. *Cons:* the MIT path is **experimental** in Samba (`selftest/knownfail_mit_kdc.d/` lists known failures, e.g. device auth); expect to close those gaps. Must forward-port the Debian krb5 security patches (`0013` NegoEx parsing, `0016` `libkdb_lda` overrun) when building from pristine 1.22.2, or use a newer krb5.

**Option C — "Permissive reassembly" (not recommended).**
Heimdal (BSD) KDC + OpenLDAP (OPL) + Cyrus SASL (BSD) + custom implementations of the AD-specific protocols. *Pros:* MIT/BSD/OPL-only artifact. *Cons:* every AD-specific spec (DRSR, SAMR, NRPC, LSAD, DSSP, GPOL, ADTS controls, PAC policy, SYSVOL) must be **written from scratch** — years of work with no interoperability guarantee. Use this only for *sub-modules* (e.g. a standalone SASL/KDC pairing), not the DC.

**Recommendation:** ship **Option A** now (it is the only complete AD DC), and structure the code so **Option B** becomes a configuration toggle (`--kdc=mit|heimdal`). That gives Monarchy both a working system and a defensible licensing/modularization story.

## C.6 Process topology (as deployed)

| Process | Modules | Notes |
|---|---|---|
| `monarchy-samba` (DC) | `ad-ldap`, `libldb-ad`, `ad-schema`, `ad-kcc`, `ad-repl`, `ad-netlogon`, `ad-lsa`, `ad-samr`, `ad-dns`, `ad-gpo`, `ad-smb`, `ad-time`, `libadt`, `libdcerpc` | one address space today; IRPC between subsystems; the split point is the `DirectoryProvider` + endpoint boundaries |
| `monarchy-kdc` | `ad-kdc`, `ad-pac` | linkable in-process (Heimdal) or a distinct MIT KDC with the Samba kdb plugin |
| `monarchy-sasl` (optional) | `ad-auth` via Cyrus SASL | pluggable mechanism `.so`s |
| `monarchy-client` | `ad-client` (SSSD-derived): `ad-gpo-client`, PAC/ID mapping | runs on member hosts, not the DC |
| `monarchy-tool` / `monarchy-gui` | `ad-tool`, `ad-gui` | clients over LDAP/RPC |

## C.7 Phased roadmap

| Phase | Goal | Code | Effort |
|---|---|---|---|
| **P0** | Working baseline DC | Samba 4.24.7 provision + `samba-tool`; build from pristine tree (patches from §4.6) | low |
| **P1** | Freeze interfaces | Extract `libadt`, `libdcerpc`, `libldb-ad` headers; document `DirectoryProvider`, `KdbBackend`, `AdMechanism`, `PacProvider` | medium |
| **P2** | Close DRSR XPRESS gap | Wire `lib/compression/lzxpress{,_huffman}.c` into `source4/rpc_server/drsuapi/getncchanges.c`; re-enable `DRSUAPI_SUPPORTED_EXTENSION_XPRESS_COMPRESS` (`drepl_service.c:122`) | **low–medium, high value** |
| **P3** | KDC modularization | Validate/repair the MIT `--with-system-mitkrb5` path against `selftest/knownfail_mit_kdc.d/`; ship as `--kdc` toggle | medium–high |
| **P4** | Client module | Package SSSD-derived `ad-client` (GPO client especially) + `winbind`/idmap | medium |
| **P5** | Gaps | `MS-W32T` RPC; FRS2/DFSR (or document DRS-SYSVOL as the supported model); any newer-ADTS controls | high |
| **P6** | Tooling/GUI | `ad-tool` polish + OpenRSAT-based `ad-gui` | medium |

## C.8 Gap backlog (explicitly not covered by any local project)

| Gap | Spec | Best route |
|---|---|---|
| XPRESS (LZXPRESS+Huffman) in DRS | MS-DRSR | **Reuse Samba `lib/compression/`** — cheapest win |
| DFSR / FRS2 RPC | MS-FRS2 | Write new, or standardize on DRS-based SYSVOL |
| `MS-W32T` RPC service | MS-W32T | Write new (small); `ntp_signd` already covers MS-SNTP |
| MIT-KDC feature parity | MS-KILE/SFU | Close `knownfail_mit_kdc.d` deltas (device auth etc.) |
| Non-AD LDAP engine path | MS-ADTS | `DirectoryProvider` adapter over 389-ds/OpenLDAP + `msuser.schema` (partial only) |
| Newer schema/control revisions | MS-ADSC/ADTS | Extend `source4/setup/ad-schema/` LDF replay |

## C.9 License matrix for the module set

| Module | Component license | Can link with? | Boundary |
|---|---|---|---|
| `libadt`, `libdcerpc`, `libldb-ad`, all `ad-*` (Samba-derived) | GPL-3.0 | GPL-3.0 + GPL-compatible (SSSD GPL-3.0+, OpenRSAT GPL-3.0) | in-process OK |
| `ad-kdc` core via MIT | MIT | anything | separate lib/module |
| `ad-kdc` core via Heimdal | BSD-3 | anything | separate lib/module |
| SASL mechanisms | BSD-style | anything | `.so` plugin |
| `ad-gpo-client`, `ad-client` (SSSD) | GPL-3.0+ | GPL-3.0 | process/module |
| Kanidm (if ever used) | MPL-2.0 | file-level copyleft | separate process |
| ApacheDS (reference only) | Apache-2.0 | anything | not shipped/in-process |
| OpenLDAP (alternate engine) | OPL-2.8 | GPL-compatible per FSF? — **verify** before linking | separate daemon is safest |

> ⚠️ **Licensing note:** a *permissive-only* Monarchy is only achievable for the KDC/SASL/LDAP-engine periphery (Option C). The AD protocol core (DRSR/SAMR/NRPC/LSAD/DSSP/GPOL/ADTS) has no permissive implementation in open source, so any permissive build would be incomplete by construction. Decide early whether Monarchy is GPL-3.0 (Option A/B) or permissive-but-partial (Option C).

---

## Appendix — how to read the companion documents

- **[`AD-RESEARCH-INDEX.md`](AD-RESEARCH-INDEX.md) Part 1** — the MS documentation index (spec IDs/URLs) and the 11-component synthesis of what an AD implementation must contain.
- **Part 2–4** — the Linux-AD project survey, the local tree maps, and the upstream/version comparison.
- **§4.6–4.7** — exactly which tarballs were acquired, from where, with which GPG fingerprints/SHA-256.
- **This document** — spec → best code → modularization. Use Part B's table as the working index and Part C as the construction plan.
