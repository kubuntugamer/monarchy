# Monarchy Research Index — Microsoft Active Directory & a Linux Reimplementation

> Research index compiled for the **Monarchy** project.
> Covers: (1) Microsoft Active Directory documentation & protocol specifications,
> (2) GitHub/open-source projects needed to implement AD on Linux, and
> (3) a scan of the local source trees in the research checkout (`ADclone/`).

---

## Part 1 — Microsoft Active Directory: Documentation Index

### 1.1 Conceptual & administrative documentation (Microsoft Learn)

| Resource | URL | Notes |
|---|---|---|
| Active Directory Domain Services overview | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview | Canonical AD DS overview: distributed database, forest/domain/OU hierarchy, Global Catalog, replication, FSMO |
| AD DS (TechNet archive, WS2008/2010) | https://technet.microsoft.com/en-us/library/cc753985(v=ws.10) | Classic component breakdown: forest, domain, DC, KDC, LDAP interface, SYSVOL, partitions, schema, W32Time |
| Directory Service (TechNet archive) | https://technet.microsoft.com/en-us/library/cc756395(v=ws.10) | Database = `Ntds.dit` + logs; default naming contexts: domain NC, configuration container, schema; SYSVOL replication |
| AD DS authentication & Kerberos (MS Learn training) | https://learn.microsoft.com/en-us/training/modules/active-directory-authentication-kerberos | Hands-on module: Kerberos in AD, troubleshooting |
| Compare directory-based services (AD DS vs Entra ID vs Entra DS) | https://docs.azure.cn/en-us/entra/identity/domain-services/compare-identity-solutions | Feature matrix: managed domain vs self-managed AD DS (GPO, trusts, schema extensions, LDAPS, LDAP read/write) |
| Microsoft Entra Domain Services (managed AD DS) | https://learn.microsoft.com/en-us/entra/identity/domain-services/overview | Cloud-managed domain: domain join, GPO, LDAP, Kerberos/NTLM without DCs |
| LDAP signing for AD DS | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing | Security hardening: LDAP signing + channel binding |

### 1.2 Protocol specifications (Microsoft Open Specifications)

The authoritative reference for anyone reimplementing AD. Published as HTML on Microsoft Learn and as PDFs in the archive `https://winprotocoldoc.z19.web.core.windows.net/` (e.g. `.../MS-ADTS/[MS-ADTS]-180316.pdf`). The full cross-reference matrix is **[MS-DOCO]** and the conceptual map is **[MS-ADOD]**.

**Core documents:**

| Doc ID | Title | What it specifies | URL |
|---|---|---|---|
| **[MS-ADOD]** | Active Directory Protocols Overview | Map of all AD protocols & how they relate — start here | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adod/af2580e0-f8f8-46ce-8598-1df6be10ab56 |
| **[MS-ADTS]** | Active Directory Technical Specification | The primary AD spec: abstract data model, LDAP behavior/extensions, DN forms (`<GUID=…>`, `<SID=…>`), directory operations, GC, KCC/topology | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a |
| **[MS-ADSC]** | AD Schema Classes | All classSchema definitions | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/ |
| **[MS-ADA1/2/3]** | AD Schema Attributes A–L / M / N–Z | All attributeSchema definitions (OID ↔ lDAPDisplayName mapping) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada1/ |
| **[MS-DRSR]** | Directory Replication Service (DRS) Remote Protocol | `drsuapi`/`dsaop` RPC interfaces: `DsGetNCChanges`, `DsReplicaSync`, `DsCrackNames`, USN/highwatermark/uptodatevector, conflict resolution, MSZIP/XPRESS compression | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/06205d97-30da-4fdc-a276-3fd831b272e0 |
| **[MS-SRPL]** | DRS Protocol Extensions (SMTP) | SMTP transport alternative for replication | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srpl/ |
| **[MS-SAMR]** | Security Account Manager (SAM) Remote Protocol | Account management RPC (subset of LDAP): domains, aliases, groups, users, handles | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380 |
| **[MS-SAMS]** | SAM Server-to-Server | Server-to-server SAM (domain replication of SAM data) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sams/ |
| **[MS-NRPC]** | Netlogon Remote Protocol | Secure channel to DC, DC discovery (`DsrGetDcName`), PASSTHRU, password change, `DsEnumerateDomainTrusts` | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ |
| **[MS-KILE]** | Microsoft Extensions to Kerberos | AD Kerberos profile: pre-auth, PAC embedding, delegation, claims, encryption types | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ |
| **[MS-PAC]** | Privilege Attribute Certificate | PAC structure: authorization data, group SIDs, delegation info, signatures | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/ |
| **[MS-SFU]** | S4U & Kerberos Constrained Delegation | S4U2Self / S4U2Proxy extensions | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/ |
| **[MS-NLMP]** | NTLM over SMB | NTLMSSP challenge/response, NTLMv2, signing, sealing (fallback auth) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c083583f-1a8f-4afe-a742-6ee08ffeb8cf |
| **[MS-SMB2]** | SMB2/3 Protocol | File access to SYSVOL and shares on a DC | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ |
| **[MS-LSAD]** | LSA (Domain Policy) Remote Protocol | Policy secrets, account policy retrieval | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/ |
| **[MS-LSAT]** | LSA Translation Methods | SID ↔ name lookup (LookupSids/LookupNames) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/ |
| **[MS-DSSP]** | Directory Services Setup Remote Protocol | `DsGetDcName`, site/subnet enumeration, DSSecurityInfo | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dssp/ |
| **[MS-DTYP]** | Windows Data Types | SID, GUID, SECURITY_DESCRIPTOR, access masks — foundational | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/ |
| **[MS-GPOL]** | Group Policy: Core Protocol | GPO discovery/application over LDAP+DRS RPC, SOM/GPLink model | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/595ec4ac-95eb-4d56-bec6-aed0e47fb202 |
| **[MS-GPSI]** | Group Policy: System Internals | GPO storage in SYSVOL, file paths (`\\...\SYSVOL\...`), GPT.ini | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsi/ |
| **[MS-FRS1] / [MS-FRS2]** | FRS / DFS-R | SYSVOL replication (FRS = legacy, DFS-R = 2008+) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-frs2/ |
| **[MS-W32T]** | Windows Time Service | Time sync requirements for Kerberos | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-w32t/ |
| **[MS-ADSO]** | Active Directory System Overview (archive, 2014) | 235-page system-level overview | https://winprotocoldoc.z19.web.core.windows.net/WinArchive/[MS-ADSO].pdf |
| **[MS-DOCO]** | Windows Protocols Documentation Roadmap | Master index/cross-reference of all MS-* specs | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-doco/f7cc0d8f-e9fa-4f0c-a0af-c1b158957c84 |
| **[MS-WPO]** | Windows Protocols Overview | Conceptual overview of all Windows protocols | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wpo/ |

**Supporting/adjacent specs:** MS-ADCAP & MS-WSDS (AD Web Services/SOAP management), MS-CSSP (CredSSP), MS-TLSP & MS-SPNG (SASL), MS-PKINIT (Kerberos PKINIT), MS-EVEN6 (event log), MS-RPCE (RPC runtime all these RPC interfaces ride on), MS-ERREF (error codes), MS-FSCC/MS-FSA (file semantics).

### 1.3 What an AD implementation must contain (synthesis)

1. **Directory database** — hierarchical LDAP store with three naming contexts (domain NC, configuration NC, schema NC) plus application partitions; objects = schema classes/attributes; Global Catalog = partial replica (PAS) of every NC in the forest.
2. **LDAP service** — RFC 4511/4512 + AD extensions: controls (paged results, show-deleted/LDAP_SERVER_SHOW_DELETED_OID, SD flags, ranged attributes), extended operations (password change, dirsync), SASL (GSSAPI/NTLM/LDAP channel binding), string-name forms `<GUID=…>`, `<SID=…>`, `<GUID=…>` baseObject lookups.
3. **Schema engine** — classSchema/attributeSchema in the schema NC, syntaxes/OIDs, linkIDs (group membership backlinks), defunct handling; MS-ADSC/MS-ADA1-3 are the ground truth.
4. **Kerberos KDC** — realm = uppercase DNS domain; krbtgt account; service tickets with PAC (MS-PAC); KILE extensions; S4U2Self/S4U2Proxy; NTLM fallback; secure channel (MS-NRPC) for DC↔member and DC↔DC.
5. **Replication (DRS/MS-DRSR)** — multi-master: per-attribute USNs, `invocationId`, highwatermark vector, uptodatevector, originating-vs-direct update conflict resolution, tombstones, ISTG/KCC topology generation, GC propagation.
6. **SYSVOL** — SMB share of GPOs + scripts replicated between DCs via DFS-R (MS-FRS2).
7. **Group Policy** — GPOs (GPC in LDAP, GPT in SYSVOL), GPLink/SOM processing (MS-GPOL/MS-GPSI).
8. **DNS** — AD-integrated zone, dynamic updates (GSS-TSIG), SRV locator records (`_ldap._tcp.dc._msdcs.<domain>`, `_kerberos._tcp`), `_msdcs` forest zone.
9. **Operations masters (FSMO)** — 5 roles: Schema Master, Domain Naming Master, RID Master, PDC Emulator, Infrastructure Master.
10. **Security** — SIDs/RIDs, security descriptors on every object, token construction via PAC, password policies/PSOs, protected accounts, LDAP signing/channel binding.
11. **Time sync** (W32Time) and **site topology** (sites/subnets/siteLinks) for Kerberos and replication scheduling.

---

## Part 2 — Open-source projects for a Linux implementation of AD

### 2.1 The reference implementation: Samba AD DC (the only complete one)

| Project | URL | License | Role |
|---|---|---|---|
| **Samba** (`samba-team/samba`) | https://gitlab.com/samba-team/samba · https://github.com/samba-team/samba | GPLv3 | Full AD DC since 4.0 (2012): LDAP server, Kerberos KDC (embedded Heimdal; optional MIT KDC), DRS replication with Windows DCs, internal DNS, SYSVOL/SMB, samba-tool admin CLI. Operates at forest functional level **Windows Server 2008 R2**. |

Key Samba documentation:
- Setting up Samba as an AD DC — https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller (`samba-tool domain provision --use-rfc2307 --server-role=dc --dns-backend=SAMBA_INTERNAL`)
- Samba internal DNS back end — https://wiki.samba.org/index.php/Samba_internal_DNS_Back_End (no recursion/zone transfer; forwards)
- Running a Samba AD DC with MIT Kerberos KDC — https://wiki.samba.org/index.php/Running_a_Samba_AD_DC_with_MIT_Kerberos_KDC
- SysVol replication (DFS-R / rsync workarounds) & DRS — https://wiki.samba.org/index.php/User_Documentation
- Samba user documentation index — https://wiki.samba.org/index.php/User_Documentation

### 2.2 Protocol building blocks (the four trees vendored in this repo)

| Project | Repo | License | AD role |
|---|---|---|---|
| **Samba 4.24.7** | gitlab.com/samba-team/samba | GPLv3 | Everything AD: `source4/` (AD DC), LDB (LDAP DB), dsdb, drsuapi, KDC, LDAP server, samba-tool |
| **OpenLDAP 2.6.13** | https://github.com/openldap/openldap (mirror) / https://www.openldap.org/ | OL/HR-PL style (open) | slapd: alternative/complementary LDAP server; overlays relevant to AD-like behavior: `syncprov` (replication), `refint`, `memberof`, `ppolicy`, `pw-pbkdf2`, `dds` |
| **MIT krb5 1.22.1** | https://github.com/krb5/krb5 | MIT-style | KDC (AS/TGS), kadmind, **`kdb_ldap`** backend (can store principals in LDAP — usable as an AD-style LDAP-backed KDC), PKINIT |
| **Cyrus SASL 2.1.28** | https://github.com/cyrusimap/cyrus-sasl | BSD-style | SASL framework for LDAP/other services: `GSSAPI`, `GSS-SPNEGO`, `NTLM` plugins |
| (Heimdal, alternative KDC) | https://github.com/heimdal/heimdal | BSD-3 | What Samba embeds by default (`source4/heimdal/`); HDB interface to LDB via `kdc/hdb-samba4.c` |

### 2.3 Integrated Linux IAM stacks (AD-like, but mostly *not* AD-protocol-compatible)

| Project | URL | Notes |
|---|---|---|
| **FreeIPA** | https://github.com/freeipa/freeipa · https://www.freeipa.org/ | Bundles 389-ds (LDAP) + MIT Kerberos + Dogtag CA + DNS + SSSD; multi-master; **one-way trust with real Microsoft AD** (extdom plugin); the classic "Linux AD" but uses its own schema, not AD protocols |
| **389-ds** | https://github.com/DirectoryServer/389-ds · https://www.port389.org/docs/389ds/design/architecture | The LDAP engine under FreeIPA; multi-master replication (ChangelogBasedReplication), memberof plugin, password policy |
| **Kanidm** | https://github.com/kanidm/kanidm | Rust IDM: OAuth2/OIDC, WebAuthn/passkeys, RADIUS, SSH keys, **read-only LDAP gateway**; faster & lighter than FreeIPA; no AD protocol compatibility |
| **LLDAP** | https://github.com/lldap/lldap | Rust, tiny (~15 MiB RAM), web UI, SQLite/MySQL/Postgres; purpose-built as a *simple* LDAP auth provider — good design reference for a minimal AD-schema-compatible server, not a DC |
| **glauth** | https://github.com/glauth/glauth | Go LDAP server, config-file driven, lightweight |
| **Apache Directory Server** | https://directory.apache.org/ | Java LDAPv3 server with schema editor (Apache Studio) |

### 2.4 Client-side integration (Linux clients ↔ a DC)

- **SSSD** — https://github.com/SSSD/sssd — LDAP/Kerberos/AD provider for NSS/PAM, offline auth, sudo rules
- **winbind + pam_winbind/nss_winbind** (Samba) — AD group/user mapping on members
- **Samba as domain member** — https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Domain_Member
- **FreeIPA ↔ AD trust** — https://freeipa.readthedocs.io (one-way trust, ID ranges, `ipa-ad-trust`)

### 2.5 Administration tooling (RSAT alternatives)

- `samba-tool` (user/computer/group/dns/gpo/drs/trust/backup management) — https://manpages.ubuntu.com/manpages/focal/man8/samba-tool.8.html
- `ldbsearch/ldbdel/ldbmodify` (LDB tools), `ldapsearch` (OpenLDAP clients)
- **OpenRSAT** — https://github.com/tranquilit/OpenRSAT — manage Samba AD from Linux/macOS
- Python `ldap3` / `python-ldap`, Rust `ldap3` crate (client libs with AD channel-binding support)

### 2.6 Feature matrix: what each option gives you vs. real AD

| Capability | Real AD DS | Samba AD DC | FreeIPA | Kanidm | LLDAP |
|---|---|---|---|---|---|
| AD LDAP schema & semantics | ✔ | ✔ | ✖ (own schema) | ✖ | ✖ |
| Kerberos KDC | ✔ (MS-KILE) | ✔ (Heimdal/MIT) | ✔ (MIT) | ✖ (OIDC) | ✖ |
| NTLM | ✔ | ✔ | partial | ✖ | ✖ |
| PAC / S4U delegation | ✔ | ✔ | partial | ✖ | ✖ |
| DRS replication (interop w/ Windows) | ✔ | ✔ | ✖ | ✖ | ✖ |
| GPO (MS-GPOL/GPSI) + SYSVOL | ✔ | ✔ (storage/processing) | ✖ (HBAC/sudo) | ✖ | ✖ |
| AD-integrated DNS | ✔ | ✔ (internal/BIND DLZ) | ✔ (Bind) | ✖ | ✖ |
| SMB file shares as DC | ✔ | ✔ | via Samba member | ✖ | ✖ |
| Domain trust with Microsoft AD | ✔ | ✔ | one-way trust | ✖ | ✖ |
| Forest functional level | 2016/2025 | 2008 R2 | n/a | n/a | n/a |

**Conclusion for Monarchy:** Samba 4 is the only project implementing the actual AD wire protocols end-to-end. A from-scratch "Linux AD" would combine: an LDAP server with AD schema semantics (OpenLDAP slapd or custom over LDB), a Kerberos KDC with PAC support (MIT krb5 + kdb_ldap + PAC glue, or Heimdal), SASL (Cyrus: GSSAPI/NTLM), DRS replication (hardest part — only Samba has a working non-Windows implementation), plus DNS, SYSVOL and GPO layers. The local tree already contains Samba + OpenLDAP + MIT krb5 + Cyrus SASL — i.e., exactly these building blocks.

---

## Part 3 — Local source scan (`ADclone/` research checkout)

_Scanned source trees below; see per-tree maps._

### 3.1 Inventory

| Item | Version | Purpose in Monarchy |
|---|---|---|
| `samba-4.24.7+dfsg/` | 4.24.7 | AD DC (LDAP, KDC, DRS, DNS, SMB, samba-tool) |
| `openldap-2.6.13+dfsg/` | 2.6.13 | slapd LDAP server + overlays |
| `krb5-1.22.1/` | 1.22.1 | MIT KDC + kdb_ldap |
| `cyrus-sasl2-2.1.28+dfsg1/` | 2.1.28 | SASL auth framework |
| `samba-4.24.7/` + `samba-4.24.7.tar.gz` (+`.tar.asc`) | 4.24.7 | **pristine upstream** AD DC, GPG-verified, fills dfsg tree's 26 missing `ctdb/doc` files (see §4.6) |
| `krb5-1.22.2/` + `krb5-1.22.2.tar.gz` | 1.22.2 | **pristine upstream** MIT KDC (upgraded acquisition — see §4.6) |
| `openldap-2.6.15/` + `openldap-2.6.15.tgz` (+`.asc`) | 2.6.15 | **pristine upstream** slapd, current LTS (see §4.6) |
| `openldap-2.7.1/` + `openldap-2.7.1.tgz` (+`.asc`) | 2.7.1 | **pristine upstream** slapd, current feature release, for evaluation (see §4.6) |
| `heimdal-7.8.0/`, `freeipa-4.13.4/`, `389-ds-base-3.3.1/`, `kanidm-1.11.2/`, `lldap-0.6.3/`, `glauth-GLAuth-v2.5.4/`, `sssd-2.13.1/`, `apacheds-parent-2.0.0-M11/`, `OpenRSAT-0.4.519/` (+ **`kanidm-1.11.2-git/`, `glauth-GLAuth-v2.5.4-git/`, `OpenRSAT-0.4.519-git/`** recursive clones with submodules) | mixed | reference/alternative projects from Part 2 (Heimdal, FreeIPA, 389-ds, Kanidm, LLDAP, glauth, SSSD, Apache DS, OpenRSAT) — see §4.7 |
| `Monarchy/` | — | project/scratch dir (this index lives here) |
| `*.orig.tar.xz`, `*.debian.tar.xz`, `*.dsc` | — | Debian source packages the trees were unpacked from |

### 3.2 Per-tree code maps

#### Samba 4.24.7 — `samba-4.24.7+dfsg/` (the AD DC)

**Top-level layout:**

| Directory | Purpose |
|---|---|
| `source4/` | **The AD DC**: LDAP server, KDC, DRS RPC servers, dsdb, DNS server, NBT, provisioning |
| `source3/` | Classic SMB2/3 file server (smbd) — reused inside the DC for SYSVOL/netlogon shares |
| `auth/` | **Shared** auth code: gensec, **NTLMSSP**, Kerberos helpers, PAC parsing, credentials, schannel |
| `lib/` | In-tree core libs: **`ldb/`** (LDAP DB engine), `talloc`, `tdb`, `tevent`, `krb5_wrap/` (Heimdal/MIT abstraction), `crypto/`, `addns/` |
| `libcli/` | Client libs incl. `auth/` (NTLMv2 checking `ntlm_check.c`, netlogon creds, SPNEGO) |
| `librpc/` | DCE/RPC: **`idl/`** — all MS-RPC IDL (drsuapi, lsa, samr, netlogon, krb5pac, dnsserver); stubs generated by `pidl/` |
| `libgpo/` | Group Policy Object helpers |
| `nsswitch/` | `winbindd` + nss/pam modules |
| `python/` | **`samba/provision/`** (domain provisioning), **`samba/netcmd/`** (`samba-tool`), `ms_schema.py` |
| `third_party/` | **`heimdal/`** (bundled mini-Heimdal KDC) + `heimdal_build/` (Samba glue), popt, cmocka |
| `docs-xml/` | Manpages + smb.conf reference (HOWTOs moved to wiki.samba.org) |
| `buildtools/` | Waf build system (`wafsamba`) |
| `source4/setup/` | Provisioning LDIFs, **`ad-schema/`** (Microsoft schema dumps), `schema_samba4.ldif`, `display-specifiers/`, `extended-rights.ldif`, `adprep/` |

**`source4/` AD DC components:**

- **`source4/dsdb/`** — the AD database (samdb) layer on LDB:
  - `samdb/samdb.c` — SamDB LDB handle API used everywhere by the DC
  - `samdb/ldb_modules/` (~60 modules, the heart of AD-on-LDB): `objectclass.c`, `objectguid.c`, `extended_dn_*.c`, **`repl_meta_data.c`** (attribute-level replication metadata/USN), **`acl.c`/`acl_read.c`/`descriptor.c`** (AD ACL engine), `password_hash.c` (unicodePwd/NT hash), `partition*.c` (NC partitions), `ridalloc.c`, **`dirsync.c`** (DirSync/MS-DRSDirSyncToken control), `paged_results.c`, `vlv_pagination.c`, `rootdse.c`, `samldb.c` (user/group/computer objects), `schema_load.c`, `tombstone_reanimate.c`, `show_deleted.c`, `linked_attributes.c`
  - `schema/` — in-memory schema engine: `schema_init.c`, `schema_prefixmap.c` (OID↔prefixMapID), `schema_syntax.c`, `schema_inferiors.c`
  - `repl/` — DREPL service (replication orchestration): `drepl_service.c`, `drepl_out_pull.c`, **`drepl_fsmo.c`** (FSMO role holders), `drepl_ridalloc.c`
  - `kcc/` — Knowledge Consistency Check: `kcc_service.c`/`kcc_periodic.c` (topology), `garbage_collect_tombstones.c`, `scavenge_dns_records.c`
- **`source4/kdc/`** — Kerberos KDC (MS-KILE/PAC/kpasswd):
  - Heimdal path (default): `kdc-heimdal.c`, **`hdb-samba4.c`** (Heimdal HDB backed by SamDB), `db-glue.c`, `wdc-samba4.c` (PAC decoration window), `kdc-glue.c`
  - MIT path (experimental): `kdc-service-mit.c`, `mit_samba.c` (KDB module), `mit_kdc_irpc.c`, `mit-kdb/`
  - PAC: **`pac-glue.c`** (builds `PAC_LOGON_INFO` from samdb: group/resource-group/claims), `pac-blobs.c`, `ad_claims.c`
  - kpasswd: `kpasswd-service*.c`; KDC proxy: `kdc-proxy.c` (HTTP 88 tunneling)
- **`source4/ldap_server/`** — AD LDAP server (MS-ADTS): `ldap_server.c`, `ldap_bind.c` (SASL/GSSAPI & simple), `ldap_backend.c` (LDAP→LDB mapping), `ldap_extended.c` (DirSync etc. extended ops)
- **`source4/rpc_server/`** — DCE/RPC servers:
  - **`drsuapi/`** (MS-DRSR): `dcesrv_drsuapi.c`, **`getncchanges.c`** (replication pull engine), `updaterefs.c`, `addentry.c`, `drsutil.c`, `writespn.c`
  - `lsa/` (`lsa_lookup.c` — name translation), `samr/` (accounts), `netlogon/` (secure channel, SamLogon, DsRGetDCName), `dnsserver/` (MS-DNSP DNS management RPC)
- **Shared auth** (`auth/` + `libcli/auth/`): `auth/ntlmssp/` — **full NTLMSSP** (`ntlmssp_server.c/client.c/sign.c`), `auth/gensec/spnego.c`, **`auth/gensec/schannel.c`** (NETLOGON secure channel), `libcli/auth/ntlm_check.c` (NTLMv2), `auth/kerberos/kerberos_pac.c`/`gssapi_pac.c` (PAC verify)
- **`source4/dns_server/`** — AD-integrated DNS: `dns_server.c`, `dns_update.c` (RFC 2136 dynamic updates, GSS-TSIG), `dns_crypto.c`, `dlz_bind9.c` (BIND DLZ)
- **`source4/samba/`** — server core/process models; starts services: `smb`, `kdc`, `ldap`, `rpc`, `drepl`, `kcc`, `dns`, `nbt`
- **`source4/smb_server/`** — SMB service wrapping source3 (serves SYSVOL/netlogon with NT ACLs)
- **Provisioning**: `python/samba/provision/__init__.py` (creates SYSVOL share, default GPOs, applies `aggregate_schema.ldif`), `python/samba/netcmd/domain/{provision,join,dcpromo,demote,classicupgrade,schemaupgrade,trust}.py`, CLI `source4/scripting/bin/samba-tool`

**AD schema assets (ground truth for Linux AD):**
- `source4/setup/ad-schema/` — **Microsoft's own schema dumps**: `MS-AD_Schema_2K8{,_R2}_{Attributes,Classes}.txt` + `.ldf` LDIFs for WS2008R2/2012/2012R2/2016/v1803/1903 (MS-ADSL licensed, `licence.txt`)
- `python/samba/ms_schema.py` — parses WSPP `.txt` docs → LDIF at provision time (bit-field semantics per MS-ADTS §2.2.9/2.2.10); `python/samba/schema.py` `add_schema()` loads it, sets prefix map
- Static: `source4/setup/schema_samba4.ldif`, `aggregate_schema.ldif`, `prefixMap.txt`, `extended-rights.ldif`, `adprep/` LDIFs

**Protocol → file quick index:**

| Protocol | Key files |
|---|---|
| DRS replication (MS-DRSR) | `librpc/idl/drsuapi.idl`, `drsblobs.idl`; `source4/rpc_server/drsuapi/{getncchanges,updaterefs,addentry,drsutil}.c`; `source4/dsdb/repl/*`, `kcc/*`; `samdb/ldb_modules/{repl_meta_data,dirsync,partition*}.c`; tests `source4/torture/drs/` |
| LDAP server (MS-ADTS) | `source4/ldap_server/*` + `source4/dsdb/samdb/` |
| Kerberos KDC (MS-KILE) | `source4/kdc/{kdc-heimdal,hdb-samba4,db-glue,kdc-glue,wdc-samba4}.c`; MIT: `{kdc-service-mit,mit_samba,mit_kdc_irpc}.c` |
| PAC (MS-PAC) | IDL `librpc/idl/krb5pac.idl`; gen `source4/kdc/{pac-glue,pac-blobs,wdc-samba4}.c`; verify `auth/kerberos/{kerberos_pac,gssapi_pac}.c`; claims `source4/kdc/ad_claims.c` |
| NTLMSSP (MS-NLMP) | `auth/ntlmssp/*`, `libcli/auth/{ntlm_check,smbencrypt}.c`, `auth/gensec/spnego.c` |
| Secure channel (MS-NRPC) | `auth/gensec/schannel.c`, `libcli/auth/netlogon_creds_cli.c`, `source4/rpc_server/netlogon/`, `samdb/ldb_modules/netlogon.c` |
| SAMR / LSA | `source4/rpc_server/{samr,lsa}/`; `samldb.c`, `ridalloc.c` |
| DNS (MS-DNSP) | `source4/dns_server/*`, `source4/rpc_server/dnsserver/`, `librpc/idl/dnsserver.idl` |
| GPO / Group Policy | `libgpo/`, `source4/setup/provision_group_policy.ldif`, client CSE `source4/scripting/bin/samba-gpupdate` |

**Build & Kerberos backend:**
- **Waf** build (`buildtools/wafsamba/`): `./configure && make`; default prefix `/usr/local/samba`; AD DC can be disabled with `--without-ad-dc`
- Kerberos selection (top-level `wscript:79–103, 348–400`):
  - **Default: bundled mini-Heimdal** → `third_party/heimdal/` (full Heimdal incl. `kdc/`, `hdb`, `gssapi`) with Samba glue in `third_party/heimdal_build/`
  - `--with-system-heimdalkrb5` → link system Heimdal
  - `--with-system-mitkrb5` → **experimental MIT-KDC AD DC** (uses `source4/kdc/mit-kdb/` KDB module + `mit_kdc_irpc.c` IRPC bridge) — *directly relevant: the local tree has MIT krb5 1.22.1*
- Hard deps: xattr, ACL and LDAP headers; flex (embedded Heimdal); GnuTLS
- Version file: `VERSION` → 4.24.7 (release)

**Caveats:**
- `libds/` has shrunk to `libds/common/flag_mapping.c` in 4.24 — the real DS layer is `source4/dsdb/` (LDB modules)
- PAC/NTLMSSP/gensec code is shared source3+source4 → lives at top level `auth/`, `libcli/auth/`, not under `source4/`
- In-tree bundled libs retained in dfsg repack: `lib/{talloc,tdb,tevent,ldb,replace,tsocket,tdr}`
- `source4/auth/kerberos/{kerberos-notes.txt,kerberos-porting-to-mit-notes.txt}` — design notes on the Kerberos layer & MIT porting (must-read for Monarchy)

#### OpenLDAP 2.6.13 — `openldap-2.6.13+dfsg/`

| Path | Contents |
|---|---|
| `configure`, `Makefile.in`, `build/*.mk` | autoconf + OpenLDAP's own make machinery (**no automake/cmake**) |
| `include/` | public headers (`ldap.h`, `lber.h`) |
| `libraries/` | `liblber`, `libldap`, **`liblmdb`** (bundled LMDB), `liblunicode`, `liblutil`, `librewrite` |
| `servers/slapd/` | the slapd server: `bind.c add.c search.c modify.c delete.c modrdn.c`, `acl.c`, `sasl.c saslauthz.c`, `syncrepl.c ldapsync.c`, `schema*.c`, `config.c`, **`bconfig.c`** (back-config, compiled unconditionally — runtime CN=Config) |
| `servers/slapd/back-*/` | **back-mdb** (primary, LMDB-backed: `dn2id.c idl.c index.c search.c …`), back-sql (RDBMS mapping, schema-map reference), back-ldap/meta/asyncmeta, back-ldif, back-monitor, back-dnssrv, back-perl, back-sock, … |
| `servers/slapd/overlays/` | **AD-relevant**: `ppolicy.c` (password policy = FGPP analogue), `refint.c` (referential integrity), `memberof.c`, **`syncprov.c`** (syncrepl provider = replication), plus accesslog, constraint, dynlist, dds, sssvlv, unique, valsort, rwm… |
| `servers/slapd/schema/` | **the schema dir** (not `etc/schema/`). Contains **`msuser.schema` / `msuser.ldif`** — Microsoft AD schema (Win2000→Server 2012), OID root `1.2.840.113556.1`; plus core/cosine/inetorgperson/nis… |
| `contrib/slapd-modules/` | `samba4`, `smbk5pwd`, `lastbind`, `nssov`, `ppm`, `adremap` |
| `debian/`, `.pc/` | Debian packaging; ⚠️ `core.schema` etc. stripped into `debian/schema/` (DFSG) and copied back by `debian/rules` before build |

- **Build**: `./configure && make depend && make`; `--enable-modules` (default no → static), `--enable-mdb` (yes), `--enable-overlays=mod`, `--enable-ppolicy/refint/memberof/syncprov=mod`
- **Deps**: Cyrus SASL ≥ 2.1.27, OpenSSL ≥ 1.1.1, optional libevent 2.1.8+ (lloadd), argon2

#### MIT Kerberos 1.22.1 — `krb5-1.22.1/` (all buildable code in `src/`)

| Path | Contents |
|---|---|
| `src/kdc/` | **the KDC**: `dispatch.c do_as_req.c do_tgs_req.c kdc_util.c kdc_authdata.c kdc_preauth.c fast_util.c policy.c replay.c` + **`ndr.c`/`t_ndr.c`** (NDR marshalling for PAC) |
| `src/lib/krb5/krb/` | **`pac.c`, `pac_sign.c`** (PAC build/verify/sign — MS-PAC), asn.1 encoders (`asn1_k_encode.c` has KILE refs) |
| `src/lib/gssapi/krb5/` | `s4u_gss_glue.c` (S4U2Self / PA-FOR-USER), `accept_sec_context.c` (KILE), `k5seal.c`/`k5unseal.c` (RFC 1964 / RFC 4757 §7 GSS tokens), `k5sealv3.c`/`k5unsealv3.c` (RFC 4121 Wrap tokens), `util_seqnum.c` (sequence-number derivation) |
| `src/plugins/kdb/ldap/` | **LDAP KDB backend**: `libkdb_ldap/kdb_ldap.c kdb_ldap_conn.c ldap_create.c ldap_principal.c ldap_realm.c ldap_pwd_policy.c ldap_tkt_policy.c lockout.c` + `kerberos.schema/kerberos.ldif` schema for storing principals **in LDAP** (AD-style single store); also `src/plugins/kdb/db2/`, `src/plugins/kdb/lmdb/` |
| `src/kadmin/server/` | kadmind: `ovsec_kadmd.c kadm_rpc_svc.c server_stubs.c auth_acl.c ipropd_svc.c schpw.c` (incremental prop = iprop) |
| `src/kadmin/cli/`, `dbutil/`, `ktutil/` | `kadmin(.local)`, **`kdb5_util`** (create/dump/load/mkey), `ktutil` |
| `src/kprop/` | `kprop.c kpropd.c kproplog.c` (DB propagation) |
| `src/clients/` | `kinit klist kdestroy kswitch kvno kpasswd ksu` |
| `src/plugins/` | plugin dirs: `kdb`, `authdata`, `preauth`, `kdcpolicy`, `kadm5_auth`, `hostrealm`, `localauth`, `pwqual`, `tls`, `gssapi`, `audit`, `certauth` |
| `src/configure.ac` + hand-written `Makefile.in`s | autoconf only; `cd src && ./configure && make`; **yacc required** (`kadmin/cli/getdate.y`); optional OpenSSL (PKINIT/TLS) |

#### Cyrus SASL 2.1.28 — `cyrus-sasl2-2.1.28+dfsg1/`

| Path | Contents |
|---|---|
| `include/sasl.h`, `saslplug.h` | public API + plugin API (`SASL_VERSION 2.1.28`) |
| `lib/` | client/server lib: `client.c server.c common.c auxprop.c canonusr.c checkpw.c config.c dlopen.c external.c` |
| `plugins/` | **AD-relevant mechs**: **`gssapi.c`/`gssapiv2_init.c` → libgssapiv2**; **`gs2.c`/`gs2_token.c` → libgs2** (GSSAPI-based, `--with-gssapi`); **`ntlm.c`/`ntlm_init.c` → libntlm**. Others: plain, scram, digestmd5, otp, srp, login, ldapdb (auxprop over LDAP), sasldb, sql |
| `common/plugin_common.c` | shared plugin helpers |
| `sasldb/`, `saslauthd/` | sasldb auxprop; saslauthd incl. `auth_ldap.c`/`lak.c` (LDAP password verification) |
| build | autoconf + **automake** + libtool modules; `libsasl2.pc.in`; deps: BDB/GDBM/**LMDB** (sasldb only), OpenSSL, optional LDAP/SQL/PAM |

### 3.3 Cross-cutting findings for Monarchy

- **Two full AD schema sources are already local**: `samba-4.24.7+dfsg/source4/setup/ad-schema/` (Microsoft's own WSPP schema dumps, 2008R2→1903, MS-ADSL licensed) and `openldap-2.6.13+dfsg/servers/slapd/schema/msuser.schema` (Microsoft OID `1.2.840.113556.1`, Win2000→2012 attributes). Samba additionally generates the schema at provision time via `python/samba/ms_schema.py`.
- **AD-like behaviors from slapd overlays**: `ppolicy` (Fine-Grained Password Policies analogue), `syncprov`+`accesslog` (replication), `memberof`, `refint` — the pieces to build an AD-shaped LDAP service without Samba's LDB.
- **PAC/MS-KILE in MIT krb5**: `src/kdc/{do_tgs_req.c, kdc_authdata.c, ndr.c}` + `src/lib/krb5/krb/{pac.c, pac_sign.c}` + `src/lib/gssapi/krb5/s4u_gss_glue.c` — MIT krb5 already implements the AD Kerberos extensions and PAC signing, so an LDAP-backed KDC (`plugins/kdb/ldap`) can issue AD-style tickets.
- **LDAP bind auth**: slapd needs Cyrus SASL ≥ 2.1.27; the GSSAPI/GS2 and NTLM plugins here cover the two AD bind mechanisms.
- **Single-store option**: MIT krb5 `kdb_ldap` can hold the Kerberos DB inside the same LDAP tree as users (principals as `krbPrincipalName` attributes) — the FreeIPA/Samba model.
- **Build order/deps**: cyrus-sasl → openldap (needs SASL ≥ 2.1.27, OpenSSL ≥ 1.1.1) → krb5 (c89 + yacc) ; all three trees are Debian-repackaged (have `debian/` + `.pc/` quilt dirs); OpenLDAP's DFSG repack moves some schema into `debian/schema/` and restores it via `debian/rules`.
- **Samba's MIT-KDC bridge is the integration seam**: Samba normally embeds mini-Heimdal (`third_party/heimdal/`), but `--with-system-mitkrb5` wires the DC to a system MIT krb5 via `source4/kdc/mit-kdb/` (KDB module) + `mit_kdc_irpc.c`. Since this repo vendors MIT krb5 1.22.1 alongside Samba 4.24.7, this is the natural path for Monarchy: Samba's AD machinery (LDAP, DRS, DNS, PAC glue) + the standalone MIT KDC rather than the embedded Heimdal.
- **Samba's replication/topology engine to study or reuse**: `source4/dsdb/repl/` (DREPL orchestration, FSMO), `source4/dsdb/kcc/` (KCC topology), `source4/rpc_server/drsuapi/getncchanges.c` (the actual MS-DRSR pull engine) — DRS is the single hardest AD protocol and Samba's is the only non-Windows implementation.
- **LDB vs slapd trade-off**: Samba implements AD semantics as ~60 LDB modules (`source4/dsdb/samdb/ldb_modules/`) over `lib/ldb` — schema enforcement, ACLs, replication metadata, password hashing all as DB modules. OpenLDAP achieves similar ends via slapd overlays. Monarchy can either (a) build on Samba's dsdb stack directly, or (b) approximate AD with slapd + `msuser.schema` + overlays (`ppolicy`/`syncprov`/`memberof`/`refint`) — (b) is lighter but will not speak MS-DRSR.
- **NTLMSSP and PAC code is shared and portable**: Samba's `auth/ntlmssp/` and `auth/kerberos/kerberos_pac.c` live outside `source4/`, and MIT krb5 has its own PAC implementation (`lib/krb5/krb/pac*.c`) — two independent references for MS-PAC.
- **Protocols fully implemented in Samba worth mirroring**: MS-ADTS (LDAP), MS-DRSR, MS-SAMR, MS-LSA(D/AT), MS-NRPC, MS-KILE, MS-PAC, MS-NLMP, MS-DNSP, MS-GPOL storage — the IDL files in `librpc/idl/` are the machine-readable protocol definitions (drsuapi.idl, lsa.idl, samr.idl, netlogon.idl, krb5pac.idl, dnsserver.idl) and are the best single summary of the AD RPC surface.

---

## Part 4 — Upstream repository comparison (verified 2026-10-19)

### 4.1 Source repositories of all listed projects

All URLs verified live via `git ls-remote` on 2026-10-19 (✔ = reachable).

**Vendored in this repo (have local source directories):**

| Project | Official upstream repo | Other refs | Local |
|---|---|---|---|
| Samba | ✔ https://gitlab.com/samba-team/samba (official, samba-team org) | GitHub mirror: https://github.com/samba-team/samba · tarballs https://download.samba.org/pub/samba/stable/ · wiki https://wiki.samba.org | ✔ `samba-4.24.7+dfsg/` |
| OpenLDAP | ✔ https://git.openldap.org/openldap/openldap (official cgit) | Mirrors: https://github.com/openldap/openldap · https://git.launchpad.net/openldap · tarballs https://www.openldap.org/software/release/ | ✔ `openldap-2.6.13+dfsg/` |
| MIT krb5 | ✔ https://github.com/krb5/krb5 (official) | tarballs https://web.mit.edu/kerberos/dist · release notes https://web.mit.edu/kerberos/krb5-1.22/ | ✔ `krb5-1.22.1/` |
| Cyrus SASL | ✔ https://github.com/cyrusimap/cyrus-sasl (official) | upstream also at git.cyrusimap.org | ✔ `cyrus-sasl2-2.1.28+dfsg1/` |

**Listed alternatives (all local copies acquired 2026-10-19 — see §4.7):**

| Project | Repo (✔ verified) | Local |
|---|---|---|
| Heimdal | ✔ https://github.com/heimdal/heimdal | ✔ `heimdal-7.8.0/` |
| FreeIPA | ✔ https://codeberg.org/freeipa/freeipa (**official — moved off GitHub**; releases are here) · mirror https://github.com/freeipa/freeipa | ✔ `freeipa-4.13.4/` |
| 389-ds | ✔ https://github.com/389ds/389-ds-base (current official) · older org https://github.com/DirectoryServer/389-ds | ✔ `389-ds-base-3.3.1/` |
| Kanidm | ✔ https://github.com/kanidm/kanidm | ✔ `kanidm-1.11.2/` |
| LLDAP | ✔ https://github.com/lldap/lldap | ✔ `lldap-0.6.3/` |
| glauth | ✔ https://github.com/glauth/glauth | ✔ `glauth-GLAuth-v2.5.4/` |
| SSSD | ✔ https://github.com/SSSD/sssd | ✔ `sssd-2.13.1/` |
| Apache Directory Server | ✔ https://github.com/apache/directory-server · source releases https://archive.apache.org/dist/directory/apacheds/ | ✔ `apacheds-parent-2.0.0-M11/` |
| OpenRSAT | ✔ https://github.com/tranquilit/OpenRSAT | ✔ `OpenRSAT-0.4.519/` |

### 4.2 Local versions vs. current upstream releases

| Project | Local tree | Upstream latest (2026-10-19) | Released | Status |
|---|---|---|---|---|
| **Samba** | 4.24.7 (Sep 9, 2026) | **4.24.7** = latest stable; 4.25.0rc2 is next series (4.25.0 upcoming) | 4.24.7: 2026-09-09 | ✅ **Up to date** (latest stable) |
| **OpenLDAP** | 2.6.13 (2026-03-09, per `CHANGES`) | **2.6.15** on the 2.6 LTS line (2026-09-08); new **2.7.x** line now current (2.7: 2026-08-06, 2.7.1: 2026-09-08) | 2.6.14 ≈ Jul 2026; 2.6.15: 2026-09-08 | ⚠️ **2 patch releases behind** on 2.6 (2.6.14, 2.6.15); a new 2.7 series exists |
| **MIT krb5** | 1.22.1 (2025-08-20) | **1.22.2** (`krb5-1.22.2-final` tag) | 2026-01-29 | ⚠️ **1 patch release behind** (1.22.2 = SPNEGO parsing fix) |
| **Cyrus SASL** | 2.1.28 (per `include/sasl.h`) | **2.1.28** (`cyrus-sasl-2.1.28` tag) | — | ✅ **Up to date** (latest release) |

Note: Samba 4.24.x is the current *stable* series (4.24.7 = maintenance head); OpenLDAP 2.7 is now the recommended line but 2.6 remains supported LTS; krb5 1.22.x is the current line.

### 4.3 Tree integrity: local dirs vs. pristine orig tarballs

Each unpacked tree was compared file-list-by-file-list against its local `*.orig.tar.*` (excluding `debian/` and `.pc/`):

| Tree | Tarball files | Dir files | Verdict |
|---|---|---|---|
| `krb5-1.22.1` | 4596 | 4596 (+1: `.gitignore`) | ✅ Identical to tarball; the one extra file is created by Debian patch `0009-Add-.gitignore.patch` |
| `openldap-2.6.13+dfsg` | 1932 | 1931 | ✅ Identical to tarball |
| `cyrus-sasl2-2.1.28+dfsg1` | 408 | 409 (+2) | ✅ Identical + 2 artifacts created by patches (`utils/sasldbconverter2.8`, `Versions`) |
| `samba-4.24.7+dfsg` | 11260 | 11235 (files+symlinks) | ⚠️ **26 files genuinely missing** vs. the local orig tarball — all `ctdb/doc/` (manpage XML sources + example configs). *(Correction: an earlier revision of this index said 46 — 20 of those were symlinks, e.g. `ctdb/include/common/srvid.h` → `../../common/srvid.h` and 18 `selftest/manage-ca` cert links, which `find -type f` skipped but do exist in the tree.)* Extra file `third_party/heimdal/lib/wind/rfc3454.txt-table` is generated by Debian patch `heimdal-rfc3454.txt`. Impact: none for the AD DC (ctdb = clustering component). **Resolved: pristine upstream `samba-4.24.7/` acquired & GPG-verified (§4.6).** |

### 4.4 Debian/Ubuntu delta on top of upstream (already applied in the trees)

All four trees are **unpacked Debian source packages with the quilt patch series already applied** (`.pc/applied-patches` present in each; newest mtimes = when they were unpacked today).

| Tree | Patches applied | Notable content |
|---|---|---|
| Samba | 31 | Standalone talloc/tevent/tdb builds, Heimdal fixes (`heimdal-kdc-fix-memset_s`, `heimdal-errno-include`), path moves (`msg.sock → /run/samba`), `meaningful-error-if-no-samba-ad-provision`, OpenSSL/compat tweaks |
| OpenLDAP | 20 | `64-bit-time-t-compat`, OpenSSL 4 compat (`ITS-10498`), syncrepl modrdn fix (`ITS-10508`), pbkdf2 configurable rounds (`lp2125685`), cross-build fixes |
| krb5 | 19 (`debian-local/0001`–`0008` + `0009`–`0016` + 2 more) | Debian path/multiarch config, **security fixes**: `0013-Fix-two-NegoEx-parsing-vulnerabilities`, `0016-Prevent-read-overrun-in-libkdb_lda(p)`, future-OpenSSL compat, KKDCP cert verification via `X509_check_host` |
| Cyrus SASL | 43 | Large MD5 modernization series (replace custom MD5/RC4 with OpenSSL EVP, OpenSSL 3 legacy provider for digestmd5), **`0034-channel-binding-gssapi-gss-spnego`** (LDAP channel binding — relevant to AD interop!), versioned libsasl2 symbols, soname revert, gcc-15 fix |

DFSG repacks (files removed from pristine upstream, per `debian/copyright` Files-Excluded):
- **Samba**: `third_party/heimdal/lib/wind/rfc*.txt`, `third_party/heimdal/doc/standardisation`, `source4/ldap_server/devdocs`, pre-rendered `docs/manpages/*.?`, `ctdb/doc/*.?{,.html}`
- **OpenLDAP**: `doc/drafts/*`, `doc/rfc/*`, `doc/guide/admin/guide.html`, and schema files (`core`, `cosine`, `inetorgperson`, `collective`, `corba`, `duaconf`, `java`, `namedobject`, `pmi` .schema/.ldif) — these live in `debian/schema/` and are restored by `debian/rules` at build time
- **krb5**: none (plain orig tarball, not a dfsg repack)
- **Cyrus SASL**: `doc/html`, `man`, `dlcompat-20010505`, `mac/`, `common/crypto-compat.*`, `docsrc/exts/themes`, `include/makemd5.c`

### 4.5 Recommendations from the comparison

1. **Samba 4.24.7 & Cyrus SASL 2.1.28 are current** — no action needed.
2. **krb5 1.22.1 → 1.22.2**: cheap, low-risk patch-level upgrade (SPNEGO fix); the Debian patch series carries two security fixes already. Consider pulling `krb5-1.22.2.tar.gz` from https://web.mit.edu/kerberos/dist if rebuilding from pristine upstream.
3. **OpenLDAP 2.6.13 → 2.6.15** (or evaluate 2.7.1): the 2.6.14/2.6.15 releases include syncrepl/ppolicy/lloadd fixes; since Monarchy leans on `ppolicy` and `syncprov`, upgrading to 2.6.15 is advisable. Tags: `OPENLDAP_REL_ENG_2_6_15` at git.openldap.org.
4. **Pristine upstream sources acquired** for Samba (4.24.7), MIT krb5 (1.22.2) and OpenLDAP (2.6.15 + 2.7.1) — see §4.6. The dfsg Samba tree turned out to be missing only 26 `ctdb/doc` files (§4.3), so it remains safe to build from, but prefer the pristine `samba-4.24.7/` tree for new work. Only Cyrus SASL was not re-downloaded (its tree matches its tarball exactly); if a pristine copy is ever wanted: https://github.com/cyrusimap/cyrus-sasl/releases.
5. **Reuse, don't rewrite**: the vendored trees already match upstream closely, so Monarchy work should target patches/additions on top (e.g., the Samba `--with-system-mitkrb5` seam + MIT `kdb_ldap`) rather than maintaining forks.

### 4.6 Acquired sources (downloaded & verified 2026-10-19)

Per the recommendations in §4.5, the following **pristine upstream** sources were acquired into the `ADclone/` research checkout:

| Artifact | Source | Verification | Unpacked to |
|---|---|---|---|
| `samba-4.24.7.tar.gz` (41.4 MB) + `.tar.asc` | https://download.samba.org/pub/samba/stable/ | ✅ **GPG Good signature** "Samba Distribution Verification Key <samba-bugs@samba.org>" (key `81F5E2832BD2545A1897B713AA99442FB680B620`) — note Samba signs the **uncompressed** `.tar`, so verify after `gunzip -c`; `gzip -t` OK; SHA-256 `45b7747a47452eff2b2159a44cc63eb43690d339fd1069088e023a015fed06c7` | `samba-4.24.7/` |
| `krb5-1.22.2.tar.gz` (8.34 MB) | https://web.mit.edu/kerberos/dist/krb5/1.22/krb5-1.22.2.tar.gz | ✅ MD5 `42472b11771d074329e0cc776d2eb5fd` matches published sum; `src/patchlevel.h` = 1.22.2 (20260129, tag `krb5-1.22.2-final`) | `krb5-1.22.2/` |
| `openldap-2.6.15.tgz` (6.22 MB) + `.asc` | mirror: gpl.savoirfairelinux.net (www.openldap.org 404s on files; index at /software/download/) | ✅ **GPG Good signature** "OpenLDAP Project <project@openldap.org>" (key 3CE2…CBCE); `CHANGES` = 2.6.15 (2026/09/08) | `openldap-2.6.15/` |
| `openldap-2.7.1.tgz` (6.20 MB) + `.asc` | same mirror | ✅ GPG Good signature (same key); `CHANGES` = 2.7.1 (2026/09/08) | `openldap-2.7.1/` |

SHA-256 (recorded): `openldap-2.6.15.tgz` = `bc91225dbfc50354033b1303bc91d1a7f6ddd1dc32fac950d79c28fe66d6bca8` · `openldap-2.7.1.tgz` = `253db80f301258ea69cda1184766d57395b836aaabf41157eb0316eb0fac1341`

**Notes on the new trees:**
- The new OpenLDAP trees are **pristine upstream** (not DFSG-stripped): `servers/slapd/schema/core.schema`, `cosine`, `inetorgperson`, etc. are present directly — no `debian/` restoration dance needed. AD `msuser.schema` confirmed present in 2.6.15 (`servers/slapd/schema/msuser.schema`), and 2.7.1 has the key overlays (`ppolicy.c` + `syncprov.c`).
- The new krb5 tree is pristine upstream with no Debian patches (the local 1.22.1 Debian tree carries useful security fixes `0013-NegoEx`, `0016-libkdb_ldap read overrun` — consider forward-porting those two when moving to 1.22.2).
- The pristine Samba tree is **complete**: it contains everything the dfsg tree lacks — the 26 `ctdb/doc` sources plus all symlinked fixtures (`srvid.h`, `run_cluster_tests.sh`, `selftest/manage-ca` certs) — and is authentic per the detached release signature over the decompressed tar.
- **Cyrus SASL 2.1.28 was not re-downloaded** — its Debian tree is already at the latest upstream release and matches its orig tarball exactly (§4.2/§4.3). A pristine copy is one `curl` away: https://github.com/cyrusimap/cyrus-sasl/releases.

**Final source inventory for Monarchy builds:**

| Component | Preferred tree for building | Rationale |
|---|---|---|
| AD DC / LDAP / DRS / DNS | `samba-4.24.7/` (pristine; `+dfsg` tree as fallback) | latest stable, GPG-verified, complete file set |
| slapd (standalone LDAP path) | `openldap-2.6.15/` | current LTS, pristine, GPG-verified |
| KDC (standalone / `kdb_ldap`) | `krb5-1.22.2/` | latest patch release, pristine, checksum-verified |
| SASL (GSSAPI/GS2/NTLM) | `cyrus-sasl2-2.1.28+dfsg1/` | latest release, includes channel-binding patch 0034 |
| 2.7 evaluation | `openldap-2.7.1/` | feature release side-by-side |

### 4.7 Reference & alternative project sources (Part 2.3–2.5) — acquired 2026-10-19

Second acquisition round: all the non-core projects named in Part 2, downloaded into the `ADclone/` research checkout.

| Project | Version | Artifact / source | Verification | Unpacked to |
|---|---|---|---|---|
| Heimdal | 7.8.0 | `heimdal-7.8.0.tar.gz` + `.sig` (GitHub release asset) | ✅ **GPG Good signature** "Heimdal Security <heimdal-security@heimdal.team>" — key `FB925C7AFA000F52B4BBD1ED9A077911BB7DC320` | `heimdal-7.8.0/` |
| FreeIPA | 4.13.4 | `freeipa-4.13.4.tar.gz` (48.8 MB) + `.asc` (Codeberg release — **official**; FreeIPA moved off GitHub/`releases.freeipa.org`) | ✅ **GPG Good signature** "Antonio Torres (Red Hat account) <antorres@redhat.com>" — key `B40A78FBA576C4A3FC7D7BBC359FAF777296F653` (keys.openpgp.org). ⚠️ *Not* the master key (`0E63…8EB963`) documented at freeipa.org whose subkeys are `843F…9706` / `2FCF…DEED`; 4.13.4 was signed by the release manager's personal key (matches the Codeberg release author `antorres`) | `freeipa-4.13.4/` |
| 389-ds | 3.3.1 | `389-ds-base-3.3.1.tar.bz2` (GitHub release asset) | ⚠️ no signature published upstream; SHA-256 recorded | `389-ds-base-3.3.1/` |
| Kanidm | 1.11.2 | tag archive `kanidm-1.11.2.tar.gz` (releases ship binaries only) | ⚠️ unsigned tag archive; SHA-256 recorded | `kanidm-1.11.2/` |
| LLDAP | 0.6.3 | tag archive `lldap-0.6.3.tar.gz` (binaries only) | ⚠️ unsigned; SHA-256 recorded | `lldap-0.6.3/` |
| glauth | 2.5.4 | tag archive `glauth-v2.5.4.tar.gz` (binaries only) | ⚠️ unsigned; SHA-256 recorded | `glauth-GLAuth-v2.5.4/` |
| SSSD | 2.13.1 | `sssd-2.13.1.tar.gz` + `.asc` + `.sha256sum` (GitHub release assets) | ✅ **GPG Good signature** "SSSD Project <sssd-maintainers@lists.fedoraproject.org>" — key `C13CD07FFB2DB1408E457A3CD3D21B2910CF6759`; ✅ published SHA-256 verified | `sssd-2.13.1/` |
| Apache Directory Server | 2.0.0-M11 | `apacheds-parent-2.0.0-M11-source-release.zip` + `.asc` (archive.apache.org) | ✅ **GPG Good signature** "Emmanuel Lecharny (CODE SIGNING KEY) <elecharny@apache.org>" via the official Apache directory `KEYS` file (fingerprint `4D2D B291 6149 BAA9 D0C9 2F37 3147 4E5E 7C6B 7034`) | `apacheds-parent-2.0.0-M11/` |
| OpenRSAT | 0.4.519 | tag archive `OpenRSAT-v0.4.519.tar.gz` (releases ship packaged binaries) | ⚠️ unsigned; SHA-256 recorded | `OpenRSAT-0.4.519/` |

SHA-256 (recorded for every archive):

- `heimdal-7.8.0.tar.gz` = `fd87a207846fa650fd377219adc4b8a8193e55904d8a752c2c3715b4155d8d38`
- `freeipa-4.13.4.tar.gz` = `b2f24d763875a9b5677384f7c6232291c641f5c3c2412614a8b8548b47416023`
- `389-ds-base-3.3.1.tar.bz2` = `0a410a3231683e064e6a8d4f087881994970da36b8a0f3657e576012f53c98c4`
- `kanidm-1.11.2.tar.gz` = `a8ed31203e5f8c036b9cb261c85ddac19291bc6ca16981495495cd9621c56529`
- `lldap-0.6.3.tar.gz` = `2beb7840063bedd67d7afe891428ee7327eca162eee561ce75693af287d7ddf1`
- `glauth-v2.5.4.tar.gz` = `b81717a2628c477ea5a66d1d3573143b02f79e2088ffb05fadb1e20ef38ab3f8`
- `sssd-2.13.1.tar.gz` = `05ea79e89f0be399983925b8874ac196d6dc5fd4416f83609557b9fc8ef798b5`
- `apacheds-parent-2.0.0-M11-source-release.zip` = `44b99d7769684c71452662821c5e32cb4c2554416cf548c42312529ca3fd8894`
- `OpenRSAT-v0.4.519.tar.gz` = `16caa9ca38429c952d14ca06dbc93fcf68cf124c7337371a1eb7259eef030ef2`

**Notes & findings:**
- **FreeIPA moved to Codeberg** — `releases.freeipa.org` no longer resolves and the GitHub repo publishes no releases; the release tarball + signature live at `codeberg.org/freeipa/freeipa/releases`. FreeIPA is an integrated stack (389-ds + MIT krb5 + Dogtag CA + DNS + SSSD), the classic "Linux AD" — but it uses its own schema and is **not AD-protocol compatible** (one-way trust with real AD is its bridge). Distribution is RPM-oriented.
- **389-ds** current official repo is `github.com/389ds/389-ds-base` (Part 2's `DirectoryServer/389-ds` is the older location). This is the LDAP engine FreeIPA bundles — the natural pairing for a `kdb_ldap`-style LDAP-backed KDC.
- **Apache Directory Server** has no final 2.0.0 release; the latest published source is the **2.0.0-M11 milestone** (parent POM version 29). Pure-Java/OSGi LDAP server — most useful as a Java reference implementation of the LDAP pieces, not as the Monarchy engine.
- **Kanidm / LLDAP / glauth / OpenRSAT** publish only prebuilt binaries on their release pages, so GitHub tag source archives were used (unsigned → SHA-256 only). Version evidence in-tree: Kanidm `Cargo.toml` = 1.11.2, glauth `v2/internal/version/const.go` = v2.5.4, OpenRSAT `sources/version.inc` = 0.4.519.
- **Submodule caveat → full recursive clones added.** GitHub tag archives do **not** include git submodules, and three projects need them: **Kanidm** (1: `platform/debian/kanidm_ppa_automation`), **glauth** (4: the `glauth-sqlite` / `-mysql` / `-postgres` / `-pam` DB+PAM plugins — declared with `git@github.com:` SSH URLs, so a `url.insteadOf` rewrite to HTTPS is required to clone them), and **OpenRSAT** (6: mORMot2, metadarkstyle, pltis_utils / -virtualtrees / -uicomponents / -djoin). Complete recursive clones are therefore also present: **`kanidm-1.11.2-git/`, `glauth-GLAuth-v2.5.4-git/`, `OpenRSAT-0.4.519-git/`** — use these for building. OpenRSAT is a **Free Pascal / Lazarus** desktop admin GUI (RSAT alternative); its only missing piece is one *nested* duplicate of mORMot2 referenced by `pltis_djoin` via an internal WAPT URL (`waptgit.ad.tranquil.it`), while the identical code is present at the top-level `submodules/mORMot2`. (Its `.gitmodules` also lists a `pltis_tsmbios` entry that is stale at tag v0.4.519 — no gitlink exists, so nothing to fetch.)
- **Apache DS** modules useful for AD work: it ships `protocol-ldap`, `protocol-kerberos`, `protocol-dns`, `protocol-changepw`, `protocol-dhcp`, `protocol-ntp` plus `server-config`/`service` — a pure-Java counterpart to the C implementation pieces.
- **Heimdal 7.8.0** is the newest tagged release of the KDC that Samba embeds; compare against Samba's `third_party/heimdal/` snapshot when working on the KDC integration seam.
- Repo-name corrections vs. Part 2: use **`codeberg.org/freeipa/freeipa`** and **`github.com/389ds/389-ds-base`**.

**Complete local source inventory (13 project trees):**

| Project | Local tree | Role |
|---|---|---|
| Samba | `samba-4.24.7/` (+ `samba-4.24.7+dfsg/`) | AD DC — the only complete AD implementation |
| OpenLDAP | `openldap-2.6.15/`, `openldap-2.7.1/` | slapd LDAP server |
| MIT krb5 | `krb5-1.22.2/` | KDC + `kdb_ldap` |
| Cyrus SASL | `cyrus-sasl2-2.1.28+dfsg1/` | SASL (GSSAPI/GS2/NTLM) |
| Heimdal | `heimdal-7.8.0/` | KDC alternative (Samba's embedded default) |
| FreeIPA | `freeipa-4.13.4/` | integrated Linux IAM stack |
| 389-ds | `389-ds-base-3.3.1/` | LDAP engine under FreeIPA |
| SSSD | `sssd-2.13.1/` | client-side integration |
| Kanidm | `kanidm-1.11.2/`, **`kanidm-1.11.2-git/`** (with submodule) | modern Rust IDM |
| LLDAP | `lldap-0.6.3/` | minimal LDAP auth provider |
| glauth | `glauth-GLAuth-v2.5.4/`, **`glauth-GLAuth-v2.5.4-git/`** (with 4 plugin submodules) | lightweight Go LDAP |
| Apache DS | `apacheds-parent-2.0.0-M11/` | Java LDAP reference |
| OpenRSAT | `OpenRSAT-0.4.519/`, **`OpenRSAT-0.4.519-git/`** (with 6 submodules) | AD administration GUI (Free Pascal/Lazarus) |

---

## Part 5 — Specification-to-code correlation & modularization blueprint

The analysis of *which code from which project best meets each AD specification*, and how to modularize those components, is in the companion document:

➡️ **[`AD-IMPLEMENTATION-BLUEPRINT.md`](AD-IMPLEMENTATION-BLUEPRINT.md)**

It contains:

- **Part A** — spec-by-spec analysis of all 13 trees (MS-DTYP, MS-ADSC/ADA, MS-ADTS, MS-DRSR, MS-KILE, MS-PAC, MS-SFU, MS-NLMP, MS-SPNG, PKINIT, MS-RPCE, MS-SAMR, MS-LSAD/LSAT, MS-NRPC, MS-DSSP, MS-GPOL/GPSI, MS-FRS1/2, MS-SMB2, MS-W32T, AD-integrated DNS, MS-ADOD/DOCO, admin tooling) with concrete verified file paths.
- **Part B** — the **correlational index** (spec → primary code → secondary → verdict → Monarchy module), a per-project reuse heat map, and a "who wins each spec" summary.
- **Part C** — the **modularization blueprint**: design principles, a component catalogue, frozen interfaces (`DirectoryProvider`, `KdbBackend`, `PacProvider`, `AuthMechanism`, `GpoProvider`), an ASCII dependency graph, three build strategies (Samba-re-cut / MIT-KDC-split / permissive-reassembly) with a recommendation, a process topology, a phased roadmap, and a gap backlog.

**Headline conclusions:** Samba is the only tree implementing the AD protocols, so Monarchy is a *restructure of Samba's protocol engine* into modules with stable interfaces — the other 12 projects supply (1) a swappable KDC core (MIT krb5 via `--with-system-mitkrb5`), (2) the best GPO **client** (SSSD `ad_gpo*`), (3) SASL/channel binding (Cyrus), (4) reference LDAP engines, and (5) the GUI (OpenRSAT). The highest-value, lowest-risk fix is enabling **DRSR XPRESS compression** by reusing Samba's existing `lib/compression/lzxpress*.c` (currently `#if 0`-disabled at `source4/dsdb/repl/drepl_service.c:122`).

---

## Part 6 — 1:1 functional equivalence with MS AD

The gap register, closure strategy and conformance-verification plan for achieving **1:1 functionality with Microsoft AD** (as opposed to "interoperates with AD") is in:

➡️ **[`AD-1TO1-CONFORMANCE.md`](AD-1TO1-CONFORMANCE.md)**

That document scores the gaps against the **newest** Windows Server (2025) — the hardest target. If your target is the **classic AD (Windows Server 2000/2003/2008 R2)** rather than modern Windows, read this first:

➡️ **[`AD-FUNCTIONAL-LEVELS-PRIMER.md`](AD-FUNCTIONAL-LEVELS-PRIMER.md)** — plain-language explanation of functional levels (the successor to Windows 2000's mixed/native mode), what each level added and where Samba stands, a **re-scored** gap list for a 2000/2003/2008 R2 target (most gaps vanish), and the recommendation to target **Windows Server 2008 R2 level** (Samba's default, a superset of the classic AD).

It contains:

- **§0–1** — what "1:1" must mean (four levels L1–L4; recommend **L3 behavioural equivalence** for a defined scope) and a scope decision matrix (AD DS mandatory; ADWS required for Windows tooling parity; AD LDS/CS/FS/RMS optional).
- **§2** — the baseline: a large list of AD-DS capabilities Samba **already** provides (XPRESS excepted), with verified evidence.
- **§3** — the **gap register (G1–G39)**: 39 measured gaps with severity, evidence path, closure route and effort.
- **§4** — closure/sourcing rules (reuse → upstream → write-new → externalise → declare deviations).
- **§5** — **conformance verification** grounded in **Microsoft's own protocol test suites** (`microsoft/WindowsProtocolTestSuites`: `ADFamily` = ADTS/DRSR/LSAD/LSAT/NRPC/SAMR/ADSC/ADA1-3/ADLS/APDS/FRS2; `Kerberos` = KILE/PAC/KKDCP; `MS-XCA` = Xpress), plus a differential test lab with a real Windows DC.
- **§6–8** — a tiered roadmap, cost/risk/licensing, and the six decisions needed before work starts. **§7.1** establishes (with citations) that every classic-AD feature is implementable: the standards spine is royalty-free (Open Specification Promise), Microsoft's proprietary AD protocols are RAND + irrevocably non-asserted for open-source development and non-commercial distribution, and the 2000/2003-era patents are expired — so the only real constraints are **trademark naming** and **commercial distribution of a closed build**.

**Licensing & patent citations:** ➡️ **[`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md)** — verified index of Microsoft's IPR instruments (OSP, Community Promise, Interoperability Principles, OSS patent pledge, Patent & Program Map), the OSP-covered vs. Tier-2 protocol lists with URLs, the per-feature 2000/2003 map, precedent (PFIF, EU Decision 2007/53/EC), interoperability case law and patent-term rules. Underpins §7.1 of the conformance doc.

**Largest gaps:** FL 2016 claims/Dynamic Access Control (upstream-declared incomplete), FL 2025, FRS2/DFSR, ADWS (TCP 9389 — needed by the PowerShell AD module), RODC completeness, DNSSEC, MS-KKDCP, MS-W32T. **Cheapest wins:** DRSR XPRESS (reuse in-tree `lib/compression/`), MS-KKDCP, MS-W32T.

**Defensive brief (just in case):** ➡️ **[`AD-LEGAL-BRIEF-JIC.md`](AD-LEGAL-BRIEF-JIC.md)** — a litigation-ready defensive brief (motion-to-dismiss/summary-judgment posture) covering copyright/patent/trademark/trade dress/EULA/fair use, the "look and feel" analysis, DJ/standing, and the Eighth/Ninth Circuit forum analysis. Built from the citation index; for attorney review, not a filed pleading.

---

## Part 7 — Microsoft AD management console reference-URL index

An index of **URLs** (nothing downloaded) to reference images of the Microsoft AD management console family — ADUC, ADAC, Sites and Services, Domains and Trusts, Schema, ADSI Edit, LDP, GPMC, DNS Manager, AD CS, AD FS, Server Manager and more:

➡️ **[`AD-CONSOLE-IMAGE-INDEX.md`](AD-CONSOLE-IMAGE-INDEX.md)** · machine-readable index [`reference/IMAGE-URL-INDEX.tsv`](reference/IMAGE-URL-INDEX.tsv) (**1,971 rows**: `group · repo · path · url`)

- **§2** — the complete console catalogue (16 consoles) with launch commands (`dsa.msc`, `dsac.exe`, `domain.msc`, `dssite.msc`, `schmmgmt.msc`, `gpmc.msc`, `dnsmgmt.msc`, `adsiedit.msc`, `ldp.exe`, …) and where each console's images are indexed.
- **§3** — index by area, with counts and grep recipes.
- **§4** — the classic consoles whose images Microsoft withdrew (**Windows 2000/2003-era** ADUC, Sites and Services, Domains and Trusts, Schema, DNS Manager): article URLs plus **Wayback CDX** recipes to recover the historical screenshots.
- **§5–6** — community sources and a dialog-by-dialog capture checklist for a Windows/RSAT host.

