# Monarchy — 1:1 Functional Equivalence with Microsoft Active Directory
## Gap register, closure strategy, and conformance-verification plan

**Companion to** [`AD-RESEARCH-INDEX.md`](AD-RESEARCH-INDEX.md) (specs, projects, acquired sources) and [`AD-IMPLEMENTATION-BLUEPRINT.md`](AD-IMPLEMENTATION-BLUEPRINT.md) (spec→code correlation + modularization).

**Date:** 2026-10-19 · **Method:** read-only source audit of `samba-4.24.7/` (the only AD implementation in the 13 local trees) against Microsoft's published behaviour, plus verification of Microsoft's own conformance test suites. Every claim below is tied to a verified path or an explicit upstream statement.

---

## 0. The requirement and its consequences

> "We want 1:1 functionality with MS AD."

**Consequence 1 — it forces a GPL Samba foundation.** The blueprint's Option C (permissive reassembly from Heimdal+OpenLDAP+Cyrus) *cannot* reach 1:1, because no permissive implementation of DRSR/SAMR/NRPC/LSAD/ADTS exists. 1:1 ⇒ **fork/restructure Samba (GPL-3.0)** and close its gaps. Options A and B from the blueprint remain valid; Option C is off the table.

**Consequence 2 — "1:1" must be operationalised, or it is unmeasurable.** Four levels of equivalence exist:

| Level | Meaning | Verifiable by |
|---|---|---|
| **L1 — Wire interop** | A Windows DC/client can join, authenticate, replicate and be managed against Monarchy. | Samba `selftest` + a live Windows DC |
| **L2 — Feature parity** | Every AD DS feature and management operation exists. | Feature checklist vs Windows |
| **L3 — Behavioural equivalence** | Same observable results *and* same errors/edge cases for every documented operation. | Microsoft Windows Protocol Test Suites + differential testing |
| **L4 — Bug-for-bug identity** | Undocumented quirks reproduced exactly. | Long-running differential fuzzing |

**Recommendation: target L3 for a defined scope, with L4 as an asymptotic goal.** L1/L2 alone are not "1:1"; L4 is not a finish line you cross, it is a permanent programme.

---

## 1. Scope decision matrix (must be fixed before work starts)

| Surface | Included? | Why |
|---|---|---|
| **AD DS** (forest/domain/DC roles, schema, replication, Kerberos, LDAP, RPC admin, trusts, GPO storage, AD-integrated DNS, SYSVOL) | **Yes — mandatory** | This is "Active Directory" |
| **AD LDS** (ADAM) — standalone LDAP | Decide | Separate product; shares schema but not DRSR/SAMR |
| **AD CS** (Certificate Services) | Decide | Separate role; Samba uses an external CA today |
| **AD FS** (federation) | Decide | Separate role; no local implementation |
| **AD RMS** (rights management) | Decide | Separate role; no local implementation |
| **ADWS** (AD Web Services, TCP 9389) | **Probably yes** | Required by the Windows **PowerShell `ActiveDirectory` module** and several RSAT tools — without it, "1:1 management" fails |
| **RSAT / MMC tools** (ADUC, ADAC, GPMC, DNS Manager, Sites & Services) | Decide | Either support ADWS, or accept non-Windows tooling. **A 1:1 MMC look is achievable and legally clean** — reimplement the console host + snap-ins (`ad-mmc`/`ad-snapins`; blueprint §A.23) and author your own artwork ([`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md) §13; [`AD-CONSOLE-IMAGE-INDEX.md`](AD-CONSOLE-IMAGE-INDEX.md) §0) |
| **Client integration** (join, nss/pam, GPO CSE) | **Yes** | Windows clients must work, and Linux member hosts need parity (SSSD/winbind — already present) |

Everything below is scoped to **AD DS at L3**, with ADWS flagged as a hard dependency for tooling parity.

### 1.5 Which Windows version is the yardstick? (read this first)

The gap register in §3 is scored against the **newest** Windows Server (2025), i.e. the *hardest* possible target. **That may not be your target.** If you are replicating the classic AD you know from **Windows Server 2000/2003**, most of the register does not apply to you at all — those features (claims, Dynamic Access Control, FL 2016/2025, LAPS, dMSA) were introduced *after* Windows Server 2008 R2 and never existed in your deployment.

See **[`AD-FUNCTIONAL-LEVELS-PRIMER.md`](AD-FUNCTIONAL-LEVELS-PRIMER.md)** for:

- a plain-language explanation of functional levels (and how they descend from Windows 2000's mixed/native mode);
- a timeline of what each level added, and where Samba stands;
- a **re-scored** gap list showing that for a Windows 2000/2003/2008 R2 target, only a handful of gaps remain relevant;
- why **Windows Server 2008 R2 level is the recommended target** (Samba's default, a superset of the AD you know).

**In short:** with a 2000/2003-era target, Monarchy is already close to 1:1, and the top priority is **G8 (XPRESS)**, with **G9 (FRS/DFS-R SYSVOL)** mattering only if you mix Samba and Windows DCs in one domain.

---

## 2. Baseline — what Samba 4.24.7 already provides (verified)

This is **not** a greenfield project. The following are already 1:1-capable today:

| Capability | Evidence |
|---|---|
| DRSR replication with Windows DCs | `source4/rpc_server/drsuapi/{getncchanges,dcesrv_drsuapi,updaterefs,writespn}.c`; `source4/dsdb/repl/` |
| AD LDAP surface (dirsync, show-deleted, DN forms, ranged, paged, sort/VLV, notifications, rootDSE) | `source4/ldap_server/`, `source4/libcli/ldap/ldap_controls.c`, `source4/dsdb/samdb/ldb_modules/` |
| Full AD schema to **v1903** | `source4/setup/ad-schema/*.ldf` (`AD_DS_Attributes_Windows_Server_v1903.ldf` et al.) |
| KCC/site topology | `source4/dsdb/kcc/` + `samba_kcc` |
| SAMR / LSAD / LSAT / NRPC / DSSP / backupkey / winreg / srvsvc | `source4/rpc_server/{samr,lsa,netlogon,backupkey,winreg,srvsvc}/` |
| Kerberos **FAST/armoring** | `source4/kdc/db-glue.c` (`ENC_FAST_SUPPORTED`), `third_party/heimdal/kdc/default_config.c` |
| **AES-SHA2 (RFC 8009)** enctypes | `third_party/heimdal/lib/krb5/crypto-aes-sha2.c` (`aes128-cts-hmac-sha256-128`, `aes256-cts-hmac-sha384-192`) |
| PAC build/validate | `source4/kdc/pac-glue.c`, `pac-blobs.c` |
| S4U2Self/Proxy, PKINIT | `source4/kdc/`, `third_party/heimdal/kdc/pkinit.c` |
| **Protected Users** semantics | `source4/dsdb/common/util.c` (`dsdb_is_protected_user`), `source4/kdc/db-glue.c` |
| **gMSA** (Group Managed Service Accounts) + KDS | `source4/dsdb/gmsa/{gkdi.c,util.c}` |
| **Fine-grained password policies (PSO)** | `python/samba/netcmd/pso.py`, `python/samba/netcmd/domain/passwordsettings.py`, `source4/dsdb/samdb/ldb_modules/password_hash.c` |
| **AD Recycle Bin** (optional feature) | `source4/dsdb/samdb/ldb_modules/rootdse.c` (`rootdse_enable_recycle_bin`), `show_deleted.c` |
| Trusts: UPLEVEL / DOWNLEVEL / **MIT** / **DCE** | `source4/rpc_server/netlogon/dcerpc_netlogon.c` (`LSA_TRUST_TYPE_*`) |
| LDAP signing + channel binding | `source4/ldap_server/ldap_bind.c`, `ldap_server.c` |
| AD-integrated DNS + DNSP RPC + scavenging | `source4/dns_server/`, `source4/rpc_server/dnsserver/`, `source4/dsdb/dns/` |
| MS-SNTP (signed NTP) | `source4/ntp_signd/` |
| FSMO, LVR, tombstones, GC | `source4/dsdb/repl/drepl_fsmo.c`, `source4/dsdb/samdb/ldb_modules/repl_meta_data.c`, `source4/dsdb/repl/drepl_out_helpers.c` |
| Large regression suite (deviation catalogue) | `python/samba/tests/{krb5,ldap,samba_tool,gpo}/`, `selftest/knownfail.d/*` |

**So the task is not "build AD" — it is "close Samba's AD-DS deltas".**

---

## 3. Gap register (the core artefact)

Severity: 🔴 blocks L3 · 🟠 notable · 🟡 edge/accepted-deviation candidate.
Closure route: `REUSE-LOCAL` (code already exists in-tree/in-another-local-tree) · `UPSTREAM` (Samba work) · `WRITE-NEW` · `EXTERNAL` (BIND/OpenSSL/Windows) · `ACCEPT` (documented deviation).

### 3.1 Functional levels, schema, directory features

| # | MS AD behaviour | Monarchy / Samba 4.24.7 today | Evidence | Sev | Closure | Effort |
|---|---|---|---|---|---|---|
| G1 | **Forest/domain FL up to 2025**, schema version 91 | Defaults to `2008_R2`; can claim 2012/2012_R2/2016; **no 2025 FL** | `docs-xml/smbdotconf/protocol/addcfunctionallevel.xml`; `source4/dsdb/common/util.c:4187`; LDFs end at v1903 | 🔴 | UPSTREAM | Large |
| G2 | FL 2016 claims + **Dynamic Access Control** fully functional | Explicitly **"incomplete in Samba 4.19"** per upstream docs; claims admin exists (`samba-tool domain claim`) but engine partial | `addcfunctionallevel.xml` warning; `python/samba/netcmd/domain/claim*` | 🔴 | UPSTREAM | Large |
| G3 | Schema adprep parity beyond v1903 | No later schema revisions | `source4/setup/ad-schema/` (max v1903) | 🟠 | UPSTREAM/EXTERNAL | Medium |
| G4 | **dMSA** (delegated Managed Service Account) | **Absent** — only appears in Windows adprep documentation | `source4/setup/adprep/WindowsServerDocs/Schema-Updates.md` (docs only) | 🟠 | PORT (KDS `gkdi.c` already exists) | Medium |
| G5 | **Windows LAPS** schema + behaviour | Schema attributes present in the v1903 LDFs; DC-side behaviour minimal | `AD_DS_Attributes_Windows_Server_v1903.ldf` | 🟡 | PORT/EXTERNAL | Small–Medium |
| G6 | `msDS-KeyCredentialLink` (Windows Hello/FIDO) | Partially recognised | `source4/dsdb/samdb/ldb_modules/acl.c`, `source4/auth/sam.c` | 🟡 | UPSTREAM | Medium |
| G7 | Central Access Policies / resource properties engine | Schema present; engine partial (ties to G2) | v1903/2012R2/2016 LDFs | 🟠 | UPSTREAM | Medium |

### 3.2 Replication

| # | MS AD behaviour | Monarchy / Samba 4.24.7 today | Evidence | Sev | Closure | Effort |
|---|---|---|---|---|---|---|
| G8 | DRSR supports **XPRESS** compression | **Disabled**: `#if 0 /* we don't support XPRESS compression yet */`; MSZIP only | `source4/dsdb/repl/drepl_service.c:122` | 🔴 | **REUSE-LOCAL** — `lib/compression/lzxpress{,_huffman}.c` | **Small — highest ROI** |
| G9 | **DFSR/FRS2** SYSVOL replication | **Absent**; SYSVOL replicated via DRS instead | no frs/dfsr implementation in-tree | 🔴 | WRITE-NEW (or `ACCEPT` a documented deviation) | Large |
| G10 | **RODC** full semantics (password replication policy, credential caching, RODC filtered attribute set, RODC KDC) | Partial: helper + KCC awareness + refuses FL update on RODC | `source4/dsdb/common/rodc_helper.c`, `kcc_service.c` | 🟠 | UPSTREAM | Medium–Large |
| G11 | DRS schema/GC/reference replication edge cases | Largely present | `source4/dsdb/repl/drepl_partitions.c`, `drepl_replica.c` | 🟡 | differential test | Small |
| G12 | Tombstone lifetime / garbage collection parity | Present | `source4/dsdb/kcc/garbage_collect_tombstones.c` | 🟡 | verify | Small |

### 3.3 Kerberos / KDC

| # | MS AD behaviour | Monarchy / Samba 4.24.7 today | Evidence | Sev | Closure | Effort |
|---|---|---|---|---|---|---|
| G13 | **MS-KKDCP** — Kerberos over HTTPS (`/KdcProxy`) | **Absent** (the `kdc-proxy.c` file is a *DC forwarding list*, not KKDCP) | `source4/kdc/kdc-proxy.c` (unrelated) | 🟠 | WRITE-NEW (small; spec + MS test suite exist) | Small–Medium |
| G14 | FL 2012 Kerberos claims / compound identity | Partial (`ad_claims.c` present; end-to-end incomplete per G2) | `source4/kdc/ad_claims.c`, `libcli/security/claims-conversions.c` | 🔴 | UPSTREAM | Medium–Large |
| G15 | Authentication policies & silos | Partial | `source4/kdc/authn_policy_util.c` | 🟠 | UPSTREAM | Medium |
| G16 | Smartcard/PKINIT parity (incl. smartcard-only accounts, freshness) | Functional; parity unverified | `third_party/heimdal/kdc/pkinit.c`, `source4/kdc/tests` | 🟠 | differential/UPSTREAM | Medium |
| G17 | MIT-KDC path parity | **Experimental**; known failures enumerated upstream | `source4/kdc/mit-kdb/`, `selftest/knownfail_mit_kdc.d/*` | 🟠 | UPSTREAM | Medium–Large |

### 3.4 LDAP

| # | MS AD behaviour | Monarchy / Samba 4.24.7 today | Evidence | Sev | Closure | Effort |
|---|---|---|---|---|---|---|
| G18 | LDAP **policy enforcement parity** (signing requirements, channel-binding policy, MaxPageSize/MaxQueryDuration limits, dsHeuristics) | Signing + CBT present; *policy administration* parity unverified | `source4/ldap_server/ldap_bind.c` | 🟠 | UPSTREAM + tests | Medium |
| G19 | Loosely-consistent AD control revisions (newer SD flags, extended DN variants) | Most present; revisions need per-version check | `source4/libcli/ldap/ldap_controls.c` | 🟡 | differential | Small |
| G20 | Global Catalog semantics | Present | `source4/dsdb/samdb/ldb_modules/` (partial-attribute-set) | 🟡 | verify | Small |

### 3.5 RPC, DC administration, tooling

| # | MS AD behaviour | Monarchy / Samba 4.24.7 today | Evidence | Sev | Closure | Effort |
|---|---|---|---|---|---|---|
| G21 | **ADWS** (AD Web Services; TCP 9389, SOAP/NTLM/Kerberos) | **Absent** | no match anywhere in-tree | 🔴 (for tooling parity) | WRITE-NEW | Large |
| G22 | **MS-W32T** RPC (Windows Time service interface) | **Absent**; MS-SNTP exists | `source4/ntp_signd/`; `librpc/idl/w32time.idl` (IDL only) | 🟠 | WRITE-NEW (small) | Small |
| G23 | SAMR/LSAD/LSAT/NRPC/DSSP edge-case parity | Broadly present | `source4/rpc_server/{samr,lsa,netlogon}/` | 🟠 | differential (ADFamily suite) | Medium |
| G24 | Newer SAMR information classes / LSAD trust info | Partial | `source4/rpc_server/samr/` | 🟡 | UPSTREAM | Small–Medium |
| G25 | `dcdiag`/`ntdsutil`-class diagnostics | Partial (`samba-tool dbcheck`, `drs showrepl`) | `python/samba/netcmd/{dbcheck.py,drs.py}` | 🟡 | build tooling | Medium |

### 3.6 Policy, SYSVOL, SMB, DNS, time, trusts, optional roles

| # | MS AD behaviour | Monarchy / Samba 4.24.7 today | Evidence | Sev | Closure | Effort |
|---|---|---|---|---|---|---|
| G26 | GPO server storage/SOM/gPLink/versioning | Present | `libgpo/`, dsdb hooks | 🟡 | verify (PSO/GPO interop tests) | Small |
| G27 | GPO **client** CSE completeness (Linux members) | SSSD partial (not a DC concern) | `sssd-2.13.1/src/providers/ad/ad_gpo*.c` | 🟡 | ADAPT SSSD | Medium |
| G28 | DFS referral parity for SYSVOL | Partial | `dfs_server/dfs_server_ad.c`, `source3/rpc_server/dfs/srv_dfs_nt.c` | 🟡 | differential | Medium |
| G29 | **SMB Direct / RDMA** (MS-SMBD) | **Absent** | no `rdma`/`smbdirect` in `source3/smbd/` | 🟡 | `ACCEPT` unless required | Large (if required) |
| G30 | SMB 3.1.1 + encryption | Present | `source3/smbd/`, `libcli/smb/` | 🟡 | verify | Small |
| G31 | **DNSSEC** in AD-integrated DNS | **Absent in internal DNS** (explicit comment) | `source4/dns_server/dnsserver_common.c:1543` ("we don't support DNSSEC") | 🟠 | UPSTREAM or `EXTERNAL` (BIND DLZ) | Medium |
| G32 | DNS aging/scavenging behaviour | Present (recent bug fixes) | `WHATSNEW.txt` (BUG 16223) | 🟡 | verify | Small |
| G33 | Time hierarchy / PDC emulator alignment | Partial | `source4/ntp_signd/` | 🟡 | UPSTREAM | Small |
| G34 | Shortcut trusts; **PAM/bastion** trust; selective authentication; SID filtering; forest trust edge cases | Partial (base trust types present) | `dcerpc_netlogon.c` (`LSA_TRUST_TYPE_*`), `dsdb_trust_*` | 🟠 | UPSTREAM | Medium–Large |
| G35 | **AD LDS** | Absent | — | scope | WRITE-NEW / EXTERNAL | Large |
| G36 | **AD CS** (enterprise PKI, autoenrollment, NDES, OCSP) | Absent (Samba can use an external CA) | — | scope | WRITE-NEW / EXTERNAL | Very large |
| G37 | **AD FS** | Absent | — | scope | WRITE-NEW | Very large |
| G38 | **AD RMS** | Absent | — | scope | WRITE-NEW | Very large |
| G39 | WMI/WBEM-based management surfaces | Absent | — | 🟡 | `ACCEPT`/EXTERNAL | Large |

### 3.7 Gap summary

- **Cheap, high-impact:** **G8 XPRESS** (reuse `lib/compression/`), **G13 MS-KKDCP**, **G22 MS-W32T** — all small, all with an authoritative MS spec.
- **Structural, must-do for L3:** **G2/G14 FL 2016 claims+DAC**, **G21 ADWS**, **G9 DFSR**, **G1 FL 2025**.
- **Fixable-but-involved:** **G10 RODC**, **G16/G15 PKINIT + silos**, **G31 DNSSEC**, **G34 trust edge cases**.
- **Scope decisions, not engineering tasks:** G35–G38 (AD LDS/CS/FS/RMS).

---

## 4. How each gap gets closed (sourcing rules)

1. **Reuse before writing.**
   - G8 XPRESS → `samba-4.24.7/lib/compression/lzxpress.c` + `lzxpress_huffman.c`; validate against **MS-XCA** (Microsoft publishes both the spec `[MS-XCA]` and a test app).
   - G4 dMSA → extend the existing KDS code (`source4/dsdb/gmsa/gkdi.c`).
   - G27 GPO client → adopt SSSD's `ad_gpo*` as the `ad-gpo-client` module (blueprint C.2).
2. **Port upstream rather than diverge.** For G1/G2/G14/G10/G34, the maintainable route is **upstream Samba contributions**, not a private fork. A long-lived fork of FL-2016 claims/DAC is a permanent merge tax; upstreaming is cheaper over a multi-year horizon.
3. **Write new only where nothing exists** (G21 ADWS, G9 DFSR/FRS2, G13 MS-KKDCP, G22 MS-W32T). For these, the MS specification + the official test suite define "done".
4. **Externalise what should never have been in a DC** (G31 DNSSEC via BIND DLZ; G36 AD CS via an external CA such as step-ca/Dogtag/OpenSSL; G37/G38 out of scope unless explicitly required).
5. **Declare accepted deviations explicitly** (candidate: G29 SMB Direct/RDMA, G39 WMI) — documented in a `DEVIATIONS.md` with rationale, so "1:1" has a precise, auditable meaning rather than a vague claim.

---

## 5. Conformance verification — how "1:1" is proven

### 5.1 Microsoft's own protocol test suites (authoritative)

`microsoft/WindowsProtocolTestSuites` (568★, actively updated; verified live 2026-10-19) ships **exactly the suites needed**:

| Suite | Specs covered |
|---|---|
| `TestSuites/ADFamily` | **MS-ADTS, MS-DRSR, MS-LSAD, MS-LSAT, MS-NRPC, MS-SAMR, MS-ADSC, MS-ADA1/2/3, MS-ADLS, MS-APDS, MS-FRS2** |
| `TestSuites/Kerberos` | **MS-KILE, MS-PAC, MS-KKDCP** |
| `TestSuites/MS-XCA` | Xpress Compression Algorithm (validates G8) |
| `TestSuites/MS-SMBD` | SMB Direct (G29) |
| `TestSuites/{MS-ADOD,MS-AZOD}` | AD protocol overview / Azure AD overview |

These are the primary acceptance tests: **a gap is closed when the relevant Microsoft suite passes against Monarchy.**

### 5.2 Differential test lab

```
        ┌──────────────┐        same forest, bidirectional DRS        ┌──────────────────┐
        │  Windows DC   │◄────────── replication ─────────────────────►│  Monarchy (Samba)  │
        │ 2016/2019/    │                                              │  DC              │
        │ 2022/2025     │◄──── Kerberos / LDAP / NRPC / SAMR ─────────►│                  │
        └──────┬───────┘                                              └────────┬─────────┘
               │ Windows RSAT: dcdiag, repadmin /showrepl, adtest,           │ samba-tool
               │ ldp.exe, dsacls, setspn, GPMC, DNS Manager, PowerShell       │ selftest + knownfail
               ▼                                                              ▼
        ┌───────────────────────── differential assertions ──────────────────────────┐
        │ same LDAP results · same Kerberos tickets · same RPC replies · same errors │
        └────────────────────────────────────────────────────────────────────────────┘
```

- **Bidirectional DRS with a real Windows DC per supported FL** is the single most valuable test (it exercises G8, G10, G11, G12, schema, GC).
- **Windows tooling as the oracle**: `dcdiag`, `repadmin`, `adtest`, `ldp.exe`, `dsacls`, `setspn`, GPMC, DNS Manager, and the **PowerShell `ActiveDirectory` module** (which requires **ADWS — G21**).
- **Linux-side parity**: SSSD/winbind join + GPO application.

### 5.3 Continuous regression gate

- Run **Samba's own `selftest`** as the fast gate; treat `selftest/knownfail.d/*` and `selftest/knownfail_mit_kdc.d/*` as the **live deviation register** — each entry is a known L3 gap; driving these files to empty *is* the L3 objective.
- Add the Microsoft WPT suites to CI (nightly against a Windows VM).
- Publish a **conformance scorecard**: per-spec pass counts + open deviation list, per release.

---

## 6. Roadmap to 1:1

| Tier | Target | Gaps closed | Effort |
|---|---|---|---|
| **0 — quick wins** | Weeks | **G8** XPRESS (MS-XCA green), **G13** MS-KKDCP, **G22** MS-W32T | Small |
| **A — L3 core** | Months | **G2/G14** FL 2016 claims + DAC (+ G7), **G18** LDAP policy parity, **G23** SAMR/LSAD/NRPC edge cases via ADFamily, **G10** RODC completion, **G20/G11/G12** verification, **G31** DNSSEC decision | Medium–Large |
| **B — full AD DS** | Quarters | **G21** ADWS, **G9** DFSR/FRS2, **G1** FL 2025 (schema 91 + features), **G4** dMSA, **G5** LAPS, **G15/G16** silos + PKINIT parity, **G34** trust edge cases, **G6** KeyCredentialLink | Large |
| **C — asymptotic** | Ongoing | L4 bug-for-bug via differential fuzzing; schema/feature tracking each Windows release; optional roles (G35–G38) if scoped in | Continuous |

**Critical path:** G8 → G2/G14 → G21/G9/G1. XPRESS and FL-2016 completeness unblock the ADFamily suite; ADWS + DFSR + FL 2025 are what stand between "excellent interop" and "1:1".

---

## 7. Cost, risk, licensing

### 7.1 Licensing & patents — what's encumbered, what isn't

**Can every Windows 2000/2003 AD feature be implemented without licensing problems?** Yes. No feature is legally off
the table. "Licensing" here is four distinct questions; only two are real constraints, and neither blocks a feature.

| Question | Status |
|---|---|
| **Copyright** — copying Microsoft's code | Non-issue: Monarchy never has Microsoft source, and reimplementing *behaviour* from published specs is permitted (see `[GO]`/`[SAS]` in the citation index). Keep clean-room discipline. |
| **Microsoft patents** | The substantive question — resolved by the three tiers below. |
| **Trademarks** | **Real constraint.** Cannot use "Active Directory", "Windows", "Microsoft", their logos or marks. Blocks *naming/branding only*. |
| **Monarchy's own source licence** | **GPL-3.0**, forced by the Samba foundation (§0). Self-imposed, orthogonal to Microsoft. |

#### The three patent tiers

| Tier | Coverage | Position |
|---|---|---|
| **1 — standards spine** | Kerberos v5 (RFC 1510/1964/4120), PKINIT (RFC 4556), LDAP v3 (RFC 2251/2256), DNS (RFC 1034/1035/2136/2782…), SPNEGO (RFC 4178), SASL (RFC 2222), NetBIOS-over-TCP (RFC 1001/1002), CIFS; plus *Microsoft Kerberos Authentication Group Membership Extensions*, *Microsoft Simple Network Time Protocol Extensions*, *Microsoft Remote X/Open Directory Services Remote Protocol* | **Royalty-free, irrevocable** — the **Open Specification Promise** (`[MS-OSP]`). Covers commercial *and* open source, full *or* partial. |
| **2 — MS-proprietary AD protocols** | MS-ADTS, **MS-DRSR**, **MS-SAMR**, **MS-NRPC**, **MS-LSAD/LSAT**, MS-SFU, MS-KILE/PAC, MS-ADSC/ADA1-3, MS-GPOL/GPOD, MS-FRS1/2, MS-DFSC, MS-DSSP, MS-W32T, MS-NLMP | Published free under the **Interoperability Principles** (`[MS-IPP]`): patents **RAND, low royalty**; **irrevocable no-assert pledge for OSS development + non-commercial distribution** (`[MS-PLEDGE]`); and *Microsoft will not assert patents on a protocol unless listed on the Patent & Program Map* (`[MS-PATMAP]`). |
| **3 — patent term** | 2000-era AD filed ~1996–2000, 2003-era ~2000–2003 | US term = 20 yrs (`[USPTO-TERM]`) ⇒ **expired ~2016–2023**. The classic AD feature set is largely patent-expired in 2026, independent of the pledges. Live claims concentrate in post-2012 features (outside the classic scope). |

#### Per-feature status (2000/2003)

| Classic feature | Spec | Tier |
|---|---|---|
| Kerberos v5, SPNEGO, SASL, GSS-API | RFC 4120/4178/2222/2743 | 1 — free |
| PAC (groups/SIDs) | MS-PAC + OSP group-membership ext. | 1/2 |
| LDAP v3; AD controls/dialects | RFC 4511; MS-ADTS | 1 / 2 |
| Dynamic DNS, SRV, DC locator | RFC 2136 / 2782 | 1 — free |
| W32Time | MS SNTP ext. (OSP) + MS-W32T | 1/2 |
| Multi-master replication, USN, FSMO | MS-DRSR + MS-ADTS | 2 — expired |
| Netlogon secure channel | MS-NRPC | 2 — expired |
| User/group/account mgmt | MS-SAMR | 2 — expired |
| Domain/trust policy, password policy | MS-LSAD / MS-LSAT | 2 — expired |
| Forest trusts (2003) | MS-LSAD + MS-NRPC | 2 — expired |
| S4U2Self/S4U2Proxy (2003) | MS-SFU | 2 — expired |
| Group Policy | MS-GPOL / MS-GPOD | 2 — expired |
| SYSVOL via FRS | MS-FRS1 | 2 — expired |
| Schema | MS-ADSC / MS-ADA1-3 | 2 — expired |
| AD LDS / ADAM (2003) | MS-ADLS + LDAP | 2/1 |
| NTLM fallback | MS-NLMP | 2 — expired |

**Precedent:** Samba has shipped a complete AD DC under GPL for over a decade (AD DC since Samba 4.0, 2012;
protocol docs via PFIF since 2007). It obtained the protocol docs via **PFIF**
(`[PFIF]`, Dec 2007) under a *"(No Patents)"* licence — docs under NDA, implementations publishable under GPL with
**no per-copy royalties and no admission of infringement**. Microsoft has never asserted patents against it. Heimdal,
MIT krb5, FreeIPA and 389-ds are in the same position.

**Verdict.** All classic-AD features are implementable. The only genuine constraints are (a) **naming/branding** and
(b) **commercial distribution of a closed-source build** — outside the `[MS-PLEDGE]` scope, where one relies on
`[MS-PATMAP]` having no listed patent, the RAND licence, or Tier-3 expiry. For an **open-source** Monarchy the pledge
covers the whole set, and the classic-era patents are expired regardless.

➡️ Full source list, quotes and per-protocol URLs: **[`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md)**
(keys `[MS-OSP]`, `[MS-CP]`, `[MS-IPP]`, `[MS-PLEDGE]`, `[MS-PATMAP]`, `[PFIF]`, `[EU]`, `[USPTO-TERM]`, `[MS-TM]`, …).

*Not legal advice; for a commercial release have counsel check the Patent & Program Map against the specs implemented.*

### 7.2 Cost & risk

- **Licensing consequence:** 1:1 ⇒ **GPL-3.0** Monarchy (Samba-derived). The permissive-reassembly option is incompatible with 1:1 (see §0). If a permissive artefact is a requirement, it must be a *subset* product with a documented, reduced conformance target — and then the §7.1 Tier-2 commercial-distribution question becomes live.
- **Maintenance risk:** every gap closed by private fork diverges from Samba; **upstream-first** is the only sustainable strategy for G1/G2/G10/G14/G34.
- **Test-lab risk:** differential conformance requires licensed Windows Server VMs (2016/2019/2022/2025) and their periodic re-provisioning. This is an ongoing operational cost, not a one-off.
- **Definition risk:** without a published `DEVIATIONS.md`, "1:1" will drift into a marketing claim. Fix the scope (§1) and the accepted-deviation list before Tier A.
- **Trademark risk:** reserve a name early — "Active Directory"/"Windows"/"Microsoft" and their marks are off-limits (§7.1).
- **Forum / binding authority:** the operator is in the **Eighth Circuit** (St. Louis). Patent questions bind nationwide via the **Federal Circuit** (location irrelevant); copyright/trade-dress questions follow **Eighth Circuit** law — which requires **secondary meaning** for product-design trade dress, and has **no landmark appellate GUI-copyright ruling** (so §13.3 cases are persuasive only). Per-circuit map: citation index **§14**.

---

## 8. Decisions required before Tier A starts

1. **Role scope** — AD DS only, or AD DS + AD LDS + AD CS + AD FS + AD RMS?
2. **Target functional level** — FL 2016 (achievable in Tier A/B) or FL 2025 (adds a large Tier-B item)?
3. **Tooling scope** — must Windows RSAT/PowerShell manage Monarchy? (If yes, **ADWS is mandatory**, G21.)
4. **Equivalence level** — L3 behavioural equivalence (recommended), or also L4 bug-for-bug?
5. **Licensing** — accept a GPL-3.0 Samba-derived product? (If not, the product must be a permissive *subset* and the §7.1 Tier-2 commercial-distribution question becomes live.)
6. **Test lab** — can Windows Server 2016/2019/2022/2025 test DCs be provisioned for differential conformance?
7. **Product name** — fix a trademark-clean name now ("Active Directory"/"Windows"/"Microsoft" are off-limits; §7.1).

---

## Appendix — how this document relates to the others

| Document | Contents |
|---|---|
| [`AD-RESEARCH-INDEX.md`](AD-RESEARCH-INDEX.md) | Part 1 = MS specs & what AD must contain · Parts 2–4 = projects, local trees, upstream comparison · §4.6–4.7 = acquired sources & verification |
| [`AD-IMPLEMENTATION-BLUEPRINT.md`](AD-IMPLEMENTATION-BLUEPRINT.md) | Part A = spec→code analysis · Part B = correlational index ("who wins each spec") · Part C = modularization (modules, interfaces, build strategies, roadmap) |
| [`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md) | Every licensing/patent/copyright/trademark source behind §7.1: Microsoft's promises (OSP/CP/IPP/OSS pledge/Patent Map), OSP-covered vs. Tier-2 protocol lists with URLs, per-feature map, precedent (PFIF/EU), case law, patent-term rules |
| [`AD-LEGAL-BRIEF-JIC.md`](AD-LEGAL-BRIEF-JIC.md) | Defensive litigation brief (just in case): motion-to-dismiss/summary-judgment posture, caption template, statement of facts, arguments on copyright/patent/trademark/trade dress/EULA/fair use, the "look and feel" analysis, DJ/standing, cross-referenced to the citation index |
| **This document** | What "1:1" means, the measured gap register, closure routes, and how conformance is proven |
