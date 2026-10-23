# Monarchy — Full AD Implementation Plan

**Scope:** Monarchy is not just a client console. It is a complete, 1:1 Active Directory
implementation (DC + admin console) on Linux. The UI (`ui/`) is the administration console;
the backend (`backend/` + a new `engine/`) is the directory service itself.

This plan builds on `AD-IMPLEMENTATION-BLUEPRINT.md` (spec→code) and
`AD-1TO1-CONFORMANCE.md` (gap register) and `AD-UI-WIRING-PLAN.md` (client wiring).

---

## 1. Reality check

> **Note:** Timelines below assume AI-assisted development, which compresses traditional
> human man-hour estimates by an order of magnitude. Phases are measured in days, not months.

A from-scratch, 1:1 AD DS (DRSR, SAMR, LSAD, NRPC, KDC with PAC/S4U/PKINIT, AD-integrated
DNS, SYSVOL/GPO, replication) is a multi-year, multi-person effort. No permissive
implementation exists (per `AD-1TO1-CONFORMANCE.md` §0). The only complete reference is
Samba 4.24.7.

**Strategy: hybrid, phased.** 
- **Phase A (ship something working):** Use Samba as the protocol engine (lib or embedded)
  so Monarchy is a real DC on day one, with our own identity, tooling, and admin console.
- **Phase B (own the stack):** Progressively replace Samba components with Monarchy's own
  implementations, derived from the specs + Samba/OpenLDAP/OpenRSAT as references, starting
  with the highest-value and most self-contained pieces (LDAP frontend, schema, DNS).
- **Phase C (1:1 parity):** Close the conformance gaps (G8 XPRESS, G9 DFS-R, ADWS, etc.).

Monarchy is licensed GPL-3.0-or-later for the whole tree, so fresh code and Samba-derived
code share one licence and no cross-licence boundary is needed.

---

## 2. Component architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Monarchy Admin Console (ui/)  — Qt 6, already complete            │
│  ConsoleView / ResultsModel / PropertySheet / MainWindow         │
└──────────────────────┬──────────────────────────────────────────┘
                       │ backend adapter (backend/)
┌──────────────────────▼──────────────────────────────────────────┐
│  Monarchy Engine (engine/) — the directory service                │
│  ├── LdapFrontend      (LDAPv3 + AD controls, rootDSE, schema) │
│  ├── RpcFrontend       (DCE/RPC: SAMR, LSAD, DRSR, Netlogon,   │
│  │                     DNSP, BackupKey, Winreg, Srvsvc)        │
│  ├── Kdc               (Kerberos: TGT/ST, PAC, S4U, PKINIT,    │
│  │                     FAST, claims) — MIT crypto + AD exts    │
│  ├── DnsServer         (AD-integrated zones, dynamic update,   │
│  │                     scavenging, DNSP RPC)                   │
│  ├── ReplEngine        (DRSR: GetNCChanges, cursors, USN,      │
│  │                     linked values, KCC)                     │
│  ├── SamDb             (LDB-style store: objects, attrs,       │
│  │                     schema, indexes, tombstones, USN)        │
│  ├── GpoEngine         (GPO storage in SYSVOL, gPLink, CSE)    │
│  ├── NtlmAuth          (NTLMSSP server)                        │
│  ├── Spnego            (SPNEGO + channel binding)              │
│  └── Provisioning      (domain/forest/DC promotion, schema load)│
└──────────────────────┬──────────────────────────────────────────┘
                       │ storage
┌──────────────────────▼──────────────────────────────────────────┐
│  Storage: TDB/LDB (or SQLite) + SYSVOL (SMB) + Kerberos keys   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Engine strategy per component

| Component | Phase A (working) | Phase B (own implementation) | Reference |
|---|---|---|---|
| **LDAP frontend** | Samba `ldap_server/` (study) → implement own LDAPv3 parser + AD controls using OpenLDAP lib as base | Fresh LDAP frontend over our store | OpenLDAP, Samba `ldap_server/`, MS-ADTS |
| **Object store (SamDb)** | Adapt Samba LDB (libldb) as storage backend | Fresh store (SQLite or custom) with schema-driven attrs, USN, tombstones | Samba `dsdb/samdb/`, LDB |
| **Schema** | Load Samba's schema LDFs | Same LDFs (they're the MS schema); our own schema engine | Samba `source4/setup/ad-schema/` |
| **SAMR/LSAD/DRSR RPC** | Samba RPC server (reference) → implement NDR clients/servers fresh using MS IDL | Fresh RPC frontend | Samba `rpc_server/`, MS-SAMR/LSAD/DRSR, `librpc/idl/` |
| **KDC** | Heimdal (Samba bundled) | MIT crypto + reimplemented AD extensions (PAC, S4U, PKINIT MS, claims) | Heimdal, MIT krb5, MS-KILE/PAC |
| **DNS** | **Done:** `engine/DnsServer` is authoritative for the domain zone, publishes the DC locator set (RFC 2782 SRV), applies RFC 2136 updates with prerequisite/rcode enforcement, bumps the SOA serial and persists the zone; the provisioner writes the initial zone | Reverse zones, scavenging, DNSP RPC, zone data in `CN=MicrosoftDNS` | Samba `dns_server/`, MS-DNSP, RFC 1035/2136 |
| **Replication (KCC)** | Samba KCC | Fresh KCC (site topology, connection objects) | Samba `dsdb/kcc/`, MS-ADTS |
| **GPO/SYSVOL** | Samba SMB + GPO code | Fresh GPO engine over SMB (libsmb or own) | Samba `gpo.py`, `source4/libcli/smb/` |
| **NTLM** | Samba (reference) or Cyrus | Fresh NTLMSSP server | Samba `libcli/auth/`, Cyrus |
| **SPNEGO** | Samba (reference) | Fresh SPNEGO + channel binding | Samba, MS-SPNG |
| **Provisioning** | **Done:** `engine/Provisioner` (C++, no Samba) creates the domain, configuration and schema NCs, containers, built-in accounts/groups with RIDs, the DC object, SYSVOL directories and the credential file | Extend the same provisioner: forest/child domains, additional DCs, schema LDF import, SYSVOL seed content | AD object model; Samba `python/samba/provision/` for object set and RID conventions |

---

## 4. Phased delivery

**Phase 0 (done):** Admin console UI complete; backend adapter skeleton; plan docs;
native provisioner (`monarchy-provision`) creating a domain from Monarchy's own code.

**Phase 1 — Directory + auth (days, AI-assisted)**
- Provisioning: create domain/forest/first DC from source — **done** (including the two default
  GPOs with their SYSVOL content and `gPLink` wiring); schema LDF import still to come.
- Passwords: `unicodePwd`/`userPassword` writes are policy-checked and stored as per-object
  salted verifiers that never appear in search results — **done**; the AD credential (NTOWFv1)
  is stored too and doubles as the RC4-HMAC Kerberos key, alongside AES-128/256 keys derived
  from the same password — **done**.
- SamDb: object store with attributes, USN, tombstones (use LDB initially).
- LDAP frontend: bind (simple + NTLMv2 + GSSAPI/SPNEGO) — **done**; search, add/modify/delete,
  rootDSE done; paged/VLV and controls still to come.
- KDC: issue TGT/ST, RC4-HMAC and AES, pre-authentication, TGS subkeys, AP-REQ/AP-REP,
  PAC-carrying tickets and GSSAPI sign/seal — **done** (`engine/Kdc.cpp`, `engine/Pac.cpp`,
  `engine/LdapServer.cpp`, `monarchy-kerberos-tests`); S4U/PKINIT still to come.
- Acceptance: `ldapsearch` against Monarchy returns AD-shaped data; Windows client can join.

**Phase 2 — Admin & RPC (days, AI-assisted)**
- NTLMSSP (NTLMv2) over LDAP SASL — **done** (`engine/Ntlm`, `monarchy-ntlm-tests`),
  including MS-NLMP §3.4 message signing and sealing (signed and sealed LDAP
  sessions, key/token bytes checked against impacket's implementation).
- Cross-realm trusts — **done** for a direct trust (`engine/Kdc.cpp` referral
  tickets, `Krb5::findTrustPrincipal`, `Krb5::storeTrustKeys`; proved with MIT
  krb5 walking an ALPHA→BETA trust in `monarchy-kerberos-tests`). Multi-hop
  transitive forests, SID filtering/selective auth and trust-password rotation
  remain.
- SAMR RPC server: **done** for server/domain/user/group handles, enumeration,
  SID↔name, every user information class including the aggregate writes and password
  sets, group creation/deletion/membership and the group information classes.
  LSAD is still to come.
- Admin console wired to live backend (replace mock DirectoryService with real).
- Group membership — **done** over LDAP: `member` stores DNs, `memberOf` is
  derived by the server, the property sheet adds/removes members, and
  `AdminService` does the read-modify-write without dropping existing members.
- NTLM + SPNEGO for LDAP signing/channel binding.
- Acceptance: ADUC (Windows) can manage Monarchy users/groups.

**Phase 3 — DNS + replication (days, AI-assisted)**
- AD-integrated DNS server + dynamic update — **done** (`engine/DnsServer`: authoritative zone, SRV locator set, RFC 2136 updates, persistence; `monarchy-dns-tests`).
- Still to come: reverse zones, ageing/scavenging, DNSP RPC and zone storage in the directory.
- DRSR replication between two Monarchy DCs (and with Samba/Windows DCs).
- KCC for automatic topology.
- Acceptance: multi-DC domain; Windows DC replicates with Monarchy.

**Phase 4 — GPO + sites (days, AI-assisted)**
- Default GPO objects, `gPLink` and `GPT.INI`/`registry.pol` in SYSVOL — **done** at provisioning time.
- Still to come: SYSVOL over SMB, GPO CRUD and link editing in the console, CSE processing,
  site/subnet/site-link management.
- Acceptance: GPMC manages Monarchy GPOs; GPOs apply to clients.

**Phase 5 — 1:1 parity & polish (ongoing)**
- PKINIT/smartcard, claims, auth policies, RODC, trust topology and rotation,
  recycle bin, FGPP, gMSA.
- XPRESS compression (G8), DFS-R SYSVOL (G9), ADWS (TCP 9389) for PowerShell RSAT.
- Differential testing vs Windows DC; Microsoft Protocol Test Suites.

---

## 5. Licensing boundary

- The project is **GPL-3.0-or-later** (see [`LICENSE`](LICENSE)); every file carries an
  SPDX identifier.
- Fresh Monarchy code and Samba-derived code (Phase A/B) are therefore under the same
  licence — no permissive/GPL split to maintain.
- Qt 6 is used under LGPL-3.0, which GPL-3.0 permits; OpenLDAP's OpenLDAP Public
  License 2.8 is GPL-compatible.

Derived or copied files must still be recorded in [`CREDITS-INDEX.md`](CREDITS-INDEX.md)
**§4**; behaviour-only references (no code copied) belong in **§3** of the same index.

---

## 6. Immediate next steps (doable now)

1. **Provisioning (done):** `monarchy-provision` builds the domain from Monarchy's own
   code — no Samba install, package or process. `scripts/provision-monarchy.sh` wraps
   the built binary; `monarchy-provision-tests` provisions into a temp directory and
   binds/searches it over LDAP.
2. **LDAP frontend:** `engine/LdapServer` already answers bind, search
   (base/one-level/subtree), add, modify, delete, modify-DN, compare and rootDSE over
   a persisted store, with AND/OR/NOT, substring and presence filters; StartTLS
   (RFC 4511) upgrades a connection in place against a provisioned DC certificate, and
   request controls are parsed with paged results (RFC 2696) supported and unknown
   critical controls refused. Next: schema checks, attribute selection, SD-flag and
   extended-DN controls.
3. **Auth (done):** `unicodePwd` handling, policy checks and the AD credential (NTOWFv1) are in;
   **NTLMv2 over LDAP SASL** authenticates against it, and the **KDC** issues TGTs and service
   tickets with RC4-HMAC and AES keys derived from the same password, carrying a signed MS-PAC,
   so `kinit`, `GSSAPI`/`SPNEGO` binds and the integrity/confidentiality layers of RFC 4752 all
   work against an unmodified MIT client. Next: S4U/PKINIT, claims and PAC-based authorization.
4. **Schema loading:** port schema LDF import into the store so attribute metadata is real.
5. **Replication:** DRSR between two Monarchy DCs once the store carries USNs and tombstones.
6. **Credentials (done):** per-object salted verifiers from `unicodePwd` writes, policy checks,
   verified simple binds, `userAccountControl` enforcement (disabled accounts cannot bind), and no
   password material in search results; the console's Account tab writes those flags.
7. **Filters (done):** server-side AND/OR/NOT, equality, substrings and presence; the wire client
   encodes RFC 4515 filter strings to BER.
8. **Membership (done):** linked `member`/`memberOf` with server-side derivation,
   property-sheet editing and round-trip tests. Next: nested-group expansion in
   token generation, primary group handling, and SAMR/LSAD group operations.
9. **DNS (done):** the engine is authoritative for the domain zone, registers the full
   DC locator set for the provisioned host/ports, applies RFC 2136 updates (verified with
   `dig` and `nsupdate`), and persists the zone; `monarchy-dns-tests` covers it. Next: secure
   update ACLs/TSIG, reverse zones, and serving zone data out of `CN=MicrosoftDNS`.

These steps turn Monarchy from "UI + mock" into "UI + real directory" within one phase.