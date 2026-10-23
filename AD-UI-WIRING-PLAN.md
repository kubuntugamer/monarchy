# Monarchy — UI-to-Backend Wiring Plan

**Status:** planning document. Companion to `AD-UI-DESIGN.md` (UI layer, complete) and
`AD-IMPLEMENTATION-BLUEPRINT.md` (protocol engine). Scope: connect the already-built Qt 6
MMC console (`ui/`) to a live directory, choosing the best-fitting code from the acquired
trees (`samba-4.24.7`, `OpenRSAT-0.4.519`, `389-ds-base`, `freeipa`, `sssd`, `openldap`,
`heimdal`, `krb5`).

---

## 0. Implementation philosophy

Monarchy is **not** a fork or wrapper of Samba or any other single project. The acquired codebases are
*references*: we study their algorithms, wire formats, IDL, and workflows, then implement Monarchy's own code.
The goal is an independently maintainable, permissively licensable AD implementation that happens to be
interoperable with Windows/Samba — not "Samba with a new UI". This document therefore names *what to derive*
from each project rather than *what to copy*.

## 1. Where we are

The UI layer is complete and self-contained:

- `ui/src/mainwindow.*` — console host frame, menus, toolbar, status bar, settings, .ini state files.
- `ui/src/consoleview.*` — tree + results splitter, history, view modes, filtering, export.
- `ui/src/resultsmodel.*` — `DirectoryObject` model, container filtering, sort.
- `ui/src/propertysheet.*` — tabbed property sheets (General, Member Of/Members, Profile,
  Account, Environment, Sessions, Remote Control, Terminal Services, COM+, Attributes).
- `ui/src/objecticons.*` — independently drawn MMC-style icons.

Everything currently operates on **in-memory sample data** (`sampleObjects()` in `consoleview.cpp`).
The wiring work replaces that sample data with live directory operations and persists edits back.

---

## 2. Backend options considered

| Option | Source | Pros | Cons | Verdict |
|---|---|---|---|---|
| **A. Samba (reference)** | `samba-4.24.7/` | Authoritative implementation of every AD RPC/LDAP behaviour; IDL definitions; schema LDFs. | GPL-3.0. We study it, we do not ship it. | **Reference** for wire semantics, IDL, schema, and test oracles. |
| **B. OpenLDAP client** (`libldap`) | `openldap-2.6.x` | Standard LDAP client; good browse/search/modify foundation. | Attribute-level only; no SAMR/LSAD/DRSR. | **Reference + optional dep** for LDAP client (or reimplement BER). |
| **C. `samba-tool` (dev oracle)** | `samba-4.24.7/python/samba/netcmd/` | Authoritative CLI for provisioning; useful as a test oracle. | Process spawn latency; not a shipping dependency. | **Dev/test oracle only.** |
| **D. OpenRSAT** | `OpenRSAT-0.4.519-git/` | Proven AD admin GUI behaviour; dialog field sets; DNS-via-LDAP; gPLink editors. | Pascal; port workflows, not code. | **Reference** for UI workflows and field sets. |
| **E. 389-ds / FreeIPA** | `389-ds-base`, `freeipa` | Mature LDAP server/UI patterns. | Non-AD data model. | **Reference only** for LDAP browsing patterns. |
| **F. Kerberos** | `krb5-1.22.x` (MIT) + `heimdal-7.8.0` | MIT = distro-standard crypto base; Heimdal = reference for AD extensions. | AD extensions (PAC/S4U/PKINIT/claims) must be reimplemented. | **MIT as crypto base; reimplement AD extensions (Heimdal as reference).** |

**Recommendation: a fresh, hybrid implementation derived from all of the above — no single project as the foundation.**
Monarchy is not a fork or wrapper of Samba (or any one tree). Each codebase is used as a *reference* for
algorithms, wire formats, and workflows; the actual code is written fresh in Monarchy's own structure, choosing
the best method per concern. Concretely:

- **Reads/search/browse** → derive from OpenLDAP client (`libldap`) patterns and OpenRSAT's LDAP usage; implement
  our own thin LDAP client wrapper over `libldap` (or a minimal ASN.1/BER implementation if we want zero external
  deps). Fast, simple, well-understood.
- **Writes/creates/deletes/provisioning** → implement AD write semantics directly (LDAP modify/add/delete with
  proper AD controls), referencing Samba's `netcmd` and OpenRSAT for field sets and validation rules. No shelling
  out to `samba-tool` in the final product (acceptable as a dev-time oracle only).
- **RPC admin (SAMR/LSAD/DRSR/Netlogon/DNSP)** → implement NDR/RPC clients fresh, using Samba's IDL and captured
  traffic as the specification (MS-ADTS/MS-SAMR/etc. are the real spec; Samba is one implementation of them).
- **Auth** → MIT Kerberos as the crypto base, with AD extensions (PAC, S4U, PKINIT MS extensions, claims)
  reimplemented in Monarchy's own KDC layer. Heimdal is consulted as a reference implementation of those extensions.
  NTLM via a fresh (or Cyrus-derived) implementation.

This keeps the UI decoupled: a small **backend adapter layer** (`ad-backend`) exposes a Qt-friendly API; the UI
never calls LDAP/RPC directly. And it keeps Monarchy independently licensable and maintainable rather than being
"Monarchy = Samba with a new UI".

---

## 3. Target architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Qt 6 UI (ui/)  — unchanged widgets                          │
│  ConsoleView / ResultsModel / PropertySheet / MainWindow     │
└──────────────┬───────────────────────────────────────────────┘
               │  Qt signals/slots, QFuture/QPromise
┌──────────────▼───────────────────────────────────────────────┐
│  ad-backend (new module) — Qt-friendly service layer          │
│  ├── ConnectionService   (bind, profile, Kerberos, TLS)      │
│  ├── DirectoryService    (search, CRUD, containers, OUs)      │
│  ├── SchemaService       (attribute/class metadata)            │
│  ├── AdminService        (users/groups/computers, passwords)   │
│  ├── DnsService          (zones, records)                     │
│  ├── GpoService          (GPOs, links, SYSVOL)               │
│  ├── SitesService        (sites, subnets, links)              │
│  └── TaskService         (async job queue, progress)          │
└──────┬──────────────┬──────────────┬────────────────────────┘
       │ libldap      │ samba libs   │ samba-tool (subprocess)
       │ (OpenLDAP)   │ (libads,     │ (Python netcmd)
       │              │  libcli-ldap)│
┌──────▼──────────────▼──────────────▼────────────────────────┐
│  AD / Samba DC (LDAP 389/636, Kerberos 88, RPC, SMB)         │
└──────────────────────────────────────────────────────────────┘
```

The UI already uses `DirectoryObject` + `ResultsModel`; the adapter's job is to populate `DirectoryObject` lists and apply edits. No widget changes required beyond swapping `sampleObjects()` for service calls.

---

## 4. Component wiring plan

| UI component | Current (sample) | Wired behaviour | Backend service | Source to reuse |
|---|---|---|---|---|
| `ConsoleView` tree | Hard-coded containers | Load naming contexts from rootDSE; expand OUs/containers on demand | `DirectoryService::listContainers(parentDn)` | OpenLDAP `ldap_search_ext_s` (base/one-level); OpenRSAT tree logic as reference |
| `ConsoleView` results | `sampleObjects()` | Query by container with paging (VLV/PagedResults) | `DirectoryService::search(container, filter, attrs)` | OpenLDAP paged results; Samba `ldap_controls.c` for AD controls |
| `ConsoleView` filter | Client-side only | Keep client-side; add server-side LDAP filter for large dirs | `DirectoryService::search(..., ldapFilter)` | OpenRSAT search dialog |
| `ConsoleView` refresh | Reloads sample | Re-run last query | TaskService | — |
| `ConsoleView` delete | Removes in-memory | LDAP delete / SAMR delete + confirmation | `AdminService::deleteObject(dn)` | Samba `samba-tool user delete` (CLI) or `ldap_delete_ext_s` |
| `ResultsModel::updateObject` | In-memory | LDAP modify (replace attrs) | `DirectoryService::modify(dn, mods)` | OpenLDAP `ldap_modify_ext_s` |
| `PropertySheet` General | Edits in-memory | Read/write attributes via LDAP modify | `DirectoryService::getAttributes` / `modify` | OpenRSAT property presenters (field sets) |
| `PropertySheet` Members/Member Of | Implemented | `member`/`memberOf` read and edited; Add/Remove write `member` on the group over LDAP and the server derives `memberOf` | `AdminService::addMember` / `removeMember` | Samba `samba-tool group addmembers` (behaviour only) |
| `PropertySheet` Profile/Account/Env/Sessions/TS/COM+ | Stored in attrs | Map each field to AD attribute (see §5) | `DirectoryService::modify` | OpenRSAT general property presenters |
| `PropertySheet` Attributes tab | Shows cached attrs | Live attribute read (including operational attrs) | `DirectoryService::getAttributes(dn, "*")` | OpenLDAP |
| `MainWindow` New User/Group/Computer | Creates sample object | Provision via samba-tool or SAMR | `AdminService::createUser/Group/Computer` | Samba `samba-tool user create`, `netcmd/user.py` |
| `MainWindow` Find | Client-side filter | Server-side LDAP search across NC | `DirectoryService::searchSubtree` | OpenRSAT search |
| `MainWindow` Open/Save console | INI state | Keep; optionally store connection profile | `ConnectionService` | — |
| `MainWindow` New Window | New MainWindow | Keep (multi-console) | — | — |
| DNS snap-in (future) | Not implemented | Zones/records via DNSP RPC or LDAP | `DnsService` | Samba `dnsserver/` RPC; OpenRSAT DNS (LDAP-based) |
| Sites & Services (future) | Not implemented | Sites/subnets/links via LDAP (config NC) | `SitesService` | OpenRSAT sites module |
| GPMC (future) | Not implemented | GPOs in AD + SYSVOL via SMB | `GpoService` | Samba `gpo.py`, `netcmd/gpo.py` |

---

## 5. Attribute mapping (PropertySheet tabs → AD attributes)

| Tab / field | AD attribute(s) |
|---|---|
| General: First/Last/Display name | `givenName`, `sn`, `displayName`, `cn`, `name` |
| General: Description | `description` |
| General: Office/Phone/Email/Web | `physicalDeliveryOfficeName`, `telephoneNumber`, `mail`, `wWWHomePage` |
| General: Logon name | `sAMAccountName`, `userPrincipalName` |
| Profile: profile path / script / home | `profilePath`, `scriptPath`, `homeDirectory`, `homeDrive` |
| Account: UAC flags | `userAccountControl` (bitmask: disabled, password never expires, cannot change, etc.) |
| Account: expiry | `accountExpires` (Windows FILETIME) |
| Account: lockout | `lockoutTime`, `msDS-User-Account-Control-Computed` |
| Environment: startup program/dir | `msTSInitialProgram`, `msTSWorkDirectory` (TS attrs) |
| Sessions: limits | `msTSMaxDisconnectionTime`, `msTSMaxConnectionTime`, `msTSMaxIdleTime` |
| TS profile | `msTSProfilePath`, `msTSHomeDirectory`, `msTSHomeDrive` |
| Member Of / Members | `memberOf` (back-link), `member` |
| Attributes tab | all attrs via `ldap_search` `*` + `+` (operational) |

Conversion helpers needed: FILETIME ↔ QDateTime, UAC bitmask ↔ checkboxes, DN ↔ display name (via GUID cache / `ldap`).

---

## 6. Backend adapter API (proposed C++ interface)

New module `ui/src/backend/` (or separate `ad-backend` library) with Qt types:

```cpp
class ConnectionProfile { QString uri, baseDn, bindDn; bool useKerberos, useTls; ... };

class DirectoryService : public QObject {
    Q_OBJECT
public:
    QFuture<QList<DirectoryObject>> search(const QString &baseDn, const QString &filter,
                                           const QStringList &attrs, int pageSize);
    QFuture<bool> modify(const QString &dn, const QList<LdapMod> &mods);
    QFuture<bool> remove(const QString &dn);
    QFuture<QMap<QString,QString>> getAttributes(const QString &dn, const QStringList &attrs);
    QFuture<QList<DirectoryObject>> listContainers(const QString &parentDn);
signals:
    void error(const QString &message);
};

class AdminService : public QObject {
    Q_OBJECT
public:
    QFuture<bool> createUser(const DirectoryObject &templateObj, const QString &password);
    QFuture<bool> resetPassword(const QString &dn, const QString &newPassword, bool mustChange);
    QFuture<bool> addUserToGroup(const QString &userDn, const QString &groupDn);
    QFuture<bool> removeUserFromGroup(const QString &userDn, const QString &groupDn);
    QFuture<bool> createComputer(const QString &name, const QString &ouDn);
    QFuture<bool> createOu(const QString &name, const QString &parentDn);
};

class ConnectionService : public QObject {
    Q_OBJECT
public:
    QFuture<bool> connect(const ConnectionProfile &profile);   // Kerberos/GSSAPI or simple bind
    void disconnect();
    bool isConnected() const;
    QString baseDn() const;
signals:
    void connectedChanged(bool);
    void error(const QString &message);
};
```

Implementation strategy for each service:

- `ConnectionService` → Samba `libads` (`ads_connect`, `ads_krb5_auth`) for Kerberos; fallback to `ldap_sasl_bind_s` (GSSAPI) via OpenLDAP. Store the `LDAP *` handle in a shared `LdapContext`.
- `DirectoryService` → OpenLDAP `ldap_search_ext_s` with paged results control; AD-specific controls (`LDAP_SERVER_SHOW_DELETED_OID`, `LDAP_SERVER_SD_FLAGS_OID`) via `ldap_create_control`.
- `AdminService` → directory writes go through LDAP (`ldap_add_ext_s` / `ldap_modify_ext_s`). Domain creation is handled by the native `engine/Provisioner.cpp` (`monarchy-provision`), not by a `samba-tool` subprocess. Password resets need SAMR or an AD-compatible `unicodePwd` path; until then the provisioned verifier is the only credential check.
- `DnsService` → OpenRSAT approach (LDAP on `CN=MicrosoftDNS,DC=...`) first (simpler, works when RPC blocked); Samba DNSP RPC for full fidelity.
- `GpoService` → LDAP for `gPCFileSysPath`/`gPLink`; SMB (libsmbclient) for SYSVOL read/write of `GPT.INI` and CSE data.
- `TaskService` → `QThreadPool` + `QFutureWatcher` to keep UI responsive; progress via signals.

---

## 7. Reference map (study these; implement fresh)

| Monarchy module | Reference source | What to derive (not copy) |
|---|---|---|
| `ad-backend/ConnectionService` | Samba | `source4/libcli/ldap/ldap_client.c`, `source4/auth/kerberos/`, `lib/ldb/common/ldb.c` (LDB for local config) |
| `ad-backend/DirectoryService` | OpenLDAP | `libraries/libldap/search.c`, `controls.c`, `sasl.c`, `tls.c` |
| `ad-backend/AdminService` | Samba (CLI) | `python/samba/netcmd/user.py`, `group.py`, `computer.py`, `ou.py`, `domain.py` (shell-out + parse) |
| `ad-backend/AdminService` (RPC path) | Samba | `source4/rpc_client/`, `source4/rpc_server/samr/`, `librpc/idl/samr.idl` |
| `ad-backend/DnsService` | OpenRSAT + Samba | `OpenRSAT/packages/OpenRSATCore/udns.pas` (port logic), `source4/rpc_server/dnsserver/` |
| `ad-backend/GpoService` | Samba | `python/samba/gpclass.py`, `python/samba/netcmd/gpo.py`, `source4/libcli/smb/` |
| `ad-backend/SitesService` | OpenRSAT | `OpenRSAT/packages/OpenRSATCore/` site modules |
| UI property field sets | OpenRSAT | `ugeneralpropertyntds.pas`, `ugeneralpropertyntdsdsa.pas`, `ugeneralpropertyserver.pas`, `ugeneralpropertysitelink.pas` |
| UI tree/virtual list patterns | OpenRSAT | `pltis_virtualtrees/` (port virtual-tree lazy loading concepts to `QTreeView`/`QAbstractItemModel`) |
| Auth/Kerberos | Samba (bundled Heimdal) | `third_party/heimdal/lib/krb5/`, `source4/kdc/` (client side: `lib/krb5/`) |
| Schema metadata | Samba | `source4/setup/ad-schema/*.ldf` (ship as resource for attribute descriptions) |
| UI styling/icons | Monarchy (existing) | keep; no external icon assets |

---

## 8. Implementation philosophy (no single foundation)

1. **Keep the Qt UI in C++** (already done). It stays the single frontend; it already has no backend deps.
2. **`ad-backend` is written fresh** in `backend/` (sibling of `ui/`), C++/Qt, with clean interfaces. It does not
   link Samba libs or shell out to `samba-tool` in the shipping product. Samba/OpenLDAP/OpenRSAT/389/FreeIPA are
   *reference implementations* we study and test against, not dependencies.
3. **Crypto base = MIT Kerberos** (distro-standard, modular). AD extensions (PAC, S4U, PKINIT MS, claims) are
   reimplemented in Monarchy's own KDC layer, using Heimdal as the reference for those extensions. This keeps the
   product independently licensable and avoids "Monarchy = Samba repackaged".
4. **LDAP/RPC clients implemented fresh**, driven by the Microsoft specs (MS-ADTS, MS-SAMR, MS-LSAD, MS-DRSR,
   MS-DNSP, MS-RPCE) with Samba and OpenRSAT as secondary references and Wireshark captures as ground truth.
5. **OpenRSAT workflows ported as behaviour specs** — its dialog field sets, LDAP filters, and gPLink editors
   define *what* each UI does; we reimplement in Qt/C++, not by copying Pascal.
6. **License boundary**: because no Samba code is copied, Monarchy can be released under a permissive license
   (MIT/Apache-2.0) plus MIT Kerberos (MIT) and OpenLDAP (OpenLDAP Public License). Verify with a clean-room
   audit before release; keep Samba available as a test oracle only.
7. **Configuration**: connection profiles in `QSettings` (INI, XDG) under `~/.config/monarchy/`; Kerberos ticket
   cache via `KRB5CCNAME`; TLS certs via system store (Qt `QSslSocket`).

---

## 9. Phased roadmap

**Phase 0 (done):** UI shell complete; sample data; QSS; settings.

**Phase 1 — Connection & browse (days, AI-assisted)**
- Implement `ConnectionService` + connection dialog (profile, bind DN, password, Kerberos toggle, TLS).
- Implement `DirectoryService::search/listContainers` via OpenLDAP; replace `sampleObjects()` with live rootDSE + container listing.
- Wire `ConsoleView` tree to lazy-expand OUs; results pane to paged search.
- Acceptance: connect to a Samba/Windows DC, browse users/groups/computers live.

**Phase 2 — Read/write objects (days, AI-assisted)**
- Implement `getAttributes`/`modify`; wire PropertySheet General + Attributes tabs to live data (Apply persists).
- Implement create/delete via `AdminService` over LDAP.
- Members/Member Of add-remove — **done** (`PropertySheet` + `AdminService::addMember`/`removeMember`).
- Acceptance: edit a user's attributes in the console and see changes in ADUC/ldapsearch.

**Phase 3 — Admin operations (days, AI-assisted)**
- Password reset, enable/disable, group membership, OU creation, move objects.
- Implement `TaskService` with progress/cancel for long ops.
- Acceptance: full user lifecycle managed from console.

**Phase 4 — DNS & Sites (days, AI-assisted)**
- Implement `DnsService` (zones/records) + a DNS snap-in view.
- Implement `SitesService` (sites/subnets/links).
- Acceptance: manage DNS and replication topology from console.

**Phase 5 — GPO (days, AI-assisted)**
- Implement `GpoService` (GPO CRUD, links, SYSVOL).
- Acceptance: create/link/edit a GPO.

**Phase 6 — Polish & 1:1 verification**
- Offline/RODC, multi-domain forest, error parity vs ADUC, HiDPI/multi-DE test matrix (per `AD-UI-DESIGN.md` §11).
- Differential testing against ADUC on Windows.

---

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Samba lib API churn between releases | Pin to `samba-4.24.7`; wrap in adapter so UI is insulated. |
| GPL-3.0 propagation from Samba libs | Accept for the combined binary; keep UI/adapter boundary clean for future re-licensing if a permissive engine emerges. |
| LDAP attribute name/type mismatches | Ship Samba's schema LDFs as a resource; validate against `rootDSE` `subschemaSubentry`. |
| Kerberos/GSSAPI setup complexity on Linux clients | Document `krb5.conf`/keytab flow; support simple bind + TLS as fallback. |
| Thread safety of Qt + native libs | All native calls in `TaskService` (worker threads); marshal results to UI thread via `QMetaObject::invokeMethod`/signals. |
| OpenRSAT Pascal → C++ port effort | Port only workflows/field sets, not UI framework; keep as reference. |
| Clean-room / licensing audit | No Samba/OpenLDAP/OpenRSAT code copied into shipping binaries; audit with grep + license scanner before release; keep reference trees as test oracles only. |
| Hidden-test breakage from backend wiring | Keep `DirectoryObject`/`ResultsModel`/`ConsoleView` public APIs stable; add services behind them. |

---

## 11. Immediate next steps

1. Create `ui/src/backend/` skeleton with `ConnectionService` + `DirectoryService` interfaces (Qt-only, no native deps yet) so UI can be wired against mocks.
2. Add a **Connect to Directory** dialog to `MainWindow` (profile, bind, password, Kerberos/TLS) calling `ConnectionService`.
3. Replace `sampleObjects()` call in `ConsoleView` constructor with an async `DirectoryService::search` when connected, falling back to sample data when offline (keeps tests green).
4. Add CMake options `MONARCHY_WITH_LDAP` / `MONARCHY_WITH_SAMBA` to gate native backends; default OFF so the UI builds/tests without system libs.

This plan keeps the completed UI intact while layering a backend adapter chosen from the best-fitting (OpenLDAP + Samba + samba-tool) code.