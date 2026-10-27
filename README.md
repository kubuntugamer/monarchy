# Monarchy

**Monarchy** is a Linux Active Directory implementation in progress: a domain
service with a real LDAP directory engine, a Kerberos KDC, an AD-style DNS
server, the remote-management stack AD exposes over DCE/RPC (SAMR, LSAD, DRSR,
the endpoint mapper, SMB2 named pipes), and a backend service layer. Its
administration GUI is the **Monarchy
Management Console** (`ui/`, `monarchy-ui`), which speaks LDAP to the engine
exactly as it would to a remote domain controller. Ordinary Kerberos clients
(`kinit`, SASL `GSSAPI`) authenticate against the engine unmodified.

## What works today

- **Monarchy Management Console (`ui/`)** — classic MMC layout: console tree and
  results pane, Details / Large Icons / Small Icons / List views, Back/Forward/Up
  history, filtering, CSV export, printing, tabbed property sheets, and a full
  menu and toolbar set. All object icons are drawn at runtime by Monarchy (no
  third-party artwork).
- **Directory engine (`engine/`)** — an in-process LDAP v3 server (RFC 4511
  subset) with bind, search (base/one-level/subtree), add, modify, compare,
  delete, modify-DN, WhoAmI, root DSE, and persisted JSON storage. Filters
  support AND/OR/NOT nesting, equality, substrings and presence (RFC 4515 on
  the client side too). Request controls are parsed, with **paged results**
  (RFC 2696) supported and an unknown critical control refused rather than
  ignored. **StartTLS** upgrades a live connection in place, presenting the
  DC certificate the provisioner created; a domain provisioned without
  `openssl` refuses StartTLS instead of pretending to encrypt. Passwords arrive as `unicodePwd`/`userPassword`,
  are checked against policy and stored as salted verifiers plus the AD NT hash
  (NTOWFv1) — none of which a search ever returns — and `userAccountControl` is
  honoured, so a disabled account cannot authenticate. Authentication itself is
  available three ways: simple bind; **NTLMv2 over LDAP SASL** (mechanism
  `NTLM`, GSS-SPNEGO tokens accepted), with CHALLENGE/AUTHENTICATE verified
  against the stored NT hash; and **Kerberos** over SASL `GSSAPI`/`SPNEGO` — the
  same two providers DCE/RPC binds with — so a password never crosses the wire
  on the two challenge-response paths. Group
  membership is a linked pair of attributes: `member` holds distinguished
  names and every `memberOf` is derived from the groups that list the object,
  so a forged `memberOf` is ignored and deleting an object removes it from
  every group.
- **KDC (`engine/`)** — a Kerberos 5 KDC (RFC 4120) serving TCP and UDP on **88**
  for a provisioned domain (`kdcPort` from `dc.conf`; provisioning defaults to
  AD's native bindings — DNS 53, LDAP 389, Kerberos 88, SMB 445, epm 135,
  SAMR/LSAD 49152/49153 — because the daemon runs as a root service with
  `CAP_NET_BIND_SERVICE`; `--dev-ports` provisions the unprivileged set a
  rootless console run can bind). Accounts carry
  AES-128/AES-256 (RFC 3962, PBKDF2 + n-fold string-to-key) and RC4-HMAC
  (etype 23, derived from the same NT hash the directory already stores) keys,
  so one password drives simple bind, NTLMv2 and Kerberos with no second
  secret. It answers AS-REQ with mandatory PA-ENC-TIMESTAMP pre-authentication
  (the first request gets a `PREAUTH_REQUIRED` error with etype-info2 salt
  hints), issues TGTs, and issues service tickets from a TGS-REQ with a TGT
  and its usage-7 authenticator for any service principal the directory holds
  (`ldap/<dc>`, `HOST/<dc>`, `GC/<dc>`, `krbtgt/<realm>` and whatever SPNs an
  administrator adds), sealing the reply with the request's subkey under usage
  9 when the client proposed one. Every ticket carries a **PAC** (MS-PAC):
  LOGON_INFO with the client's SID, domain SID, group RIDs and account flags,
  PAC_CLIENT_INFO for the authentication time, UPN/DNS info for name
  resolution, and the server and KDC signatures, re-signed for each service.
  The directory authorizes writes over a Kerberos session from that PAC: only
  Domain Admins (512), Enterprise Admins (519) and Schema Admins (518) may
  modify it, so a standard user's ticket can read but not write. It also verifies AP-REQs for LDAP
  SASL `GSSAPI` — Authenticator decryption, 5-minute clock skew, a replay
  cache, and both PAC signatures — returning a GSS-API AP-REP so mutual
  authentication and the SASL security layer succeed. `monarchy-provision`
  writes a `krb5.conf` that points at the new realm, so `kinit` needs no
  hand-written stanza.
- **DNS engine (`engine/`)** — an authoritative UDP zone for the domain
  (RFC 1035) that publishes the full domain-controller locator set a client
  looks for: `_ldap._tcp` for the domain, `dc._msdcs`, the site-scoped
  `_sites._msdcs` names, `_kerberos`, `_kpasswd`, `_gc` and the PDC record,
  plus SOA/NS/A. It applies RFC 2136 dynamic updates (prerequisites, `IN`/
  `ANY`/`NONE` update classes, `NOTZONE`/`NOTAUTH`/`REFUSED`/`YX*`/`NX*`
  rcodes), bumps the SOA serial, and persists the zone to `dnszone.json`.
  It is authoritative only — it does not recurse.
- **Provisioning (`engine/`)** — `monarchy-provision` creates a domain from
  Monarchy's own code: domain/configuration/schema NCs, default containers, the
  built-in accounts and groups with RIDs, this DC's computer object, SYSVOL
  directories, a salted administrator credential, and a `dc.conf` the console
  reads. It also generates the domain's DNS zone from the same code that
  serves it, and creates the two policies every domain starts with (GPO
  objects in `CN=Policies,CN=System`, `gPLink` on the domain and the Domain
  Controllers OU, `GPT.INI` and `registry.pol` under `sysvol/<domain>/Policies/
  {GUID}/`). No Samba install, package or binary is involved.
- **Backend (`backend/`)** — `ConnectionService`, `DirectoryService`, and
  `AdminService` over a built-in LDAP wire client. Building with
  `-DMONARCHY_WITH_LDAP=ON` uses the system OpenLDAP client (with GSSAPI
  support) instead.
- **Remote management (`engine/`)** — the interfaces AD serves over DCE/RPC,
  all from the same store the LDAP engine holds, on the loopback address and
  behind NTLMSSP or Kerberos binds that sign, and seal when asked: **SAMR**
  (accounts, groups, membership, the full information classes including the
  aggregate class-21 write and password sets), **LSAD** (policy information,
  privileges, account rights, secrets), **DRSR** (`DsBind`/`DsGetNCChanges`,
  `DsCrackNames`, DC info — a DCSync-shaped client can walk it), the
  **endpoint mapper**, and **SMB2** with `IPC$` named pipes into those same
  endpoints.
- **Wiring** — the console hosts the engine on ports 1389 (LDAP), 8888 (KDC)
  and 1053 (DNS), the DCE/RPC endpoints on `samrPort` 1035, `lsadPort` 1036
  and `drsPort` 1038 (loopback only), plus the endpoint mapper and SMB2 on
  `epmPort`/`smbPort`, then connects to it over LDAP. Create, edit, delete, refresh, and
  password resets round-trip through the directory and survive a restart. The
  property sheet's Members / Member Of tabs edit membership with Add/Remove,
  writing `member` on the group and letting the server update `memberOf`. The
  Account tab edits the real `userAccountControl` flags (disabled, password
  never expires) instead of private attributes. New
  objects are created under the connected naming context and only appear in
  the results pane once the directory accepts them.

## Build

Requirements: CMake 3.16+, a C++17 compiler, and Qt 6.5+ (`Widgets`, `Core`,
`Gui`, `PrintSupport`, `Concurrent`, `Network`, `Test`). OpenLDAP development
headers are optional.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

With the system OpenLDAP backend:

```sh
cmake -S . -B build-ldap -DCMAKE_BUILD_TYPE=Release -DMONARCHY_WITH_LDAP=ON
cmake --build build-ldap -j"$(nproc)"
ctest --test-dir build-ldap --output-on-failure
```

Either `cmake -S .` or the historical `cmake -S ui -B ui/build` layout works.

## Run

```sh
./build/ui/monarchy-ui
```

To create a fresh domain instead of browsing the sample directory:

```sh
./build/ui/monarchy-provision --realm CORP.EXAMPLE.COM --domain CORP \
    --adminpass 'Choose-A-Password!' \
    --targetdir "${XDG_DATA_HOME:-$HOME/.local/share}/monarchy/Monarchy"
# or, with the same defaults:
scripts/provision-monarchy.sh
```

The console reads the resulting `dc.conf` (naming context, ports, DC host and
address, site, store/secrets/zone paths), so the next start serves the
provisioned domain, validates the administrator password, and answers DNS from
the provisioned zone. Re-running the provisioner refuses to touch an existing
store unless `--force` is given. `--dc-ip` sets the address published in the
zone (default `127.0.0.1`).

```sh
dig @127.0.0.1 -p 1053 SRV _ldap._tcp.dc._msdcs.corp.example.com +short
# 0 100 1389 corpdc1.corp.example.com.
nsupdate <<'EOF'
server 127.0.0.1 1053
zone corp.example.com
update add host7.corp.example.com 300 A 10.0.0.7
send
EOF
```

### Running as boot-started system services

The same daemon turns into the machine's directory services: `scripts/
install-dc-services.sh` installs `monarchy-dcd` and the provisioner under
`/usr/local/bin`, creates a `monarchy-dc` service account, and enables the
`packaging/monarchy-dcd.service` unit so the LDAP, KDC, DNS, SAMR, LSAD,
Netlogon, DRSUAPI, EPM and SMB2 endpoints all start at boot under `/var/lib/`
monarchy/Monarchy` — the way a Windows DC starts them:

```sh
sudo scripts/install-dc-services.sh
sudo -u monarchy-dc /usr/local/bin/monarchy-provision \
    /var/lib/monarchy/Monarchy --realm MONARCHY.EXAMPLE.COM --adminpass '…'
sudo systemctl restart monarchy-dcd
```

The unit carries `AmbientCapabilities=CAP_NET_BIND_SERVICE`, and provisioning
itself defaults to the real-DC ports (DNS 53, LDAP 389, Kerberos 88, SMB 445,
epm 135), so the service binds them right away the same way `lsass.exe` does.
Provision with `--dev-ports` only for a rootless machine.

The application starts its local directory on **LDAP 1389**, the KDC on
**8888** and **DNS 1053**, serves the DCE/RPC endpoints on `samrPort` 1035,
`lsadPort` 1036 and `drsPort` 1038 (loopback), the endpoint mapper on
`epmPort` and SMB2 on `smbPort`, then connects to it automatically. Use **File →
Connect to Directory…** to point the console at a remote LDAP server (the local
engine keeps running). **File → Disconnect** returns to the offline sample
directory. Outbound LDAPS and Kerberos/GSSAPI binds to a *remote* server require
the `MONARCHY_WITH_LDAP=ON` build; the default build reports an error instead of
silently falling back to plaintext. The engine's own KDC needs no external
library — any Kerberos client can use it:

```sh
KRB5_CONFIG=/path/to/domain/krb5.conf \
KRB5CCNAME=FILE:/tmp/krb5cc kinit -V Administrator@CORP.EXAMPLE.COM
klist   # krbtgt/CORP.EXAMPLE.COM@CORP.EXAMPLE.COM, aes256-cts-hmac-sha1-96
```

SASL `GSSAPI` binds (and `SPNEGO` with a Kerberos token) then authenticate with
that ticket cache: an initial client token, the server's AP-REP, the RFC 4752
security-layer negotiation, and a success result. The server offers `none`,
`integrity` and `confidentiality`; when a client selects one, every LDAP PDU
after the bind is carried in length-prefixed GSS-API wrap tokens — RFC 4121
Wrap tokens for AES contexts, RFC 1964/RFC 4757 sealing for RC4 ones — with the
per-direction key usages, sequence numbers and checksums those documents
define. `gss_unwrap` on the client side verifies each one.

The local store is written on exit to the platform application-data directory.
Without a provisioned domain that path is
`~/.local/share/monarchy/Monarchy/directory.json` with the sample objects and the
naming context `DC=corp,DC=example,DC=com`; a provisioned domain stores its
directory under `private/` and uses the realm you chose.

## Tests

`ctest` runs fourteen suites:

- `monarchy-ui-tests` — container filtering, navigation history, view modes, CSV
  export, property-sheet edits, membership add/remove in the property sheet
  (names shown, distinguished names kept), and live loading of a 13-object test
  directory through the real LDAP stack.
- `monarchy-backend-tests` — bind/search attribute fidelity, container mapping,
  modify/add/delete round trips, root-DSE handling, DNS zone records, group
  membership (adding two members, derived `memberOf`, removal, refusal of a
  forged `memberOf`, survival of a save/load cycle), the password lifecycle
  (create, bind, wrong password, policy rejection, reset, refusal of a forged
  hash, no password material in search results), and composite/substring
  filters.
- `monarchy-ntlm-tests` — NTOWFv1/HMAC-MD5 against published test vectors, the
  MS-NLMP §3.4 session-security primitives (session base key, signing/sealing
  keys, MAC and stateful RC4) and a complete sealed token, byte for byte, against
  vectors from impacket's independent implementation; then real NTLMv2 exchanges
  over LDAP SASL: NEGOTIATE, CHALLENGE, AUTHENTICATE with a correct password
  (success), a wrong password and a disabled account (both `invalidCredentials`),
  refusal of a forged `ntHash`, and both security layers driven end to end — a
  signed session and a sealed one each carry a search request and its reply, an
  answer never appears in the clear, and a single flipped byte in a sealed token
  drops the connection instead of being answered.
- `monarchy-kerberos-tests` — RC4-HMAC and AES string-to-key against published
  vectors, then the KDC over its real socket: the `PREAUTH_REQUIRED` round trip,
  TGT issuance with the correct pre-authentication, service tickets for a
  directory SPN, AP-REQ verification and AP-REP mutual authentication, a
  Kerberos LDAP bind (bind 14 → 14 → 0), an SPNEGO-wrapped one, and rejection of
  a wrong password, a disabled account and an unknown service. Where the MIT
  krb5 client library is installed the suite is also driven by
  `krb5_get_init_creds_password` and GSS-API, i.e. the same code path as
  `kinit`: an AES-256 `kinit`, a TGS, a GSSAPI bind, PAC verification with
  MIT's own `krb5_pac_verify` and UPN/DNS buffer readback with
  `krb5_pac_get_buffer`, authorization from the PAC (a standard user's session
  is refused a write with `insufficientAccessRights` while an administrator's
  succeeds), a fully wrapped LDAP session (search over the confidentiality
  layer, both with RC4 and with AES keys) whose tokens MIT seals and opens
  independently of the server, and the DCE/RPC token split (`dceRpcFraming`),
  where the test builds a client's half of the token itself and the server has
  to recombine, verify and unseal it — and to refuse it once a byte changes or
  the key is wrong. A two-realm test provisions `ALPHA` and `BETA`,
  gives both the same trust secret, and lets MIT walk the trust: `kinit` into
  `ALPHA`, then a service ticket for `BETA` — the referral TGT from `ALPHA`, the
  cross-realm TGT accepted by `BETA`, and the resulting AP-REQ verified by
  `BETA`'s directory.
- `monarchy-dns-tests` — drives the DNS engine over real UDP: the complete DC
  locator record set and its ports, SRV/A/ANY queries, refusal of out-of-zone
  queries, dynamic update add/delete/single-value delete, prerequisite and
  zone enforcement rcodes, SOA serial bumps, and zone persistence.
- `monarchy-provision-tests` — provisions a domain into a temporary directory
  (including the default GPOs and SYSVOL content), checks the resulting objects,
  SIDs, group links, policy files, secrets and root DSE, then binds and searches
  the provisioned store over real LDAP (including rejection of a wrong
  password and of an unknown account).
- `monarchy-netlogon-tests` — the Netlogon secure-channel crypto: the
  server-authenticate exchange against independent vectors and the legacy
  `NetrLogonSamLogon` validation path. (The Netlogon endpoint slice itself is
  not part of the 0.1.0 claim — see `STATUS.md`.)
- `monarchy-drs-tests` — the DRSR bind extensions, a whole V6
  `DsGetNCChanges` reply walked field by field (every object, its attribute
  list and its values), level-2 DC info, FQDN→canonical name cracking, and
  the refusals; live, `scripts/drs-conformance.py` drives the DCSync-shaped
  sequence over impacket's independent NDR behind an authenticated
  `PKT_PRIVACY` bind (6 checks, non-zero exit on failure).
- `monarchy-samr-tests` — the SAMR wire forms pinned byte for byte: a
  bind_ack result per presentation context (NDR32 accepted, NDR64 declined),
  the enumerate/lookup/query chains, the class-21 logon-hours array against
  both oracles, and the write path (create user/group, membership, the
  aggregate information writes and the RC4-ciphered password buffers)
  replayed from impacket-captured requests.
- `monarchy-lsad-tests` — response bytes pinned for policy-information
  levels 3, 5 and 8, the audit arms, `LsarLookupPrivDisplayName`, and the
  invalid-handle/invalid-class refusals; live, `scripts/lsad-conformance.py`
  drives the endpoint through Samba's `samba.dcerpc.lsa` NDR decoder and
  impacket's `lsad`/`lsat` clients — 50 checks, all passing.
- `monarchy-epm-tests` — the tower's five floors and byte order, the lookup
  reply layout against the bytes impacket's own marshaller produces, both
  handle marshallings, paging, `ept_map` against a captured request, and the
  management-opnum refusals.
- `monarchy-smb-tests` — dialect negotiation, the tree connect to `IPC$`,
  pipe open/close, and a full DCE/RPC bind carried through a pipe.
- `monarchy-ldap-tests` — request controls: paged results (pages, total
  count, resume cookie, abandon, a foreign cookie refused), and an unknown
  critical control refused with `unavailableCriticalExtension`.
- `monarchy-tls-tests` — StartTLS against the provisioned DC certificate:
  bind and search inside the handshake, plaintext after the upgrade aborted,
  and openssl's own `s_client -starttls ldap` verifying the certificate.

All suites pass in the default and `MONARCHY_WITH_LDAP=ON` builds.

## Layout

```
backend/     Connection, directory, administration services + LDAP wire client
engine/      LDAP server, KDC, DNS server, DCE/RPC endpoints (SAMR, LSAD,
             DRSR, endpoint mapper, SMB2), persisted store
ui/src/      Console widgets, results model, property sheets, main window
ui/tests/    QtTest suites
scripts/     Provisioning wrappers and conformance drivers (impacket, Samba)
reference/   Protocol reference material with provenance and licences
*.md         Architecture, conformance, licensing, and UI design documents
```

## Credits

Upstream projects, specifications, artwork, fonts and trademark notices are
catalogued in [`CREDITS-INDEX.md`](CREDITS-INDEX.md). All C++ in this repository
is original; Samba, OpenRSAT and the other reference trees informed behaviour and
design only, and Qt 6 (plus optional OpenLDAP) are the only libraries the engine
and console link. The Kerberos test executable additionally links the MIT krb5
client, so the KDC is proved against an independent implementation.

## License

Monarchy is licensed under the **GNU General Public License, version 3 or later**
(`GPL-3.0-or-later`). The full text is in [`LICENSE`](LICENSE); every source,
build, resource and script file carries an SPDX identifier.

This choice matches the roadmap, which uses Samba (GPL-3.0) as the Phase-A engine,
and it is compatible with the current dependencies: Qt 6 is used under its
LGPL-3.0 option (which GPL-3.0 permits) and OpenLDAP's OpenLDAP Public License
2.8 is GPL-compatible. Documentation in `*.md` is covered by the same license
unless a file states otherwise; quoted specification text remains with its
original authors.

## Security and scope

This is a development directory, not a hardened domain controller. Once a domain
has been provisioned, credentials are the ones AD keeps: the salted SHA-256
verifier, the NT hash (MD4 of the UTF-16LE password) and the AES long-term keys
(PBKDF2 with the principal salt). Simple binds check the verifier; **NTLMv2 over
LDAP SASL** verifies an NtChallengeResponse against the NT hash (HMAC-MD5,
NTOWFv1); **Kerberos** derives AES-256/AES-128 and RC4-HMAC keys from the same
password, so the KDC issues tickets for them and `kinit` works against the
realm.
Passwords must meet a minimum length plus three of the four character classes,
and disabled accounts cannot bind by any of the three mechanisms. The sample
directory has no credentials and therefore still accepts any bind, and LDAP
traffic is plaintext — use the OpenLDAP build with LDAPS towards a remote
server.

Known limits of the Kerberos support: the PAC carries LOGON_INFO,
PAC_CLIENT_INFO and UPN/DNS info but not the credential, delegation or claims
buffers; authorization is enforced for writes (admin groups) and not yet for
reads; AES and RC4 are the only enctypes (no DES3).

Cross-realm trusts are implemented for a direct (single-hop) trust, which is
what a Windows 2000 external or forest trust is: the trust account in
`CN=System` holds the shared key and `trustDirection` decides whether tickets
may be issued into the peer realm or accepted from it, a request for a service
in a trusted realm is answered with a referral TGT (`krbtgt/PEER@OURS`) sealed
with that key and carrying a PAC re-signed for the trust boundary, and an
incoming `krbtgt/OURS@PEER` TGT is opened with the same key. Not implemented:
transited-realm encoding beyond one hop, SID filtering and selective
authentication, and trust-password rotation.

Both SASL security layers are implemented: RFC 4752/4121/1964 for GSSAPI and
MS-NLMP §3.4 signing and sealing for NTLM, each carried in the RFC 4422
length-prefixed framing. The KDC has no keytab export, because the keys are
computed from the directory's NT hash and password on demand.

The DNS server applies dynamic updates from any peer that can reach its port —
there is no secure-update ACL or TSIG enforcement yet — so do not expose ports
1389/1053 to untrusted networks.

Remote management over DCE/RPC: `engine/Rpc.cpp`
implements the connection-oriented transport (bind/bind_ack, request, response,
fault, NDR32 negotiation) and `engine/Ndr.cpp` the NDR primitives, with
`engine/Samr.cpp` serving SAMR, `engine/Lsad.cpp` LSAD and `engine/Drs.cpp`
DRSR. The DC process serves those endpoints itself, from
the same store the LDAP engine holds: `monarchy-ui` listens on `127.0.0.1`, on the
ports in `dc.conf` (`samrPort` 1035, `lsadPort` 1036 and `drsPort` 1038 by
default), so the accounts and RIDs returned
over SAMR are the provisioned domain's own (a provisioned domain yields
RIDs 500/501/502/1000 over both protocols). Binds authenticate with NTLMSSP,
either directly (`auth_type` 10) or wrapped in GSS-SPNEGO (`auth_type` 9), which
is what Windows and Samba send: the NegTokenInit's NTLMSSP NEGOTIATE is answered
with a NegTokenResp carrying the CHALLENGE, and the AUTHENTICATE that follows
(the third leg, in an `AUTH3` PDU or in an `alter_context`, both accepted) is
answered with accept-completed. The challenge is answered from the account's
stored NT hash and every PDU that follows is signed, or signed and sealed when
the client asks for privacy. A call made before a bind has authenticated is
refused, and a failed AUTHENTICATE ends the connection rather than downgrading
it. A bind is answered once per presentation context, in order: Windows and
Samba offer NDR32 and NDR64 in the same PDU and expect a result for each, so the
NDR32 context is accepted and the NDR64 one is declined with
`proposed_transfer_syntaxes_not_supported` instead of being silently dropped.
Kerberos is the other security provider, and the one Windows prefers: a bind
with `auth_type` 16 carries a bare AP-REQ, one with 9 the same AP-REQ inside
GSS-SPNEGO, and either way the ticket is accepted by the same KDC acceptor that
verifies LDAP's AP-REQs. The ack returns the AP-REP with a fresh acceptor
subkey, the client's closing AP-REP arrives in an `AUTH3` or an `alter_context`
and completes mutual authentication, and every call that follows carries an
RFC 4121 CFX token split around the stub — the verifier holds the header, the
encrypted copy of it, the checksum and the confounder, the stub the ciphertext
of the NDR payload — sealed at level 6 or MIC-signed at level 2, with the
sequence numbers the AP-REP started. SAMR's password buffers are keyed off the
ticket's session key, as MS-SAMR expects.

Verified interoperable against impacket's
independent SAMR client over `ncacn_ip_tcp`: bind, `SamrConnect`,
`SamrConnect2` and `SamrConnect4`, `SamrEnumerateDomainsInSamServer` and
`SamrLookupDomainInSamServer` (the
returned domain SID is parsed and printed correctly by impacket), `SamrOpenDomain`,
`SamrEnumerateUsersInDomain` (names and RIDs), `SamrOpenUser`,
`SamrQueryInformationUser2` (classes 6, 8 and 16 — the name union, the full
name and the account-control flags — 4, the logon week on its own, and 21, the
aggregate all-information class a property sheet or `net rpc user` reads:
account and full name, home directory and drive, script and profile path,
comments, workstations, parameters, RID, primary group, account flags, expiry,
last password change, logon hours, the country and code page and the password
flags). Class 21 is checked against both oracles —
impacket and Samba's own NDR client — because its logon-hours array is the
`[size_is(1260), length_is(units_per_week/8)]` of MS-SAMR 2.2.7.5, a shape
impacket models differently from Samba. `SamrLookupNamesInDomain`
(names to RIDs and `SID_NAME_USE`, with `STATUS_SOME_NOT_MAPPED` /
`STATUS_NONE_MAPPED` for names that do not resolve), `SamrLookupIdsInDomain`
(the inverse), `SamrCloseHandle`, and the write path — `SamrCreateUser2InDomain`,
`SamrCreateGroupInDomain`, `SamrOpenGroup`, `SamrAddMemberToGroup`,
`SamrRemoveMemberFromGroup`, `SamrGetMembersInGroup`, `SamrDeleteUser` and
`SamrDeleteGroup`, all of which mutate the LDAP store and persist it. Account
information is writable too: `SamrSetInformationUser` / `SamrSetInformationUser2`
cover classes 8 (full name), 13 (comment), 16 (account flags), 17 (expiry), 20
(parameters), 21 (the whole `SAMPR_USER_ALL_INFORMATION`, as ADUC's "new user"
dialog sends it), 23/25 (that structure plus a password buffer, which is how
the change-password dialogs arrive) and 24/26 (password alone). A class-21 set
applies exactly the fields its `WhichFields` mask names — full name,
description, comment, home directory and drive, script and profile path,
workstations, primary group, account flags and expiry, parameters, country and
code page and the logon week — and leaves every other field of the account
alone, the way AD does. The password buffer is not sent in the clear — it
arrives RC4-ciphered under the RPC NTLM session key, right-justified before its
length in the 512-byte block as Samba's `extract_pw_from_buffer` reads it (class
25 mixes in a confounder through MD5 first) — so `Rpc::Call` carries that key to
the handler.
A password set this way goes through the same path an LDAP write does: the
salted verifier, the NT hash and the Kerberos keys move together, so the new
password works for simple bind, NTLM and `kinit` at once. Proven live on a
provisioned `MONARCHY.FIVE`: over an authenticated, sealed session impacket
disabled and re-enabled an account (class 16, read back), set the full name
(class 8, read back), set a password with class 24 and again with class 26, then
authenticated as that account with the new password over a fresh sealed bind —
while the superseded password and a wrong one were both refused, and a
policy-violating password returned `STATUS_PASSWORD_RESTRICTION`.
Proven again on a provisioned `MONARCHY.AGG`: impacket created an account, filled
fourteen fields in a single class-21 write and read every one of them back
through class 21 (with the logon week also read back through class 4), set the
password with class 23 and again with class 25, and logged in with the last one
over a fresh sealed bind while the superseded password was refused — with LDAP
serving the same display name, home directory and week. `monarchy-samr-tests`
replays impacket-captured request bytes against that path, so the working subset
is covered in CI.

**LSAD (lsarpc)** (`engine/Lsad.cpp`): `LsarOpenPolicy`/`LsarOpenPolicy2`,
`LsarClose`, `LsarDeleteObject`, `LsarQueryInformationPolicy` for every class
MS-LSAD defines (audit log and events, domain, PD account, server role, replica
source, quotas, audit-full set and query, DNS domain), both translation
directions — `LsarLookupNames`/`LsarLookupSids`, paged with
`STATUS_MORE_ENTRIES` and closed with `STATUS_NO_MORE_ENTRIES` — the
34-privilege catalogue (`LsarEnumPrivileges`, `LsarLookupPrivValue`/`PrivName`/
`PrivDisplayName`), account rights and system-access masks written to the
account's `userRight` in the directory (LDAP shows them, they survive a
restart), secrets and private data, `LsarGetUserName`, the policy security
descriptor, and `LsarEnumTrustDom` answering empty, as a standalone DC. The
independent check is `scripts/lsad-conformance.py`: 50 checks against a live
endpoint through Samba's `samba.dcerpc.lsa` (pidl's decoder, the reference the
layout is written against) and through impacket's `lsad`/`lsat` clients.

**DRSR (MS-DRSR)** (`engine/Drs.cpp`): `DsBind`/`DsUnbind` with the extension
words advertising GETCHGREQ V5/V8/V10 and GETCHGREPLY V6; `DsGetNCChanges`
answered in V6 for V8/V10 requests — the canonical 19-entry schema prefix
table, the usnvec echo, up-to-date cursors, a batch capped by `cMaxObjects`
with `fMoreData` for the rest, and the object chain marshalled the way the
peer walks it; `EXOP_REPL_OBJ` targeting one object by DN, GUID or SID;
`DsReplicaSync`/`DsUpdateRefs` as the lifecycle calls a cycle makes;
`DsCrackNames` translating FQDN, canonical, NT4, UPN, display name, GUID, SID
and DNS-domain forms; and `DsGetDomainControllerInfo` levels 1–3 describing
this DC. Password material is deliberately not served — replication-level
conformance, not secret export. `monarchy-drs-tests` pins a whole V6 reply
field by field, and `scripts/drs-conformance.py` drives the DCSync-shaped
sequence over impacket's independent NDR behind an authenticated NTLMSSP bind
at `PKT_PRIVACY` (6 checks). `DsReplicaAdd` and the multi-DC half remain.

**SMB2 and named pipes** (`engine/Smb2.cpp`): dialect negotiation (2.0.2/2.1),
session setup carrying SPNEGO/NTLMSSP verified by the same authenticator SAMR
and LSAD use, SMB2 signing (HMAC-SHA256 over the exported session key, with the
key-exchange RC4 step), and `IPC$` pipe I/O. Each pipe is a headless channel
into that interface's own `RpcServer`, so `\\dc\pipe\samr` runs exactly the
bind, dispatch and fault code the TCP endpoint runs. Live against a provisioned
DC, impacket over `ncacn_np` enumerates the SAMR domain and opens the LSAD
policy, and Samba's own `smbclient -L` authenticates and lists the server.

**Endpoint mapper** (`engine/Epm.cpp`): `ept_lookup` and `ept_map` on `epmPort`
(135 by default, `epmPort` in `dc.conf`), so a client that knows an interface
UUID and a protocol can ask which port it lives on instead of being told.
Answers are built from the ports the endpoints actually bound, and the tower is
the five-floor C706 appendix L encoding — interface, data representation,
binder, and then either TCP port plus IPv4 address (big-endian) or the pipe name
plus host, so every interface is advertised over both transports.
`monarchy-epm-tests` pins the encoding and the reply layout against the bytes
impacket's own marshaller produces; live, `hept_lookup` returns six entries
(`lsarpc`/`samr`/`epmapper` each as `ncacn_ip_tcp` and as
`ncacn_np:…[\pipe\…]`), and `hept_map` answers with the transport asked for:
`ncacn_np` gives `\pipe\samr`, `ncacn_ip_tcp` gives port 1035. Binding 135
needs `CAP_NET_BIND_SERVICE` or root, so an unprivileged console says so and
stays reachable by explicit port.
Protocol references used for this
(Samba's `samr`/`lsa`/`drsuapi`/`netlogon`/`epmapper` IDLs and impacket's
`samr`/`lsad`/`epm` clients, with
provenance and licences) are held in `reference/specs/`. Everything else — the
bad-password and logon counters, the domain information *set* calls, and aliases
— is absent and is not claimed to work; Netlogon (secure channel, DC locator,
domain join) and `DsReplicaAdd` with the multi-DC half of replication are not
implemented, nor is SMB 3.x, so there is no SMB encryption or preauth integrity, and `IPC$`
is the only share — `\pipe\samr`, `\pipe\lsarpc` and `\pipe\epmapper` are
reachable over SMB2 (see below), but a directory browse is empty;
and LSAD's trusted-domain calls are refused until Netlogon exists to carry their
secure channel. A logon week written over SAMR is
stored and read back, but nothing consults it at logon yet, so it restricts
nobody.
`monarchy-rpc-probe` is the development endpoint used to drive that interop by
hand, and `STATUS.md` is the 0.1.0 release contract.

Not yet implemented: PKINIT and S4U, the rest of SAMR, LSAD trusted domains,
Netlogon, `DsReplicaAdd` and multi-DC replication (two Monarchy DCs, or
Samba/Windows peers),
NTLM over raw SMB/DCE, GPO editing and client-side extension processing, the
DNSP RPC interface and
DNS zone storage in the directory (`CN=MicrosoftDNS,...`), reverse zones and
scavenging, schema LDF import, and the full 1:1 conformance register. See `AD-FULL-IMPLEMENTATION-PLAN.md`,
`AD-UI-WIRING-PLAN.md`, and `AD-1TO1-CONFORMANCE.md` for the roadmap.
