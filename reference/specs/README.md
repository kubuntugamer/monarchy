# Protocol references held locally

These files are **reference material**, not part of the build and not linked into
Monarchy. They are here so the wire formats in `engine/` can be checked against
authoritative descriptions instead of memory.

| File | Origin | Licence | Used for |
|---|---|---|---|
| `samba-samr.idl` | Samba `librpc/idl/samr.idl`, gitlab.com/samba-team/samba (master) | GPL-3.0-or-later | SAMR opnums, structures, `samr_UserInfo` union discriminants |
| `samba-lsa.idl` | Samba `librpc/idl/lsa.idl` | GPL-3.0-or-later | LSAD (policy, trust and account lookups) |
| `samba-drsuapi.idl` | Samba `librpc/idl/drsuapi.idl` | GPL-3.0-or-later | DRSR replication calls |
| `samba-netlogon.idl` | Samba `librpc/idl/netlogon.idl` | GPL-3.0-or-later | Netlogon secure channel (`nrpc` lives here now) |
| `samba-security.idl` | Samba `librpc/idl/security.idl` | GPL-3.0-or-later | SIDs, ACEs, security descriptors, `samr_*` access masks |
| `samba-epmapper.idl` | Samba `librpc/idl/epmapper.idl`, fetched 2026-10-22 from `gitlab.com/samba-team/samba/-/raw/master/librpc/idl/epmapper.idl` | GPL-3.0-or-later | EPM interface (`e1af8308-5d1f-11c9-91a4-08002b14a0fa` v3.0): `epm_Lookup`/`epm_Map`/`epm_MapAuth`/`epm_InqObject`, protocol/floor/tower layout, the `EPMAPPER_STATUS_*` codes |
| `impacket-epm.py` | impacket `impacket/dcerpc/v5/epm.py`, fetched 2026-10-22 from `raw.githubusercontent.com/fortra/impacket/master/impacket/dcerpc/v5/epm.py` | Apache-2.0 | Working EPM client: `twr_t`/`twr_p_t`/`ept_entry_t` marshalling, `EPMTower` floors, `hept_lookup`/`hept_map`, `PrintStringBinding` to read a tower back as `ncacn_ip_tcp:host[port]` |
| `impacket-samr.py` | impacket 0.13 `impacket/dcerpc/v5/samr.py` | Apache-2.0 | Working client: NDR layouts, opnums, response shapes |
| `impacket-lsad.py` | impacket `.../lsad.py` | Apache-2.0 | LSAD client |
| `impacket-ndr.py`, `impacket-rpcrt.py` | impacket `.../ndr.py`, `rpcrt.py` | Apache-2.0 | NDR/union/pointer rules, DCE/RPC PDU framing |

Specifications these implement (fetched by URL when needed):

- MS-SAMR — Security Account Manager Remote Protocol
- MS-LSAD — Local Security Authority (Domain Policy) Remote Protocol
- MS-DRSR — Directory Replication Service Remote Protocol
- MS-NRPC — Netlogon Remote Protocol
- MS-RPCE — Remote Procedure Call Protocol Extensions (DCE/RPC + NDR)
- DCE 1.1 RPC, Open Group C706 — chapter 6 (endpoint mapper interface), appendix L
  (towers) and appendix O (the official EPM IDL), `pubs.opengroup.org/onlinepubs/9629399/`
- MS-PAC, MS-PKCA (PKINIT), MS-SFU (S4U2Self/S4U2Proxy)

## How they are used

The working subset of SAMR in `engine/Samr.cpp` was checked byte for byte
against impacket's marshaller, and request stubs captured from it are replayed in
`ui/tests/test_samr.cpp`. Where the two disagree with a guess, the reference
wins: the `samr_UserInfo` discriminant is a `uint16` tag followed by 2 bytes of
padding, and class 6 (`SamrUserInformationName`) is the name arm — class 1 is
*General*, which an earlier version of the code got wrong.

The IDLs are kept as text for layout queries, e.g.:

```
grep -n "samr_UserInfo" -A 40 reference/specs/samba-samr.idl
grep -n "samr_LookupNames" -A 20 reference/specs/samba-samr.idl
```

## Licensing note

Samba is GPL-3.0-or-later, the same licence as Monarchy. impacket is Apache-2.0;
it is stored purely as a test oracle and no impacket code is copied into the
engine or the console. `CREDITS-INDEX.md` records both.
