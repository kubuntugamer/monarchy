# Testing the servers

Every capability in [`STATUS.md`](STATUS.md) is claimed with three things, and a
change that breaks any of them has broken the claim:

1. **a suite** that fails when the behaviour changes,
2. **an independent client** — not this tree's own encoder — that the suite or
   the conformance stage drives, and
3. **a live probe** against a provisioned DC, because a server that answers a
   unit-test socket is not the same thing as a server that answers on a port.

A row with no independent client is a suite testing itself. The gaps at the end
are where that is still true, and they are listed rather than implied away.

## 1. The matrix

Ports are `native / --dev-ports`. Netlogon (1037) and DRSUAPI (1038) keep the
same number in both sets; the catalog (3268) is already unprivileged; the
endpoint mapper (135) and SMB (445) stay native under `--dev-ports`.

| Endpoint | Port | Suites | Independent client | Live probe |
|---|---|---|---|---|
| LDAP (RFC 4511 subset) | 389 / 1389 | `monarchy-ldap-tests`, `monarchy-backend-tests` | raw BER on a socket (`ui/tests/ldap_wire_helpers.h`) | raw-BER bind/search, `ldap3` |
| Global Catalog (same store) | 3268 / 3268 | `monarchy-provision-tests` (`publishesItsIdentityAndGlobalCatalog`) | none — the suite drives both ports itself | search the same object on 3268 |
| StartTLS (RFC 4511 §4.14.1) | as LDAP | `monarchy-tls-tests` | **openssl** `s_client -starttls ldap` | ldap3 against `private/ldap.crt` as CA |
| SASL NTLM + signing/sealing | as LDAP | `monarchy-ntlm-tests` | **impacket** message layouts, byte-exact | — |
| DNS (locator, A/SRV/ANY, RFC 2136) | 53 / 1053 | `monarchy-dns-tests` | **dig** and a hand-built query | `dig @dc -p port SRV …`; `scripts/check-dc-health.sh` follows every locator |
| KDC (RC4-HMAC, AES-128/256) | 88 / 8888 | `monarchy-kerberos-tests` | **MIT krb5** `kinit` / GSSAPI | `kinit` into a provisioned realm |
| kpasswd (RFC 3244) | 464 / 1464 | `monarchy-kpasswd-tests` | **MIT** `krb5_change_password` / `krb5_set_password` | same, against the daemon |
| SAMR | 49152 / 1035 (loopback) | `monarchy-samr-tests` | **impacket** NDR, **Samba** `dcerpc.samr` | `scripts/samr-conformance.py` |
| LSAD | 49153 / 1036 (loopback) | `monarchy-lsad-tests` | **impacket** NDR (Samba half needs pidl) | `scripts/lsad-conformance.py --skip-samba` |
| Netlogon (MS-NRPC) | 1037 / 1037 (loopback) | `monarchy-netlogon-tests` | **impacket** NDR | `scripts/netlogon-conformance.py` (creates its machine account over SAMR) |
| DRSUAPI | 1038 / 1038 (loopback) | `monarchy-drs-tests`, `monarchy-drsclient-tests`, `monarchy-replication-tests` | **impacket** NDR | `scripts/drs-conformance.py` |
| Endpoint mapper (C706) | 135 / 135 (loopback) | `monarchy-epm-tests` | **impacket** `hept_lookup` / `hept_map`, C706 appendix L towers | `hept_lookup` returns a port that accepts a connection |
| SMB2 + named pipes | 445 / 445 | `monarchy-smb-tests` | **impacket** over `ncacn_np` (live only) | binary walk of `\pipe\samr`, `\\dc\SYSVOL` |
| SMB1 (NT LM 0.12) | 445 / 445 | `monarchy-smb1-tests` | **Samba** `smbclient -m NT1` (live only) | fetch `GPT.INI` byte for byte, anonymous refused |
| The endpoint set as a whole | every port `dc.conf` declares | `monarchy-dcservice-tests` | a TCP connection to each declared port, made by the kernel | `scripts/check-dc-health.sh` |
| RPC auth (NTLMSSP + SPNEGO + Kerberos) | all RPC | `monarchy-samr-tests`, `monarchy-kerberos-tests` | **impacket** and **Samba** with credentials | every conformance script binds at `PKT_PRIVACY` |

`scripts/ci.sh --conformance` is the row-for-row proof of the RPC half: it
provisions a throwaway domain, starts the daemon on free ports, and drives DRSR,
LSAD, SAMR and Netlogon with impacket's own NDR. CI runs it on every push, and a second job builds the tree with
`MONARCHY_WITH_LDAP=ON` so the OpenLDAP configuration is compiled and its suites
run rather than assumed to work.

## 2. What to run when you touch this

Anything under `engine/` can change what a client sees on a port it does not
name, so the safe default is `scripts/ci.sh --conformance` and the table is for
when you want the narrow loop first.

| You changed | Suites to run | Plus |
|---|---|---|
| `Rpc.cpp`, `Ndr.cpp` | `monarchy-samr-tests` `monarchy-lsad-tests` `monarchy-drs-tests` `monarchy-epm-tests` | every conformance script — this is the shared marshaller |
| `Ntlm.cpp`, `Gss.cpp` | `monarchy-ntlm-tests` `monarchy-samr-tests` `monarchy-lsad-tests` | a conformance script with credentials |
| `LdapServer.cpp`, `LdapServer.h` | `monarchy-ldap-tests` `monarchy-tls-tests` `monarchy-backend-tests` `monarchy-provision-tests` | a bind/search probe on 1389 |
| `Kdc.cpp`, `Krb5.cpp`, `Aes.cpp` | `monarchy-kerberos-tests` `monarchy-kpasswd-tests` | `kinit` |
| `Samr.cpp` | `monarchy-samr-tests` `monarchy-netlogon-tests` | `samr-conformance.py` |
| `Lsad.cpp` | `monarchy-lsad-tests` | `lsad-conformance.py --skip-samba` |
| `Drs.cpp`, `DrsClient.cpp`, `ReplicationAgent.cpp` | `monarchy-drs-tests` `monarchy-drsclient-tests` `monarchy-replication-tests` | `drs-conformance.py` |
| `Netlogon.cpp` | `monarchy-netlogon-tests` `monarchy-logonhours-tests` `monarchy-workstation-tests` | `netlogon-conformance.py` |
| `Epm.cpp` | `monarchy-epm-tests` | `hept_lookup` — a tower naming a dead port is the failure this catches |
| `DnsServer.cpp` | `monarchy-dns-tests` | `scripts/check-dc-health.sh` |
| `Smb1.cpp`, `Smb2.cpp` | `monarchy-smb-tests` `monarchy-smb1-tests` | `smbclient -m NT1` |
| `Provisioner.cpp` | `monarchy-provision-tests` | **full** `ci.sh --conformance`: it seeds the tree every other suite starts from |
| `DcService.cpp` | `monarchy-dcservice-tests`, full `ci.sh --conformance` | `check-dc-health.sh` |
| `ui/src/mainwindow.cpp`, `mainwindow.h` | `monarchy-mainwindow-tests` `monarchy-ui-tests` `monarchy-backend-tests` | full `ci.sh` — it is what listens on every port |
| `CMakeLists.txt`, `ui/CMakeLists.txt` | — | `ci.sh --with-ldap` as well |

A suite that passes while its independent client fails is the signal this table
exists to produce: it means the tree and the wire agree with each other and not
with MS-SAMR, MS-LSAD, MS-DRSR, MS-NRPC or RFC 4511.

## 3. Proving a running DC

```sh
# throwaway domain on the unprivileged ports
build/ui/monarchy-provision --realm T.EXAMPLE --domain T --adminpass '…' \
    --targetdir /tmp/dc --dev-ports
build/ui/monarchy-dcd --dcdir /tmp/dc &

scripts/check-dc-health.sh /tmp/dc     # every declared port + every SRV locator
scripts/drs-conformance.py      --host 127.0.0.1 --port 1038 --basedn … --user Administrator --password …
scripts/lsad-conformance.py     --host 127.0.0.1 --port 1036 --domain-sid … --skip-samba …
scripts/samr-conformance.py     --host 127.0.0.1 --port 1035 --user Administrator --password …
scripts/netlogon-conformance.py --host 127.0.0.1 --port 1037 --samr-port 1035 --user Administrator --password …
```

Every script exits non-zero on any failed check, so they are usable as a gate.
`check-dc-health.sh` is the one that catches a locator pointing at a port that
did not bind — the failure mode a client reports as "the DC is down" while the
DC believes it started.

## 4. Known gaps in this matrix

These are places where a change can pass everything and still be wrong. They are
recorded, not hidden:

- **G4 — SMB has no independent client in CI.** The suites are self-contained;
  `smbclient` and impacket over `ncacn_np` are live-only, so a byte that only
  this tree's SMB encoder accepts would pass.
- **G6 — the LDAP path has no live external client in CI.** `ldap3` is a
  development convenience on one box, not a stage in `ci.sh`.
- **G7 — `check-dc-health.sh` needs an install,** so CI runs the suites and the
  conformance scripts but never the health check.

Four of the original seven are closed; their entries stay here so a reference
in #7 still resolves:

- **G1 — closed.** `scripts/ci.sh --sanitize` configures a Debug build with
  AddressSanitizer and UndefinedBehaviorSanitizer, halts on a UBSan diagnostic
  instead of printing one and exiting 0, and the `sanitizers` CI job runs it. It
  found nothing to fix on the tree it landed on, and it has one limit worth
  knowing: the compiler does not instrument a left shift whose result fits the
  unsigned type, which C++11 defines, so the wider-than-four-byte BER INTEGER
  behind #9 stays undefined while this job stays green. That one is pinned by
  the code and the message-id test, not by the sanitizer.

- **G2 — closed.** `MONARCHY_WITH_LDAP=ON` is the `openldap-backend` CI job,
  which installs `libldap2-dev` and runs `scripts/ci.sh --with-ldap`; the
  configure check now names the package instead of a library that is present.
- **G3 — closed.** `monarchy-dcservice-tests` provisions a domain, moves only the
  ports another process already holds, and asserts that a TCP connection to every
  port `dc.conf` still declares is accepted. A port the daemon cannot take must
  be reported, so a locator is never derived from a listener that failed.

- **G5 — closed.** `scripts/check-dc-health.sh` walks `kpasswdPort` with the ten
  ports beside it, taking 464 as the default because that is the port a client
  falls back to when the zone publishes no `_kpasswd` record at all
  (`krb5 1.22.2 src/lib/krb5/os/locate_kdc.c`, `locate_service_kpasswd`). On one
  tree, same daemon, only `dc.conf` changed to name a port with nothing behind
  it, the check reported 24 checks with one failing where the previous version
  reported 23 passing. It does not make the SRV section stronger: that section
  still fails only on a record pointing at a dead port, never on a missing one,
  and the new probe is TCP-only, so a DC answering kpasswd over UDP alone is a
  false FAIL rather than a pass.

## 5. Parity between two working copies

`scripts/parity-report.sh` prints the commit, the tracked changes, the suite
names and the built binaries in a diffable form; `--dcdir` adds the installed
domain's ports and the health verdict.

```sh
diff <(scripts/parity-report.sh) <(ssh box-b 'cd monarchy && scripts/parity-report.sh')
```

Both boxes pass on their own tree, so a difference in HEAD is invisible to the
suites and is exactly what this reports. The rule that goes with it: a claim in
an issue thread includes the report, and a box does not act on a thread it has
not re-read at the head the report shows.
