# Monarchy — Licensing & Patent Citation Index

## Every source needed to answer "can we build this without legal problems?"

> **Purpose.** A single, verified index of the licensing, patent, copyright and trademark sources that govern a
> clean-room / Samba-derived reimplementation of **Windows 2000/2003-era Active Directory** on Linux.
> Companion to [`AD-1TO1-CONFORMANCE.md`](AD-1TO1-CONFORMANCE.md) **§7** (which states the conclusions this index cites).
> Source provenance — which project or specification each module is derived from — is catalogued in
> [`CREDITS-INDEX.md`](CREDITS-INDEX.md).
>
> **Not legal advice.** This is a research index of primary documents. It records what Microsoft *says* in its own
> published covenants, plus the standards, case law and precedent that bear on the question. For a commercial
> product, counsel must check the Patent & Program Map against the exact specifications implemented.

**All URLs in this document were verified live on 2026-10-19** (HTTP 200, follow-redirects enabled).
A few are valid-but-bot-blocked to `curl` — `403` (`*.justia.com`, `worldwide.espacenet.com`, `caselaw.findlaw.com`)
or a `202` challenge (`eur-lex.europa.eu`, `courtlistener.com`). Open those in a browser.

**How to read the tiers:** the whole question collapses to three patent tiers plus two non-patent issues.

| Tier | What it covers | Patent position |
|---|---|---|
| **Tier 1** | Standards-based core (Kerberos, LDAP, DNS, SPNEGO, SASL, PKINIT, NetBIOS, CIFS) + a few MS extensions | **Royalty-free, irrevocable** — covered by the Open Specification Promise (OSP) |
| **Tier 2** | MS-proprietary AD protocols (ADTS, DRSR, SAMR, NRPC, LSAD, SFU, GPOL, FRS, schema…) | Docs free under the Interoperability Principles; patents **RAND/low-royalty**, *and* an **irrevocable no-assert pledge for open-source development + non-commercial distribution** |
| **Tier 3** | Patent term | Windows 2000/2003-era patents were filed ~1996–2003 → **expired ~2016–2023** |
| **N1** | **Trademarks / naming** | Real constraint: no "Active Directory", no Microsoft marks/logos |
| **N2** | **Your own source licence** | Samba-derived ⇒ **GPL-3.0** (self-imposed, not Microsoft's) |

---

## 1. Microsoft's IPR framework — primary sources

| Key | Instrument | What it does | URL |
|---|---|---|---|
| `[MS-OPENSPEC]` | Open Specifications — home | Index of all MS-*\* spec documents (protocols, formats, standards) | https://learn.microsoft.com/en-us/openspecs/main/ms-openspeclp/3589baea-5b22-48f2-9d43-f5bea4960ddb |
| `[MS-OSP]` | **Open Specification Promise** | *Irrevocable promise not to assert Necessary Claims* for implementations conforming to a **listed** Covered Specification. Covers **commercial and open source**, full or partial. Rev. 2023-02-24. | https://learn.microsoft.com/en-us/openspecs/dev_center/ms-devcentlp/1c24c7c8-28b0-4ce1-a47d-95fe1ff504bc |
| `[MS-CP]` | **Microsoft Community Promise** | Same shape as the OSP, for a *different* (mostly standards/DNSSEC/OCSP) list. Rev. 2023-01-31. | https://learn.microsoft.com/en-us/openspecs/dev_center/ms-devcentlp/8b8d1b7a-a10a-4667-9558-6d9c43adf60d |
| `[MS-IPP]` | **Interoperability Principles Program** (Feb 21 2008) | The program under which the *Windows Server* protocols (MS-ADTS, MS-DRSR, …) are published. Contains the **RAND** commitment and the **OSS patent pledge**. | https://learn.microsoft.com/en-us/openspecs/dev_center/ms-devcentlp/d84cac00-b312-44ee-9156-23bde6477c3d |
| `[MS-PLEDGE]` | **Interoperability Principles Patent Pledge for Open Source Developers** | Irrevocable no-assert promise for **OSS development + non-commercial distribution** of the Interoperability-Principles protocols. *Excludes commercial distribution.* Text on the `[MS-IPP]` page. | (see `[MS-IPP]`) |
| `[MS-PATNOTE]` | Patent Promises and Patents | Hub page: points at the Patent & Program Map and the pledges. | https://learn.microsoft.com/en-us/openspecs/dev_center/ms-devcentlp/13571077-e344-4e6f-a477-369894979798 |
| `[MS-PATMAP]` | **Patent and Program Map** | The list of Microsoft patents/applications Microsoft claims cover each protocol, per license program. **Microsoft commits it will not assert patents on a protocol unless listed here.** | https://go.microsoft.com/fwlink/?LinkId=2220996 → resolves to `patmap-tool.html` |
| `[MS-PROGRAMS]` | Open Specifications — Programs | Index of the licensing programs. | https://learn.microsoft.com/en-us/openspecs/dev_center/ms-devcentlp/44355844-d37d-4ec6-bee1-6b6cda79f722 |
| `[MS-WSPP]` | **Workgroup Server Protocol Program (WSPP)** | The program under which the EU-mandated Windows workgroup-server protocol docs were licensed (the Samba/PFIF route). | https://learn.microsoft.com/en-us/openspecs/dev_center/ms-devcentlp/5f4fc8ba-f448-4b05-968e-df51c60eaef8 |
| `[MS-MIP]` | **Microsoft Interoperability Program (MIP)** | Successor umbrella for the protocol-licensing programs. | https://learn.microsoft.com/en-us/openspecs/dev_center/ms-devcentlp/a83d8d17-0cde-46df-a496-2686bff58d5d |
| `[MS-WINPROT]` | Windows Protocols — landing | TOC for all `MS-xxxx` Windows protocol specs. | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-winprotlp/ |
| `[MS-PR]` | Interoperability Principles — press release (2008-02-21) | Announcement + the four principles. | https://news.microsoft.com/2008/02/21/microsoft-makes-strategic-changes-in-technology-and-business-practices-to-expand-interoperability/ |

### 1.1 The OSP promise (verbatim, `[MS-OSP]`)

> "Microsoft irrevocably promises not to assert any Microsoft Necessary Claims against you for making, using,
> selling, offering for sale, importing or distributing any implementation to the extent it conforms to a Covered
> Specification ("Covered Implementation") …"
>
> "'Microsoft Necessary Claims' are those claims of Microsoft-owned or Microsoft-controlled patents that are
> necessary to implement only the required portions of the Covered Specification that are described in detail and
> not merely referenced in such Specification."

Key properties: **irrevocable**, **royalty-free**, **worldwide**, **transferable only with the implementation**,
applies to **commercial and open source**, and to **full or partial** implementations. It is a *covenant not to sue*,
not a licence. It lapses for a given specification only if you sue Microsoft over that same specification.

### 1.2 The Interoperability Principles commitments (verbatim, `[MS-IPP]`)

**RAND terms:**
> "Some of Microsoft Open Protocols are covered by patents … Microsoft will indicate on its website which protocols
> are covered by Microsoft patents and will license all these patents on reasonable and non-discriminatory terms, at
> low royalty rates."

**No-assertion unless listed:**
> "Microsoft will not assert patents on any Open Protocol unless those patents appear on that list [`[MS-PATMAP]`]."

**The OSS pledge (the important one for this project):**
> "Microsoft irrevocably promises not to assert any Microsoft Necessary Claims against you as an open source
> software developer ("You") for making, using, importing, or distributing any implementation of a Covered
> Specification ("Covered Implementation") … To benefit from this promise, You must be a natural or legal person
> participating in the creation of software code for an open source project. … **If You engage in the commercial
> distribution or importation of software derived from an open source project or if You make or use such software
> outside the scope of creating such software code, You do not benefit from this promise for such distribution or
> for these other activities.**"

"Covered Specifications" for the pledge = *"the protocols implemented in the current and future versions of Exchange
Server 2007, Office 2007, Office SharePoint Server 2007, SQL Server 2008, Windows Vista … **and Windows Server
2008**"* as published at Open Specifications. **AD DS is a Windows Server 2008 role**, so the `ADFamily` protocol
set falls inside that scope.

**Bottom line for an open-source Monarchy:** development **and non-commercial distribution** are covered by an
irrevocable no-assert promise for the entire Interoperability-Principles protocol set. **Commercial distribution is
the only gap** — there you rely on (a) `[MS-PATMAP]` showing no listed patent, (b) the RAND/low-royalty licence, or
(c) Tier 3 expiry.

---

## 2. The per-document IPR notice (what *every* `MS-xxxx` spec says)

Every Open Specification document carries the same "Intellectual Property Rights Notice". The load-bearing paragraph:

> **Patents.** "Microsoft has patents that might cover your implementations of the technologies described in the
> Open Specifications documentation. Neither this notice nor Microsoft's delivery of this documentation grants any
> licenses under those patents or any other Microsoft patents. **However, a given Open Specifications document might
> be covered by the Microsoft Open Specifications Promise or the Microsoft Community Promise.** If you would prefer
> a written license, or if the technologies described in this documentation are not covered by the Open
> Specifications Promise or Community Promise, as applicable, patent licenses are available by contacting
> iplg@microsoft.com."
>
> **License Programs.** "To see all of the protocols in scope under a specific license program and the associated
> patents, visit the Patent Map."

So the notice itself tells you to check **two** things per protocol: (i) is it on the OSP/CP list? (ii) what does the
Patent & Program Map list? See §3 and §4 below for the answers for the AD protocol family.

*Source (example instance):* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ (any section; notice is at the foot of the spec).

---

## 3. Tier 1 — OSP-covered specifications relevant to AD (royalty-free)

Extracted verbatim from the **Covered Specifications** list on `[MS-OSP]`. These are the standards-based spine of AD
plus the few Microsoft extensions Microsoft chose to put in the OSP.

| AD ingredient | OSP list entry | RFC / spec |
|---|---|---|
| Kerberos v5 core | "RFC 1510 and RFC 1964 - Kerberos Network Authentication Service (v5)" | [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) (current), RFC 1510 (orig), RFC 1964 (GSS mech) |
| Kerberos PKINIT (smart cards, 2000/2003) | "RFC 4556 - Public Key Cryptography for Initial Authentication in Kerberos (PKINIT)" | [RFC 4556](https://www.rfc-editor.org/rfc/rfc4556) |
| Kerberos password change | "RFC 3244 - Kerberos Change Password" | https://www.rfc-editor.org/rfc/rfc3244 |
| **PAC group membership** | "**Microsoft Kerberos Authentication Group Membership Extensions**" | MS extension (the group-membership part of the PAC) |
| LDAP v3 core | "RFC 2251 and RFC 2256 - Lightweight Directory Access Protocol (LDAP v3)" | [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511) (current) |
| SPNEGO | "RFC 2478 and RFC 4178 - Simple and Protected GSS-API Negotiation (SPNEGO)" | [RFC 4178](https://www.rfc-editor.org/rfc/rfc4178) |
| SASL | "RFC 2222 - Simple Authentication and Security Layer (SASL)" | https://www.rfc-editor.org/rfc/rfc2222 |
| GSS-API | RFC 2743 / 1964 (GSS-API + Kerberos mech) | https://www.rfc-editor.org/rfc/rfc2743 |
| DNS (AD-integrated) | "RFC 1034, RFC 1035, RFC 1995, RFC **2136**, RFC 2181, RFC **2782**, RFC 2845, RFC 2930 … - Domain Name System (DNS)" | see [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136) (dynamic update), [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782) (SRV) |
| **W32Time / time sync** | "**Microsoft Simple Network Time Protocol Extensions**" | MS extensions to SNTP |
| NetBIOS over TCP | "RFC 1001 and RFC 1002 - NetBIOS over TCP (NETBT)" | https://www.rfc-editor.org/rfc/rfc1001 |
| SMB1/CIFS (SYSVOL transport, legacy) | "Draft-leach-cifs-v1-spec-02 - Common Internet File System (CIFS)" | IETF draft |
| Directory-services RPC | "**Microsoft Remote X/Open Directory Services Remote Protocol**" | MS extension (directory RPC) |
| TDS | "[MS-TDS]: Tabular Data Stream Protocol" | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/ |

> **Note:** the OSP lists **RFC 1510/1964**, not RFC 4120. RFC 4120 obsoletes 1510; the OSP's subject matter is
> the Kerberos v5 protocol, which RFC 4120 restates. Treat the base mechanism as covered.

**Also in the OSP list, adjacent technologies:** TLS (RFC 2246), EAP, IPsec/IKE with GSS-API + Kerberos, PPP/PPPoE/
MPPE, SOCKS, WebDAV (RFC 4918), WS-Security Kerberos Token Profile, NAP SoH, Teredo, UPnP IGD, VT-UTF8.

---

## 4. Tier 2 — AD protocols *not* in the OSP (documented; RAND + OSS pledge)

These are the protocols that make AD *AD*. They are **not** OSP-covered; they are published under the
Interoperability Principles (`[MS-IPP]`), so they attract the RAND commitment, the OSS pledge, and the
"won't-assert-unless-on-the-map" rule — and, for the 2000/2003 era, **patent expiry** (§7).

All landing URLs below verified live. Pattern: `https://learn.microsoft.com/en-us/openspecs/windows_protocols/<short>/`

| Short | Protocol | AD role | URL |
|---|---|---|---|
| **MS-ADTS** | Active Directory Technical Specification | The core AD DS spec | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ |
| MS-ADOD | AD Protocols Overview | Inter-protocol map | …/ms-adod/ |
| **MS-DRSR** | Directory Replication Service (DRS) Remote Protocol | **Replication**, FSMO, RID pool | …/ms-drsr/ |
| MS-SRPL | Directory Replication Service (DRS) — Supplemental | Windows 2008+ replication addenda | …/ms-srpl/ |
| **MS-SAMR** | Security Account Manager (SAM) Remote Protocol | User/group/account mgmt | …/ms-samr/ |
| **MS-LSAD** | Local Security Authority (Domain Policy) Remote Protocol | Domain/trust policy | …/ms-lsad/ |
| MS-LSAT | Local Security Authority (Translation Methods) Remote Protocol | SID↔name translation | …/ms-lsat/ |
| **MS-NRPC** | Netlogon Remote Protocol | Secure channel, DC locator, trust authn | …/ms-nrpc/ |
| MS-KILE | Kerberos Protocol Extensions | AD Kerberos behaviours | …/ms-kile/ |
| MS-PAC | Privilege Attribute Certificate Data Structure | PAC internals | …/ms-pac/ |
| **MS-SFU** | Kerberos S4U (Service for User) extensions | Protocol transition, 2003 feature | …/ms-sfu/ |
| MS-ADSC | AD Schema Classes | Schema objects | …/ms-adsc/ |
| MS-ADA1 | AD Schema Attributes (A–L) | Schema attributes | …/ms-ada1/ |
| MS-ADA2 | AD Schema Attributes (M–Z) | Schema attributes | …/ms-ada2/ |
| MS-ADA3 | AD Schema Attributes — supplemental | Schema attributes | …/ms-ada3/ |
| MS-ADLS | AD Lightweight Directory Services Schema | AD LDS / ADAM | …/ms-adls/ |
| MS-GPOL | Group Policy: Core Protocol | GPO download/apply | …/ms-gpol/ |
| MS-GPOD | Group Policy: Data Structures | GPO file formats | …/ms-gpod/ |
| MS-FRS1 | File Replication Service Protocol | SYSVOL (legacy FRS) | …/ms-frs1/ |
| MS-FRS2 | Distributed File System Replication Protocol | DFS-R SYSVOL | …/ms-frs2/ |
| MS-DFSC | Distributed File System (DFS): Referral Protocol | DFS | …/ms-dfsc/ |
| MS-DFSNM | DFS: Namespace Management | DFS admin | …/ms-dfsnm/ |
| MS-DSSP | Directory Services Setup Remote Protocol | dcpromo / DC promotion | …/ms-dssp/ |
| MS-W32T | Windows Time Service Remote Protocol | W32Time RPC | …/ms-w32t/ |
| MS-NLMP | NT LAN Manager (NTLM) Authentication Protocol | NTLM | …/ms-nlmp/ |
| MS-KKDCP | Kerberos KDC Proxy Protocol | KKDCP (G13) | …/ms-kkdcp/ |
| MS-RPCE | Remote Procedure Call Protocol Extensions | DCE/RPC transport | …/ms-rpce/ |
| MS-SRVS | Server Service Remote Protocol | Net share enum (SYSVOL) | …/ms-srvs/ |
| MS-SMB2 | Server Message Block (SMB) Protocol v2/v3 | SYSVOL transport | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ |
| MS-SPNG | Simple and Protected GSS-API Negotiation Mechanism | SPNEGO (MS view) | …/ms-spng/ |

> **Per-protocol patent status:** must be read from `[MS-PATMAP]` (an interactive export; not citable per-row here).
> The operative Microsoft commitment is `[MS-IPP]`: patents are asserted **only** for protocols listed there.

---

## 5. Per-feature citation map — **Windows 2000 / 2003 AD**

| Classic feature | Spec | Tier | Typical position |
|---|---|---|---|
| Kerberos v5 logon, interop with MIT/Heimdal | RFC 4120 + MS-KILE | 1 (+2) | royalty-free; MS extensions RAND/pledge |
| PAC (groups, SIDs, logon info) | MS-PAC; group-membership part in OSP | 1/2 | base royalty-free, full **PAC** Tier 2 |
| NTLM fallback | MS-NLMP | 2 | RAND/pledge; expired |
| LDAP v3 queries/modify | RFC 4511 | 1 | royalty-free |
| AD LDAP controls/dialects | MS-ADTS | 2 | RAND/pledge; expired |
| Multi-master replication, USN, up-to-dateness, conflict resolution | MS-DRSR + MS-ADTS | 2 | RAND/pledge; **expired** |
| FSMO roles | MS-DRSR + MS-ADTS | 2 | expired |
| Netlogon secure channel, DC locator, machine accounts | MS-NRPC | 2 | expired |
| User/group/account management | MS-SAMR | 2 | expired |
| Domain/trust policy, password policy, lockout | MS-LSAD / MS-LSAT | 2 | expired |
| Trusts (incl. 2003 forest trusts) | MS-LSAD + MS-NRPC | 2 | expired |
| S4U2Self / S4U2Proxy (2003) | MS-SFU | 2 | expired |
| Group Policy (GPO storage + application) | MS-GPOL / MS-GPOD | 2 | expired |
| SYSVOL replication (FRS, 2000/2003) | MS-FRS1 | 2 | expired |
| AD-integrated DNS (dynamic update, SRV) | RFC 2136 / RFC 2782 | 1 | royalty-free |
| W32Time / time hierarchy | MS SNTP extensions (OSP) + MS-W32T | 1/2 | base royalty-free; RPC part Tier 2 |
| Schema (classes + attributes) | MS-ADSC / MS-ADA1-3 | 2 | expired |
| AD LDS / ADAM (2003) | MS-ADLS + LDAP | 2/1 | expires/RAND |
| GSS-API / SPNEGO / SASL negotiation | RFC 2743/4178/2222 | 1 | royalty-free |
| SMB / CIFS SYSVOL access | CIFS (OSP) + MS-SMB2 | 1/2 | CIFS royalty-free; SMB2 Tier 2 |

**Verdict:** *every* classic-AD feature is implementable. Tier-1 pieces need nothing; Tier-2 pieces are covered for
OSS development/non-commercial distribution by `[MS-PLEDGE]`, and their patents are (mostly) expired (§7).

---

## 6. Precedent — it has already been done, at scale, for 20+ years

| Key | Item | Relevance | URL |
|---|---|---|---|
| `[PFIF]` | Samba Team / **Protocol Freedom Information Foundation** page | How Samba got the Windows workgroup-server protocol docs: PFIF signed with Microsoft, **Dec 20 2007**, for a one-time €10,000, under the EU antitrust remedy. Docs under NDA; **implementations publishable under GPLv2/v3 with no per-copy royalties and no admission of infringement.** | https://www.samba.org/samba/PFIF/ |
| `[PFIF-AG]` | The PFIF/Microsoft agreement (PDF) | "Work Group Server Protocol Program License Agreement **(No Patents)**" | https://www.samba.org/samba/PFIF/PFIF_agreement.pdf |
| `[SFLC]` | SFLC analysis: OSP & the GPL | Whether the OSP covenant is compatible with GPL-licensed implementations | https://softwarefreedom.org/resources/2008/osp-gpl.html |
| `[EU]` | **European Commission Decision 2007/53/EC**, 24 March 2004 (Case COMP/C-3/37.792 — *Microsoft*) | Ordered Microsoft to disclose the interoperability information; basis of PFIF/WSPP. CELEX 32007D0053, OJ L 32, 6.2.2007, p. 23. | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32007D0053 |
| `[MS-PR]` | Microsoft Interoperability Principles press release, 2008-02-21 | The shift that produced `[MS-IPP]` | (see §1) |
| Independent AD-protocol implementations in production | Samba AD DC (GPLv3+), Heimdal, MIT krb5, FreeIPA, 389-ds, Shishi, nss_ldap/SSSD | None required a Microsoft patent licence; none has been sued over AD reimplementation | — |

> **Note on PFIF's patent scope:** the agreement clarified *which* patent numbers Microsoft believes are relevant,
> **without granting an implicit patent licence** — and required **no per-copy royalty** and **no acknowledgement of
> infringement** by Free Software implementations. Samba has shipped a full AD DC on that basis ever since.

---

## 7. Patent term & expiry — decisive for a 2000/2003 target

| Key | Rule / resource | Notes | URL |
|---|---|---|---|
| `[USPTO-TERM]` | 35 U.S.C. §154(a)(2) | US utility-patent term = **20 years from the earliest effective non-provisional filing** (+ possible adjustment/extension) | https://www.uspto.gov/ |
| `[PATMAP]` | Patent & Program Map | Which protocols Microsoft says are patented | (see §1) |
| `[USPTO-SEARCH]` | USPTO Patent Public Search | Search by assignee/date | https://ppubs.uspto.gov/pubwebapp/ |
| `[GOOGLEPAT]` | Google Patents | Full-text + family + expiry estimation | https://patents.google.com/ |
| `[ESPACENET]` | EPO Espacenet | Worldwide families | https://worldwide.espacenet.com/ |

**Expiry argument (heuristic, not per-claim legal analysis):** Windows 2000 AD was designed and filed ~1996–2000 →
those US patents expired ~**2016–2020**. Windows Server 2003 features (forest trusts, S4U, LVR, lastLogonTimestamp,
ADAM, AD FS 1.0) were filed ~2000–2003 → expired ~**2020–2023**. Therefore the **classic 2000/2003 AD feature set
is, by 2026, largely patent-expired independent of any Microsoft pledge**. Live-claim risk concentrates in
post-2012 features (FL 2012+ Dynamic Access Control, 2016 PAM, 2025 LAPS) — outside the classic scope.

*Caveats:* continuations/divisionals can extend the effective term; some families have later-filed members; and
patents differ by jurisdiction. Spot-check the specific mechanism on `[PATMAP]`/`[GOOGLEPAT]` if a commercial
release matters.

---

## 8. Copyright & interoperability — case law that permits clean-room reimplementation

| Key | Case | Holding relevant here | Citation |
|---|---|---|---|
| `[GO]` | **Google LLC v. Oracle America, Inc.**, 593 U.S. 1 (2021) | Reimplementing a functional API is fair use; declaring code functional | https://supreme.justia.com/cases/federal/us/593/19-956/ |
| `[SEGA]` | Sega Enterprises Ltd. v. Accolade, Inc., 977 F.2d 1510 (9th Cir. 1992) | Intermediate copying for interoperability = fair use | — |
| `[CONNECTIX]` | Sony Computer Entertainment, Inc. v. Connectix Corp., 203 F.3d 596 (9th Cir. 2000) | Reverse-engineering for a compatible product = fair use | — |
| `[LOTUS]` | Lotus Dev. Corp. v. Borland Int'l, Inc., 49 F.3d 807 (1st Cir. 1995), aff'd 516 U.S. 233 (1996) | Menu/interface methods of operation not copyrightable | — |
| `[SAS]` | SAS Institute Inc. v. World Programming Ltd., C-406/10 (CJEU, 2 May 2012) | EU: functionality, language and data formats not protected by copyright | https://curia.europa.eu/ |

**Practical consequence:** the AD *protocols, schema and observable behaviour* are functional and thus outside
copyright. The **only** copyright exposure is copying Microsoft **source code** — which Monarchy never has. Maintain
clean-room discipline (no Windows binaries/headers as a source; spec-and-test-derived only).

---

## 9. Trademarks — the one *hard* constraint

| Key | Item | URL |
|---|---|---|
| `[MS-TM]` | Microsoft Trademarks (list) | https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks |
| `[MS-TMGUIDE]` | Microsoft Trademark & Brand Guidelines | https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general |

**Constraint:** cannot use **"Active Directory"**, "Windows", "Windows Server", "Microsoft", their logos, or the
MMC `*.msc` snap-in names/marks in a way suggesting origin/endorsement. **This affects naming and branding only —
it blocks no feature and no protocol.**

---

## 10. Defensive patent pools (secondary, for a commercial release)

| Key | Item | Note | URL |
|---|---|---|---|
| `[OIN]` | Open Invention Network | Defensive patent pool; royalty-free cross-licence to members for the "Linux System" | https://www.openinventionnetwork.com/ |
| `[OIN-MS]` | Microsoft joined OIN (Oct 2018) | Membership cross-licenses member patents, incl. Microsoft's, to OIN members for the Linux System | (OIN newsroom) |

**Caveat:** OIN's licence runs to OIN members and applies to the defined **"Linux System"** package set (Samba is
normally treated as part of that set — *verify the current definition* before relying on it). OIN is a supplement,
not a substitute for the `[MS-OSP]`/`[MS-PLEDGE]` position.

---

## 11. Self-imposed: the Samba GPL-3.0 chain

| Key | Item | URL |
|---|---|---|
| `[SAMBA-LIC]` | Samba licensing (GPLv3+ for the AD DC) | https://www.samba.org/samba/docs/GPL.html |
| `[GPL3]` | GNU GPL v3 | https://www.gnu.org/licenses/gpl-3.0.html |

**Consequence:** v1 of Monarchy (§0 of the conformance doc) recommends restructuring Samba ⇒ the result is
**GPL-3.0**. That is a *self-imposed* obligation, orthogonal to Microsoft. A permissive/closed product is possible
only as a **subset** that avoids Samba code (and then the Tier-2 commercial-distribution question in §1.2 becomes
live).

---

## 12. Citation keys used in `AD-1TO1-CONFORMANCE.md` §7

`[MS-OSP]` · `[MS-CP]` · `[MS-IPP]` · `[MS-PLEDGE]` · `[MS-PATMAP]` · `[MS-PATNOTE]` · `[PFIF]` · `[EU]` ·
`[USPTO-TERM]` · `[MS-TM]` · `[SAMBA-LIC]` · `[APPLE-MS]` · `[LOTUS]` · `[BSA]` · `[SAS]` · `[ALICE]` · `[WALMART]` ·
`[TRAFIX]` · `[DESIGN171]` · `[EU-DESIGN]` · `[MDY]` · `[BRODERBUND]` · `[KP-PERM]` · `[SALINGER]` · `[ROTTLUND]` ·
`[EFJ]` · `[ALFA8]` · `[TC-HEARTLAND]` · `[GO]`

---

## 13. User interface — a 1:1 look without copying expression

**Question.** Can Monarchy reproduce the **1:1 look of the Microsoft Management Console (MMC)** — console tree, results
pane, standard toolbar, tabbed property sheets, the classic ADUC/ADSS/ADDT/Schema/GPMC/DNS snap-ins — without IP problems?

**Answer: yes.** Copyright, design patents and trademarks each touch the UI, but each protects something different,
and the elements that make a console *read* as MMC are either the **generic Win32 common-controls idiom** or supplied
by **your own toolkit**. The only Microsoft-owned thing in the picture is the **artwork** (icons / bitmaps / custom
illustrations) — which Monarchy replaces anyway.

### 13.1 Copying expression vs. implementing an idiom

| Copying expression — **do not** | Implementing the idiom — **fine** |
|---|---|
| Extracting MS `.ico`/bitmap resources from `dsa.dll`, `mmc.exe`, `%SystemRoot%\system32\…` | Drawing your own icons, or using an existing open icon set |
| Tracing a toolbar glyph or a dialog's custom art pixel-for-pixel | Using generic glyph shapes (back/forward, up-level, refresh) from any set |
| Shipping or redistributing a Microsoft **screenshot** as an asset (splash art, in-product help, docs art) | Building the same screen with your own toolkit at the same sizes/positions |
| Using MS product names / logos / "Active Directory" | Naming your own product and your own `.msc` files |

Two windows that **look identical because both implement the same standard idiom** are not a copy — that is the
**idea/expression** line plus **scènes à faire** (elements that necessarily follow from the function are unprotectable).

### 13.2 Element-by-element status of "the MMC look"

| Element | Protectable? | Notes |
|---|---|---|
| Console tree + results pane + splitter + standard toolbar + menu + status bar + column headers | **No** | Win32 common-controls idiom, used by thousands of unrelated products; functional |
| Window chrome, control rendering, scrollbars, tabbed property sheets | **Not Microsoft's** | Comes from the toolkit/theme you choose (Qt/GTK) |
| Fonts (Tahoma ~2000-era, Segoe UI later) | **No** | The *look* isn't protected. Use metric-compatible **OFL** fonts — e.g. **Selawik** (Segoe UI-metric, Microsoft-authored, OFL) |
| Icons / toolbar glyphs / custom illustrations | **Yes — copyright** | The one element to replace. The *metaphors* (person = user, two people = group, monitor = computer) are unprotectable ideas |
| The layout *as a compilation* | Thin at most | Where all elements are functional/unprotectable the aggregate is unprotected (merger); trade dress needs distinctiveness **and** non-functionality |
| Design patents on the classic console | **Expired / inapplicable** | 2000-era filings expired ~2011–2018 (15-yr term); functional layouts are not "ornamental" and fail §171 subject matter |

### 13.3 Authority

| Key | Authority | Point | Source |
|---|---|---|---|
| `[APPLE-MS]` | Apple Computer, Inc. v. Microsoft Corp., 35 F.3d 1435 (9th Cir. 1994) | Apple "cannot get patent-like protection for the idea of a graphical user interface, or the idea of a desktop metaphor." Broad GUI look-and-feel copyright claims fail. | https://law.resource.org/pub/us/case/reporter/F3/035/35.F3d.1435.93-16883.93-16869.93-16867.html |
| `[BRODERBUND]` | Broderbund Software, Inc. v. Unison World, Inc., 648 F. Supp. 2d 1127 (N.D. Cal. 1986) | The 9th Circuit's strongest **UI-copying** authority: **menu screens and user interfaces are copyrightable audio-visual works** where there is "stylistic creativity" beyond the utilitarian. A plaintiff would cite this to claim an MMC console's look — but it protects *creative* UI, not a functional layout, and it is a district court decision. | https://law.justia.com/cases/federal/district-courts/FSupp/648/1127/1431057/ |
| `[LOTUS]` | Lotus Dev. Corp. v. Borland Int'l, 49 F.3d 807 (1st Cir. 1995), aff'd 516 U.S. 233 (1996) | A menu command hierarchy is an uncopyrightable "method of operation". | https://www.law.cornell.edu/supremecourt/text/516/233 |

> **Forum note.** `[APPLE-MS]` and `[BRODERBUND]` are **Ninth Circuit** authorities — the circuit a plaintiff would most want. `[LOTUS]` (1st Cir.) and `[ALICE]`/`[WALMART]`/`[TRAFIX]` (SCOTUS) are national law. For a St. Louis operator, only the SCOTUS line and the **Eighth Circuit** framework (§14.3) bind; the 9th Cir. cases are **persuasive only**. See **§14.4**.
| `[BSA]` | CJEU **C-393/09**, *Bezpečnostní softwarová asociace* (22 Dec 2010) | A GUI is **not** protectable as a *computer program*, but **may** be a copyright *work* if it is the author's own intellectual creation. | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62009CJ0393 |
| `[SAS]` | CJEU **C-406/10**, *SAS Institute v. World Programming* (2 May 2012) | Functionality, programming language and file formats are not protected by copyright. | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62010CJ0406 |
| `[ALICE]` | Alice Corp. v. CLS Bank Int'l, 573 U.S. 208 (2014) | Abstract software/UI-method claims frequently invalid — narrows utility-patent risk for interaction techniques. | https://www.law.cornell.edu/supremecourt/text/13-298 |
| `[WALMART]` | Wal-Mart Stores v. Samara Bros., 529 U.S. 205 (2000) | Product design is protectable as trade dress only with **secondary meaning**. | https://www.law.cornell.edu/supremecourt/text/529/205 |
| `[TRAFIX]` | TrafFix Devices v. Marketing Displays, 532 U.S. 23 (2001) | **Functionality** bars trade-dress protection — a functional console layout is out. | https://www.law.cornell.edu/supremecourt/text/532/23 |
| `[DESIGN171]` | 35 U.S.C. §171 + USPTO *Supplemental Guidance* (17 Nov 2023) | GUIs/icons **are** protectable as **design patents** (surface ornamentation embodied in a screen) — but only the exact ornamental design, excluding function; 15-year term. | https://www.law.cornell.edu/uscode/text/35/171 · https://www.federalregister.gov/documents/2023/11/17/2023-25473/supplemental-guidance-for-examination-of-design-patent-applications-related-to-computer-generated |
| `[EU-DESIGN]` | Council Reg. (EC) No 6/2002, Art. 8 | Community design protection can cover a GUI's appearance, but features **solely dictated by function** are excluded. | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32002R0006 |

> **Binding where?** *Lotus* (1st Cir.) and *Apple v. Microsoft* (9th Cir.) are **persuasive only** — no circuit binds another. *Lotus* is not even a Supreme Court holding: it was affirmed by an **equally divided** Court (516 U.S. 233), so it is the First Circuit's rule, widely followed but not national law. What actually binds a given operator depends on the circuit — see **§14** for the Eighth Circuit (St. Louis) position.

### 13.4 What a 1:1 open MMC is built from (all legally clean)

1. **Console host** (`ad-mmc`) — `.msc` loader, console tree, results pane, standard toolbar, status bar, snap-in
   registration. The MMC/snap-in model and the `.msc` format are documented and functional: reimplement freely.
2. **Toolkit style** — Qt is the shortest path: `QTreeWidget`/`QTableView` + a Windows-like `QStyle`/QSS
   (`[QT]` — https://doc.qt.io/qt-6/qstyle.html, https://doc.qt.io/qt-6/stylesheet-reference.html), or GTK + a
   Windows theme. You supply the pixels.
3. **Icons** — your own set, or an open theme with the right shape language (`[ICONS]` — Adwaita CC0/LGPL,
   https://gitlab.gnome.org/GNOME/adwaita-icon-theme · Breeze LGPL, https://invent.kde.org/frameworks/breeze-icons).
4. **Snap-ins** (`ad-snapins`) — ADUC / ADSS / ADDT / Schema / GPMC / DNS rebuilt over the Monarchy backend.
5. **Fonts** — metric-compatible OFL families (`[SELAWIK]` — https://github.com/microsoft/Selawik).

> **Rules for [`AD-CONSOLE-IMAGE-INDEX.md`](AD-CONSOLE-IMAGE-INDEX.md):** the indexed Microsoft screenshots are
> **reference only** — study the layout and workflows; do **not** ship them as assets, and do **not** trace the artwork.

---

## 14. Venue, forum & what actually binds (E.D. Mo. / Eighth Circuit)

**Operator location:** St. Louis, Missouri. This section records *which court's law governs* Monarchy — because
"a court held X" is meaningless without knowing whether that court binds you.

### 14.1 The binding hierarchy

| Court | Binds Monarchy? | Where |
|---|---|---|
| **Supreme Court** | **Yes** — nationwide, on federal law | — |
| **Court of Appeals for the Federal Circuit** | **Yes — nationwide on patents** (incl. design patents, 35 U.S.C. §171) | 28 U.S.C. §1295 |
| **Court of Appeals for the Eighth Circuit** | **Yes** — within the circuit: Missouri, Arkansas, Iowa, Minnesota, Nebraska, N. & S. Dakota. *Courthouse: St. Louis.* | https://www.ca8.uscourts.gov/ |
| **U.S. District Court, Eastern District of Missouri (E.D. Mo.)** | The trial court for St. Louis | https://www.moed.uscourts.gov/ |
| Other circuits (2d, 9th, 1st…), incl. *Lotus*/*Apple v. Microsoft* | **Persuasive only** | — |
| Other district courts | **Persuasive only** — not binding even within the same district | — |

> **Horizontal precedent does not exist in the federal system.** A district court does not bind another district
> court — not across districts, and not within the same district. Only **vertical** precedent (higher → lower) binds.

### 14.2 Consequence per question

| Question | Governing law | Practical effect for Monarchy |
|---|---|---|
| Design patents / utility patents | **Federal Circuit — nationwide** | **Location is irrelevant**; §171/GUI law is the same in St. Louis as anywhere |
| Copyright (GUI "look and feel") | **Eighth Circuit** | *Lotus* (1st Cir.) and *Apple v. Microsoft* (9th Cir.) are **persuasive only** |
| Trade dress | **Eighth Circuit** | Requires **secondary meaning** for product design; a generic console layout also fails the **functionality** bar regardless |
| Trademarks / naming | Eighth Circuit | Own name/logo (§9) |

### 14.3 The Eighth Circuit's copyright framework (what actually binds)

| Key | Authority | Point | Source |
|---|---|---|---|
| `[ROTTLUND]` | Rottlund Co. v. Pinnacle Corp., 452 F.3d 726 (8th Cir. 2006) | The Eighth Circuit uses the **extrinsic/intrinsic** substantial-similarity test, and **disfavours dissection/filtering** of a work into unprotected elements at the intrinsic stage — i.e. it does **not** apply the 2nd Circuit's abstraction-filtration-comparison test the same way. | https://law.justia.com/cases/federal/appellate-courts/F3/452/726/587348/ |
| `[EFJ]` | E.F. Johnson Co. v. Uniden Corp. of Am., 623 F. Supp. 1485 (D. Minn. 1985) | The notable **software**-copyright decision from within the Eighth Circuit: an "iterative" test for substantial similarity of computer programs. **District court — persuasive, not binding.** | https://law.justia.com/cases/federal/district-courts/FSupp/623/1485/1514007/ |
| `[ALFA8]` | ALFA International — *Trade Dress: 8th Circuit* compendium | Product-design trade dress in the Eighth Circuit requires **secondary meaning** (consumer recognition of source). | https://www.alfainternational.com/compendium/business-litigation-2/business-litigation-trade-marks-trade-dress/8th-circuit/ |

> **Honest gap — recorded deliberately.** As of 2026 the **Eighth Circuit has no landmark appellate decision on GUI /
> software "look and feel" copyright**. The in-circuit software authority is a **1985 district-court** decision, so
> the §13.3 cases remain **persuasive** here, not binding. That weakens nothing for Monarchy — the elements in play are
> functional — but nobody should tell you "the Eighth Circuit follows *Lotus*."

### 14.4 The Ninth Circuit — the forum a plaintiff would want

The observation behind this section is accurate for copyright and trade dress, and **wrong for patents** — and the
distinction is exactly why §14.1 separates the two.

#### 14.4.1 Why the Ninth Circuit is the forum a plaintiff wants

| Key | Authority | Why a plaintiff would cite it | Source |
|---|---|---|---|
| `[MDY]` | MDY Industries, LLC v. Blizzard Entertainment, Inc., 629 F.3d 928 (9th Cir. 2010) | The flagship 9th Cir. software case. Held that **copying Blizzard's expressive code to interoperate** (Gliders/bots) was infringement, and that the **anti-reverse-engineering EULA bound MDY's users**. Hostile to "interoperability"/"clean-room" framing; broadly pro-rightsholder on software scope. | https://cdn.ca9.uscourts.gov/datastore/opinions/2011/02/17/09-15932.pdf |
| `[APPLE-MS]` | Apple Computer, Inc. v. Microsoft Corp., 35 F.3d 1435 (9th Cir. 1994) | The 9th Cir. granted Apple **partial "look and feel" relief** — the circuit most willing to credit a GUI "look and feel" theory (the "virtual identity" test). | https://law.resource.org/pub/us/case/reporter/F3/035/35.F3d.1435.93-16883.93-16869.93-16867.html |
| `[BRODERBUND]` | Broderbund Software, Inc. v. Unison World, Inc., 648 F. Supp. 2d 1127 (N.D. Cal. 1986) | The strongest **UI-copying** authority in the 9th Circuit: held that **menu screens and user interfaces are copyrightable audio-visual works** where there is "stylistic creativity" beyond the utilitarian. The case a plaintiff would cite to claim an MMC console's look. **District court — persuasive only.** | https://law.justia.com/cases/federal/district-courts/FSupp/648/1127/1431057/ |
| `[KP-PERM]` | KP Permanent Make-Up, Inc. v. Lasting Impression I, Inc., 543 U.S. 111 (2004) (SCOTUS, reversing the 9th Cir.); 9th Cir. 17 F.3d 1083 (1994) | The 9th Cir.'s **aesthetic-functionality** approach to trade dress (pro-plaintiff) — reversed by SCOTUS, but the underlying circuit culture is what a plaintiff invokes. | https://www.law.cornell.edu/supremecourt/text/543/111 |
| `[SALINGER]` | Salinger v. Colting, 559 F.3d 918 (9th Cir. 2009) | **Counterweight** — the 9th Cir. on fair use (the *Catcher in the Rye* case): it does not always side with the rightsholder; fair use is available. | https://law.justia.com/cases/federal/appellate-courts/ca9/08-16892/08-16892-2009-03-27.html |

**Why the reputation is "pro-rightsholder," not merely "pro-corporate":** the 9th Circuit's IP posture favours the
*rightsholder* — which often means a corporation in practice but not always. It's the circuit of *MDY* and
*Broderbund*, not of *Salinger* alone.

#### 14.4.2 Why the Ninth Circuit cannot be reached for patents

This is the firewall: patent appeals from every district court go **exclusively** to the **Federal Circuit**
(28 U.S.C. §1295). A plaintiff cannot get 9th Circuit patent law no matter where they file. So the entire `ad-mmc`
**design-patent** exposure is Federal Circuit law everywhere, and the 9th Circuit forum-shopping concern applies
**only to copyright and trade dress** — the same questions where Monarchy's exposure is already near zero.

#### 14.4.3 Why the Ninth Circuit authorities do not hurt Monarchy

The hardest case on the list is **MDY**, so it deserves a direct answer:

- MDY held that **copying Blizzard's expressive code** to interoperate (Gliders/bots) was infringement, and that the
  **anti-reverse-engineering EULA bound MDY's users** because they assented to it.
- It did **not** hold that clean-room reimplementation of *unprotectable functional elements* is infringement. The
  infringement was the copying of protectable expression; the EULA bound the users because they clicked "I agree."
- Monarchy **never accepted Microsoft's EULA** (independent implementer of public specifications, not a licensee) and
  Monarchy **does not copy Microsoft's expression** — it implements the *functional* console idiom with its own artwork.
  The idea/expression line, merger, and scènes à faire survive MDY intact.
- `[BRODERBUND]` is the UI analogue: it protects a **stylistically creative** user interface. A standard MMC layout
  (tree, results pane, toolbar, property sheets) is functional, not stylistically creative — and *Broderbund* is a
  **district court decision from 1986**, persuasive only, predating *Apple v. Microsoft* and *Lotus*.

**Bottom line:** the 9th Circuit is the forum a plaintiff would *want*, and the cases they would cite are real. But
they don't reach patents, and on copyright/trade dress they require (a) **copied expression**, which Monarchy doesn't
have, and (b) a **protectable UI**, which a generic console layout is not. The defence is structural — clean-room,
own artwork, no EULA — not jurisdictional.

#### 14.4.4 Mitigations if a Ninth Circuit forum is ever threatened

- **Declaratory judgment action** filed first, in E.D. Mo., to lock in your forum and get first-to-file priority.
- **§1404(a) transfer** motion if a plaintiff files elsewhere.
- **§1406(a) dismissal/transfer** if venue is improper.
- **Forum non conveniens** where an alternative forum is plainly more appropriate.
- **Plaintiff's choice deference** cuts against you, but it is not absolute — especially where the chosen forum has
  no connection to the events.

---

### 14.5 Venue — where a suit could be brought

| Statute | Effect |
|---|---|
| **28 U.S.C. §1391** | General venue: where a defendant resides or where the acts occurred → **E.D. Mo. is a natural forum** for Monarchy |
| **28 U.S.C. §1400(b)** + `[TC-HEARTLAND]` *TC Heartland LLC v. Kraft Foods Group Brands LLC*, 581 U.S. 258 (2017) | Patent suits only where the defendant **resides** or maintains a **regular and established place of business** — no more forum-shopping into E.D. Tex. |
| Appeal route | E.D. Mo. → **Eighth Circuit** (St. Louis) → Supreme Court; **patent appeals → Federal Circuit** |

**Net for Monarchy:** on the **patent** side, forum is irrelevant (Federal Circuit everywhere). On **copyright/trade
dress**, you get **Eighth Circuit law**, whose trade-dress doctrine is *harder* for a plaintiff to deploy against a
generic UI. And your home district is E.D. Mo., one block from the Eighth Circuit courthouse.

---

## Appendix — re-verification recipe

```sh
# every URL in this index, HTTP code check
grep -oE 'https?://[^ )|"]+' AD-LICENSING-PATENT-CITATION-INDEX.md \
  | sort -u \
  | while read u; do printf '%s  %s\n' "$(curl -s -L -o /dev/null -w '%{http_code}' --max-time 25 "$u")" "$u"; done
```

Re-run when: Microsoft revises a promise (the OSP/CP pages carry "Revised" dates), the Patent & Program Map is
re-exported, or before any commercial release.
