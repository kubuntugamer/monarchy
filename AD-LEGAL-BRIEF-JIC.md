# Monarchy — Defensive Legal Brief (Just in Case)

> **NOT LEGAL ADVICE.** This is a research-draft brief prepared from the primary sources indexed in
> [`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md). It is intended to be
> handed to a licensed attorney for review, adaptation to the actual complaint, and signature. It is not a filed
> pleading and should not be filed as-is. Every authority below is cited to a primary source; keys like
> `[MS-OSP]` resolve in the citation index.

**Posture assumed:** a hypothetical civil action brought against the Monarchy project (or its maintainer) by a
rights-holder, alleging copyright, patent, trademark, and/or trade-dress infringement arising out of the
Monarchy reimplementation of the classic (Windows 2000/2003-era) Active Directory management console and
protocol stack. This brief is drafted as a **motion-to-dismiss / summary-judgment posture** and, where the
threat is only prospective, as a **declaratory-judgment posture**.

---

## I. Caption (template)

```
UNITED STATES DISTRICT COURT
FOR THE EASTERN DISTRICT OF MISSOURI

[PLAINTIFF],                          )
                                      )
      Plaintiff,                      )
                                      )
v.                                     )    Case No. [___]
                                      )
[MONARCHY MAINTAINER],                  )
                                      )
      Defendant.                      )
```

*(Operator is in St. Louis, Missouri — E.D. Mo. is the home forum; patents would be appealed to the Federal
Circuit regardless of forum. See citation index §14.)*

---

## II. Statement of facts

1. **Monarchy** is a free, open-source, non-commercial reimplementation of the **classic Microsoft Active
   Directory (Windows Server 2000/2003-era)** management console and protocol stack, for Linux/Unix.
2. Monarchy is derived from **Samba (GPL-3.0)** for the protocol engine and from **independently authored**
   code for the console host, snap-ins, and artwork. It is distributed under the GPL-3.0.
3. Monarchy's console host (`ad-mmc`) reproduces the **standard MMC idiom** — console tree, results pane,
   standard toolbar, status bar, tabbed property sheets — using its **own toolkit** (Qt) and its **own artwork**
   (original icons, open icon themes, metric-compatible OFL fonts). It does not ship, extract, trace, or
   redistribute any Microsoft bitmap, icon, screenshot, or other artwork.
4. Monarchy implements the AD protocols (ADTS, DRSR, SAMR, NRPC, LSAD, MS-KILE, MS-PAC, MS-SFU, MS-GPOL,
   MS-FRS1, MS-ADSC/ADA1-3, etc.) from the **publicly published Microsoft Open Specifications**, using
   clean-room discipline. It does not contain, decompile, or derive from any Microsoft source code or binary.
5. Monarchy has **never accepted, and is not a party to, any Microsoft End User License Agreement**. It is an
   independent implementer of published specifications, not a licensee.
6. Monarchy does not use the names "Active Directory," "Windows," "Windows Server," "Microsoft," or any Microsoft
   logo or mark. It operates under a **trademark-clean product name**.
7. Monarchy is **non-commercial**: no revenue, no subscriptions, no user-based connection fees, no
   contractually-required services. Distribution is of source code under an open-source license.
8. Monarchy's reference materials are **URLs only** — no Microsoft images are downloaded, stored, or shipped.

---

## III. Summary of argument

1. **No copyright infringement.** Monarchy copies no Microsoft expression. It implements functional ideas and
   published protocols with its own code and artwork. The idea/expression dichotomy, merger, and scènes à faire
   defeat every claim; the controlling authority (*Apple v. Microsoft*, *Lotus*) rejects GUI "look and feel"
   copyright. The one case a plaintiff would cite (`MDY`) is distinguished on its facts (no copied expression,
   no accepted EULA).
2. **No patent infringement.** The Windows 2000/2003-era patents are **expired** (20-year term). The standards
   spine is **royalty-free under the OSP**. The proprietary AD protocols are covered by an **irrevocable
   no-assert pledge for open-source development and non-commercial distribution**, and Microsoft will not assert
   patents on a protocol unless listed on the Patent & Program Map. Patent appeals go to the Federal Circuit,
   which binds every district.
3. **No trademark infringement.** No Microsoft mark is used; no likelihood of confusion; different name and
   branding.
4. **No trade dress.** A functional MMC-style console layout is not protectable: functionality bars it
   (*TrafFix*), and product-design trade dress requires secondary meaning (*Wal-Mart*), which a generic
   management-console idiom cannot acquire. In the Eighth Circuit (the operator's home circuit) the secondary-
   meaning requirement is express.
5. **No EULA breach.** Monarchy is not a licensee; it never accepted Microsoft's terms. *MDY* is distinguishable.
6. **Fair use / interoperability.** Even on the most adverse reading, reimplementing published functional
   interfaces for interoperability is fair use (*Google v. Oracle*, *Sega*, *Connectix*, *Lotus*) and, in the
   EU, functionality is excluded from protection (*SAS v. WPL*).

---

## IV. Argument

### A. No copyright infringement

#### 1. The idea/expression dichotomy and merger

Copyright protects **expression**, not ideas, methods of operation, or functionality. *Apple Computer, Inc. v.
Microsoft Corp.*, 35 F.3d 1435 (9th Cir. 1994): Apple "cannot get patent-like protection for the idea of a
graphical user interface, or the idea of a desktop metaphor." *Lotus Dev. Corp. v. Borland Int'l, Inc.*,
49 F.3d 807 (1st Cir. 1995), aff'd, 516 U.S. 233 (1996): a menu command hierarchy is an uncopyrightable
"method of operation." *SAS Institute Inc. v. World Programming Ltd.*, C-406/10 (CJEU, 2 May 2012):
functionality, programming language, and file formats are not protected. *CJEU C-393/09 (BSA)*: a GUI is not
protectable as a computer program, though it may be a work if it is its author's own intellectual creation.

Monarchy reproduces **none** of Microsoft's expression. It re-implements the *functional* MMC idiom — console
tree, results pane, toolbar, status bar, tabbed property sheets — with its own code. Where an idea can only be
expressed one way, merger bars protection; where a layout is dictated by function, scènes à faire bars it.

#### 2. No copied expression; clean-room discipline

Monarchy contains no Microsoft source code, no decompiled binaries, no traced artwork. It is authored from
published specifications and differential testing. The only copyright exposure in a UI clone is the **artwork**,
and Monarchy ships none of Microsoft's.

#### 3. *MDY* is distinguished

*MDY Industries, LLC v. Blizzard Entertainment, Inc.*, 629 F.3d 928 (9th Cir. 2010), is the case a plaintiff
would cite. It held that copying Blizzard's **expressive code** to interoperate was infringement and that the
**anti-reverse-engineering EULA bound MDY's users**. It does **not** hold that clean-room reimplementation of
unprotectable functional elements is infringement. Monarchy (a) never accepted Microsoft's EULA — it is an
independent implementer of public specifications, not a licensee — and (b) copies no expression. The idea/
expression line, merger, and scènes à faire survive *MDY* intact. *Google LLC v. Oracle America, Inc.*, 593
U.S. 1 (2021) confirms that reimplementing a functional API is fair use; *Sega Enterprises Ltd. v. Accolade,
Inc.*, 977 F.2d 1510 (9th Cir. 1992), and *Sony Computer Entertainment, Inc. v. Connectix Corp.*, 203 F.3d 596
(9th Cir. 2000), protect reverse engineering for compatibility.

#### 4. *Broderbund* does not reach a functional console

*Broderbund Software, Inc. v. Unison World, Inc.*, 648 F. Supp. 2d 1127 (N.D. Cal. 1986), protects **stylistically
creative** user interfaces as audio-visual works. A standard MMC layout (tree, results pane, toolbar, property
sheets) is functional, not stylistically creative, and *Broderbund* is a district-court decision from 1986 —
persuasive, not binding, and predating *Apple v. Microsoft* and *Lotus*.

### B. No patent infringement

#### 1. The patents are expired

Windows 2000-era AD was designed and filed ~1996–2000; Windows Server 2003 features ~2000–2003. Under 35
U.S.C. §154(a)(2), US utility patents run 20 years from filing; design patents 15 years. The classic-AD
patents expired ~2016–2023. Live claims concentrate in post-2012 features outside the classic scope.

#### 2. The standards spine is royalty-free (OSP)

Kerberos v5 (RFC 1510/1964), PKINIT (RFC 4556), LDAP v3 (RFC 2251/2256), DNS (RFC 1034/1035/2136/2782…),
SPNEGO (RFC 4178), SASL (RFC 2222), NetBIOS-over-TCP (RFC 1001/1002), CIFS, plus the Microsoft Kerberos
group-membership extensions, SNTP extensions, and the X/Open directory-services RPC entry — all are in the
**Open Specification Promise** (`[MS-OSP]`): irrevocable, royalty-free, worldwide, for commercial *and* open
source, full *or* partial implementations.

#### 3. The proprietary AD protocols: RAND + OSS pledge

MS-ADTS, MS-DRSR, MS-SAMR, MS-NRPC, MS-LSAD/LSAT, MS-SFU, MS-KILE/PAC, MS-ADSC/ADA1-3, MS-GPOL/GPOD,
MS-FRS1/2, MS-DFSC, MS-DSSP, MS-W32T, MS-NLMP are published under the Interoperability Principles (`[MS-IPP]`):
RAND/low-royalty licensing, plus an **irrevocable no-assert pledge for open-source development and
non-commercial distribution** (`[MS-PLEDGE]`). Microsoft will not assert patents on a protocol unless listed on
the Patent & Program Map (`[MS-PATMAP]`). Monarchy is open-source and non-commercial, so the pledge covers
development and non-commercial distribution; for any commercial release, the reliance is on the map showing no
listed patent, the RAND licence, or Tier-3 expiry.

#### 4. Federal Circuit controls patents nationwide

Patent appeals from every district go exclusively to the **Federal Circuit** (28 U.S.C. §1295). The
design-patent law (35 U.S.C. §171) is the same in St. Louis as in San Jose. The operator's location is
irrelevant to the patent analysis. *Egyptian Goddess v. Swisa*, 543 F.3d 665 (Fed. Cir. 2008) (en banc), is
the design-patent infringement test.

### C. No trademark infringement

Monarchy uses **none** of Microsoft's marks: not "Active Directory," not "Windows," not "Windows Server," not
"Microsoft," not any Microsoft logo. No likelihood of confusion is possible where the name, branding, and
packaging are entirely distinct. Trademark protects source identification, not functionality or a generic
management-console idiom.

### D. No trade dress

Product-design trade dress requires **distinctiveness** and **non-functionality** (*Wal-Mart Stores v. Samara
Bros.*, 529 U.S. 205 (2000); *TrafFix Devices v. Marketing Displays*, 532 U.S. 23 (2001) — functionality bars
protection). A console-tree/results-pane/toolbar layout is the **standard Win32 common-controls idiom used by
thousands of unrelated products**; it is functional and generic, not distinctive. In the Eighth Circuit, product-
design trade dress additionally requires **secondary meaning** (ALFA International, *Trade Dress: 8th Circuit*),
which a generic management-console layout cannot acquire. *KP Permanent Make-Up, Inc. v. Lasting Impression I,
Inc.*, 543 U.S. 111 (2004), confirms that fair use and consumer confusion can coexist.

### E. No EULA breach

Monarchy is not a licensee. It never accepted, and is not bound by, any Microsoft EULA. *MDY* is
distinguishable: there, the users had assented to the EULA. Independent implementation of published
specifications from public documents is not a breach of any contract.

### F. Fair use and interoperability

Even on the most adverse reading, reimplementing published functional interfaces for interoperability is fair
use: *Google v. Oracle* (fair use of a functional API), *Sega* and *Connectix* (reverse engineering for
compatibility), *Lotus* (method of operation). In the EU, *SAS v. WPL* excludes functionality, language, and
formats from copyright. *MDY* does not change this: it addressed copying of expression under an accepted
contract, not clean-room reimplementation of unprotectable functional elements.

---

## V. The "look and feel" argument specifically

A plaintiff's strongest theory would be that the Monarchy console's **appearance** infringes copyright or trade
dress. Each element fails:

| Element | Result |
|---|---|
| Console tree + results pane + splitter + toolbar + menu + status bar + column headers | **Not protectable** — generic Win32 idiom; functional; scènes à faire |
| Window chrome, controls, scrollbars, tabbed property sheets | **Not Microsoft's** — supplied by the toolkit |
| Fonts | **Not protected** as a "look" — use metric-compatible OFL faces |
| Icons / toolbar glyphs / illustrations | **Replaceable** — Monarchy ships its own artwork; the metaphors (person = user, two people = group) are unprotectable ideas |
| The layout *as a compilation* | **Thin at most** — merger bars protection where all elements are functional |
| Design patents on the classic console | **Expired** (15-year term; ~2011–2018) and **inapplicable** — functional layouts are not "ornamental" |

*Apple v. Microsoft* rejects patent-like protection for the idea of a GUI or desktop metaphor. *Broderbund*
protects only *stylistically creative* UI and is a 1986 district decision. *Wal-Mart* and *TrafFix* bar trade
dress for functional product design without secondary meaning.

---

## VI. Declaratory judgment / standing (if no suit has been filed)

If a threat is prospective rather than actual, Monarchy (or its maintainer) may file a **declaratory judgment
action** in E.D. Mo. to (a) establish non-infringement and (b) lock in a favourable forum and obtain
first-to-file priority. The DJ plaintiff must show an **actual controversy** (real and immediate threat of
suit, not a hypothetical fear). Where a rights-holder has sent a cease-and-desist or threatened litigation,
that threshold is ordinarily met. The DJ action also preserves the ability to seek **§1404(a) transfer** or
**§1406(a) dismissal** if the rights-holder files elsewhere.

---

## VII. Conclusion

Monarchy is a **clean-room, open-source, non-commercial reimplementation** of the classic Active Directory
management console and protocol stack. It copies **no Microsoft expression**, accepts **no Microsoft EULA**,
uses **no Microsoft mark**, and ships **no Microsoft artwork**. The patents on the 2000/2003 feature set are
**expired**; the standards spine is **royalty-free**; the proprietary protocols are covered by an **irrevocable
OSS no-assert pledge**; and the console's functional idiom is **not protectable** as copyright or trade dress.
On these facts, every theory a plaintiff could bring fails.

---

## VIII. Cross-reference to the research record

| Document | Contents |
|---|---|
| [`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md) | Every source, quote, and URL behind §§IV.B, V, and the patent/trademark analysis (keys `[MS-OSP]`, `[MS-IPP]`, `[MS-PLEDGE]`, `[MS-PATMAP]`, `[PFIF]`, `[EU]`, `[APPLE-MS]`, `[LOTUS]`, `[BSA]`, `[SAS]`, `[ALICE]`, `[WALMART]`, `[TRAFIX]`, `[DESIGN171]`, `[EU-DESIGN]`, `[MDY]`, `[BRODERBUND]`, `[KP-PERM]`, `[SALINGER]`, `[ROTTLUND]`, `[EFJ]`, `[ALFA8]`, `[TC-HEARTLAND]`, `[GO]`) |
| [`AD-1TO1-CONFORMANCE.md`](AD-1TO1-CONFORMANCE.md) §7.1, §7.2 | The three-tier patent analysis; per-feature status; forum/binding-authority bullet |
| [`AD-CONSOLE-IMAGE-INDEX.md`](AD-CONSOLE-IMAGE-INDEX.md) §0 | Reference-only / don't-ship design rules |
| [`AD-IMPLEMENTATION-BLUEPRINT.md`](AD-IMPLEMENTATION-BLUEPRINT.md) §A.23 | The `ad-mmc` / `ad-snapins` / `ad-icons` module plan |

---

> **Final caveat.** This brief is a research draft, not a filed pleading and not legal advice. A licensed
> attorney must adapt it to the actual complaint, check the authorities for subsequent history, and sign it.
> Every proposition reduces to a primary source in the citation index; that is the point of the index.