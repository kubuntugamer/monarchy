# AD Functional Levels — a plain-language guide
### Written for someone whose AD experience is Windows Server 2000

Companion to [`AD-RESEARCH-INDEX.md`](AD-RESEARCH-INDEX.md), [`AD-IMPLEMENTATION-BLUEPRINT.md`](AD-IMPLEMENTATION-BLUEPRINT.md) and [`AD-1TO1-CONFORMANCE.md`](AD-1TO1-CONFORMANCE.md).

---

## 1. The short version

- A **functional level** is just a *version number* stamped on a domain or forest that means *"this behaves like at least Windows Server X."*
- It is the direct descendant of the **"mixed mode / native mode"** switch you used in Windows 2000.
- Raising it only **adds** features. You never *have* to raise it.
- **Samba defaults to Windows Server 2008 R2 level** — which is a *superset* of the Windows 2000 AD you know.
- Almost everything alarming in `AD-1TO1-CONFORMANCE.md` (claims, Dynamic Access Control, "FL 2025") belongs to **Windows Server 2012, 2016 and 2025** — features that did not exist in the AD you built and that you have never used. **My earlier document scored the gap list against the newest Windows Server. That was the wrong yardstick for your target.** This document re-scores it against the AD you actually know.

---

## 2. First, connect it to what you already know: mixed vs native mode

In **Windows 2000** you chose one of two modes when you built the domain:

| Windows 2000 mode | What it meant | Unlocked |
|---|---|---|
| **Mixed mode** | "Old NT 4.0 backup domain controllers may still exist in this domain." | Safest; but no universal groups, no group nesting, no SID history |
| **Native mode** | "Only Windows 2000 (or later) DCs here." | Universal groups, nested groups, group conversion, SIDHistory, transitive trusts |

**That switch is exactly what a "functional level" is.** In Windows Server 2003, Microsoft renamed it, turned it into a number, and split it into three separate dials. Nothing conceptually new — same idea, finer control.

---

## 3. The three dials

There are **three** functional levels, and this trips people up:

| Dial | Meaning | Where it lives |
|---|---|---|
| **Forest functional level** | The oldest DC in the whole *forest*. Gates forest-wide features. | rootDSE `forestFunctionality` |
| **Domain functional level** | The oldest DC in *this domain*. Gates domain-wide features. | rootDSE `domainFunctionality` |
| **Domain controller functional level** | What *this specific DC* claims its operating system is. Always ≥ the domain level. | rootDSE `domainControllerFunctionality` |

**The one rule:** you can **raise** a level, never lower it (short of restoring a backup). So you choose once, wisely.

In practice: if you only have one domain and one DC (as in most small setups, and certainly your Windows 2000 setup), all three are set to the same number and you can forget they are separate.

---

## 4. The timeline: what each level actually added, and where Samba stands

This is the table that matters. Read the **Samba** column against your target.

| Functional level | Year | What it *added* over the previous level | Samba 4.24.7 |
|---|---|---|---|
| **Windows 2000** (mixed/native) | 2000 | The AD you know: domains, OUs, users, computers, groups, GPOs, sites/subnets, AD-integrated DNS, Kerberos, LDAP, trusts, multi-master replication | ✅ **Complete** |
| **Windows Server 2003** | 2003 | **Linked Value Replication (LVR)**, `lastLogonTimestamp`, domain rename, cross-forest trusts, schema more modern | ✅ **Complete** |
| **Windows Server 2008** | 2008 | AES Kerberos encryption (128/256-bit), DFS-R for SYSVOL, Read-Only Domain Controllers (RODC) | ✅ Kerberos AES yes · ⚠️ DFS-R no · ⚠️ RODC partial |
| **Windows Server 2008 R2** → **Samba's default** | 2009 | **AD Recycle Bin**, Managed Service Accounts (sMSA), Authentication Mechanism Assurance, Offline Domain Join | ✅ **Complete** |
| **Windows Server 2012** | 2012 | **Dynamic Access Control (claims)**, Kerberos armoring (FAST), compound identity, **fine-grained password policies (PSO)**, authentication policies & silos, virtualisation-safe DCs | ⚠️ **Partial** — FAST ✅, PSO ✅, **claims/DAC ⚠️ incomplete** |
| **Windows Server 2012 R2** | 2013 | **Protected Users** group, **group Managed Service Accounts (gMSA)**, dMSA | ✅ Protected Users ✅, gMSA ✅ · ⚠️ dMSA no |
| **Windows Server 2016** | 2016 | Privileged Access Management (bastion forests), time-limited group membership | ⚠️ Partial |
| **Windows Server 2019 / 2022** | — | *No new functional level* — same level as 2016 | — |
| **Windows Server 2025** | 2025 | New schema, Windows LAPS, dMSA, LDAP signing/channel-binding enforcement, 32K DB pages | ❌ Not supported |

**Read that again with your target in mind:** everything after 2008 R2 is where Samba's gaps live — and you have never used any of it.

---

## 5. What Samba can actually be set to (verified in source)

| Setting | Accepted values | Where |
|---|---|---|
| **DC functional level** (`smb.conf`) | `2008_R2`, `2012`, `2012_R2`, `2016` — **floor is 2008 R2** | `lib/param/param_table.c` (`enum_ad_functional_level`) |
| **Domain/forest level at provision** | `2000`, `2003`, `2008`, `2008_R2` **(default)**, `2016` | `samba-tool domain provision --function-level` |
| **Raise an existing domain** | `2003` → `2008` → `2008_R2` → `2012` → `2012_R2` → `2016` | `samba-tool domain level raise` |
| **Base schema** | `2008_R2` … `2016`, **`2019` (default)** | `samba-tool domain provision --base-schema` |

Two things worth noticing there:

1. **Samba provisions at Windows Server 2008 R2 level by default.** That is a *strict superset* of the Windows 2000 domain you know — you get everything 2000 had, plus LVR, the AD Recycle Bin, managed service accounts and Kerberos AES, with nothing taken away.
2. **The DC itself will never claim to be older than 2008 R2.** Samba's own enum doesn't go lower, and the code refuses to start a domain whose level is *higher* than the DC claims (`python/samba/provision/__init__.py:1364`). So "make it exactly Windows 2000" is not a supported configuration — and you don't want it anyway (see §7).

Typical commands:

```bash
# The recommended target — Windows Server 2008 R2 level (this is the default anyway)
samba-tool domain provision --realm=EXAMPLE.COM --domain=EXAMPLE \
    --function-level=2008_R2

# If you specifically want to advertise the old 2000/2003-era level
samba-tool domain provision --realm=EXAMPLE.COM --domain=EXAMPLE \
    --function-level=2003        # 2003 is strictly better than 2000; see §7

# Check, and raise later
samba-tool domain level show
samba-tool domain level raise --domain-level=2008_R2 --forest-level=2008_R2
```

---

## 6. Re-scoring the gap register against *your* target

`AD-1TO1-CONFORMANCE.md` has 39 numbered gaps (G1–G39). Scored against **Windows Server 2025**, that list looks long. Scored against **the Windows 2000/2003/2008 R2 AD you know**, it collapses.

### Spread across the levels

| If your target is… | Gaps that still apply | Gaps that **vanish** (introduced after your level) |
|---|---|---|
| **Windows 2000 / 2003** | **G8** (XPRESS), **G22** (W32T), **G21** (ADWS, only for Windows management tools), **G23** (RPC edge cases), **G26/G27** (GPO), **G31** (DNSSEC, optional), **G13** (MS-KKDCP, optional), **G29** (SMB Direct, optional), **G35–G39** (separate products) | G1, G2, G3, G4, G5, G6, G7, G10*, G14, G15, G16, G18, G19, G20 |
| **Windows 2008 R2** (recommended) | as above, **plus G10** (RODC, if you want branch-office RODCs) | G1, G2, G4, G5, G6, G7, G14, G15 |

\* RODC was introduced at Windows Server 2008, so it only becomes relevant once you target 2008+.

### The list that actually still matters to you

| Gap | What it is | Do you care? |
|---|---|---|
| **G8 — DRSR XPRESS compression** | Samba disables the XPRESS replication-compression option (MSZIP only). Replication still *works*, just uses bigger packets. | **Yes — cheap, worthwhile.** Fix already sits in-tree (reuse `lib/compression/lzxpress*.c`). |
| **G9 — FRS / DFS-R SYSVOL replication** | Windows DCs replicate SYSVOL between DCs with FRS (≤2008) or DFS-R (2008+). Samba replicates SYSVOL over **DRS** instead. | **Only if you mix Samba and Windows DCs in one domain.** An all-Samba domain is unaffected. |
| **G10 — RODC completeness** | Read-Only Domain Controllers (a Windows Server 2008 feature). | Only if you want branch-office RODCs. |
| **G21 — ADWS** (port 9389) | A SOAP/HTTP service Windows management tools use. **The PowerShell `ActiveDirectory` module talks ADWS, not LDAP.** | Only if you want to manage Monarchy with Windows RSAT/PowerShell. `samba-tool` doesn't need it. |
| **G22 — MS-W32T** | The RPC interface behind Windows time commands. Signed NTP (`ntp_signd`) already works without it. | Minor. |
| **G26 / G27 — GPO server & client** | Samba serves GPOs; SSSD applies them on Linux members. | Present already. |
| **G31 — DNSSEC** | Signing DNS zones. | Optional; rarely needed. |
| **G29 — SMB Direct (RDMA)** | Kernel-bypass SMB for very fast networks. | Optional performance feature. |
| **G35–G38 — AD LDS / CS / FS / RMS** | *Separate* Microsoft server products, not part of AD DS. | Out of scope unless you specifically want them. |

Everything else in that document — FL 2016 claims, Dynamic Access Control, FL 2025, schema 91, dMSA, Windows LAPS, authentication silos, KeyCredentialLink — is **Windows Server 2012 and later**, and simply does not exist at your target level.

---

## 7. Recommendation

**Target: Windows Server 2008 R2 functional level — which is what Samba gives you out of the box.**

Why this is the right answer for you:

1. **It is a superset of the AD you know.** Every object, container, GPO, site, trust, DNS-integrated zone and Kerberos behaviour from Windows 2000 is still there.
2. **It is where Samba is essentially complete.** The documented incompleteness in Samba begins at the 2012-level features.
3. **It supports modern clients.** Windows 10/11 and modern Linux clients interoperate comfortably.
4. **You gain real things over 2000:** Linked Value Replication, the AD Recycle Bin, managed service accounts, Kerberos AES encryption.
5. **Nothing is removed** by choosing it.

**If you specifically want the oldest look**, use **`--function-level=2003`**, not `2000`:

- Windows 2000 level *lacks* **Linked Value Replication** and `lastLogonTimestamp`.
- Windows 2003 level adds both, at no cost.
- So **2003 is strictly better than 2000**, and is the closest honest equivalent to "the AD I grew up on."
- You cannot usefully go lower anyway: Samba's DC cannot claim below 2008 R2.

**Do not paper over this with the word "1:1":** if your target is the 2000/2003-era model, then Monarchy is *already very close to 1:1* for it, and the honest remaining work is short (G8 first). "1:1 with Windows Server 2025" is a different, much larger project — and it is not what you asked for.

---

## 8. What the frightening words actually mean

| Term | Plain meaning |
|---|---|
| **Functional level** | Version stamp on a domain/forest: "behaves like at least Windows Server X." Successor to 2000's mixed/native mode. |
| **FL 2016 / FL 2025** | Newer stamps. FL 2016 = the banner under which PAM and time-limited group membership arrived. FL 2025 = Windows LAPS, dMSA, new schema. |
| **Claims** | A Windows Server 2012 feature to tag users/computers with attributes and write access rules against those tags. Non-existent in 2000-era AD. |
| **Dynamic Access Control (DAC)** | The umbrella feature that uses claims. Windows Server 2012. Samba implements it only partially. |
| **Kerberos armoring / FAST** | A 2012 hardening feature that protects Kerberos messages from eavesdropping. Samba *has* it. |
| **gMSA / dMSA** | *Group / delegated* Managed Service Accounts — 2012 R2 and later. Samba has gMSA; dMSA is later still. |
| **PSO** | "Fine-grained password policy" (Windows Server 2008 / 2012). Samba *has* it. |
| **RODC** | Read-only branch-office DC (Windows Server 2008). Samba supports it partially. |
| **ADWS** | Port 9389 web service used by Windows management tools and PowerShell. Samba does not have it. |
| **Schema version** | An independent counter for the *attribute/class definitions*, separate from functional level. Samba is at the Windows Server 2019 schema. |

---

## 9. One-paragraph summary

You set up AD on Windows 2000 in **mixed or native mode**. Microsoft later renamed that switch to **functional levels** and split it into three dials (forest, domain, DC). Each new Windows Server version added features under a new number: 2003 (LVR), 2008 (Kerberos AES, RODC), 2008 R2 (AD Recycle Bin, managed service accounts), 2012 (claims/DAC), 2012 R2 (Protected Users, gMSA), 2016 (PAM), 2025 (LAPS, dMSA). **Samba implements everything up to 2008 R2 essentially completely, and only goes partial from 2012 upward.** So if you replicate **the AD you know**, Monarchy is nearly there already; the one genuinely worthwhile fix is **DRSR XPRESS compression (G8)**, and the only structural caveat is that **SYSVOL uses DRS rather than FRS/DFS-R**, which matters only if you mix Samba and Windows domain controllers in the same domain.
