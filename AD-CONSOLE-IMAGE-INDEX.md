# Microsoft AD Management Console — Reference URL Index

**Purpose:** an index of **URLs** to reference images of the **Microsoft Active Directory management console family** — nothing is downloaded, nothing is stored locally except this index. Use it to jump straight to a screenshot without hunting.

**Interpretation note:** "MS AD Mgmt Console" is read as the **Microsoft Active Directory management console family** — ADUC, ADAC, Sites and Services, Domains and Trusts, Schema, Group Policy Management, DNS Manager, ADSI Edit, LDP, plus the adjacent admin tools (AD CS, AD FS, Server Manager).

**Machine-readable index:** [`reference/IMAGE-URL-INDEX.tsv`](reference/IMAGE-URL-INDEX.tsv) — **1,971 rows**, tab-separated, columns `group · repo · path · url`. Every `url` is a direct raw image link (verified HTTP 200 pattern). Filter with `grep`.

---

## 0. How to use this index — reference, don't ship

> **These are Microsoft's images.** Index them, link them, study them — but do **not** download-and-ship them as
> Monarchy assets, and do **not** trace their artwork. Copyright protects the *pictures*, not the *layout*.
> Full legal basis: [`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md) **§13**.

Treat each screenshot as a **specification of behaviour**, then rebuild it with your own toolkit and artwork.

| Derive from the screenshots (not protectable) | Replace with your own (protected) |
|---|---|
| Pane structure (console tree, results pane, splitter) | Icon bitmaps — never extract MS `.ico`/`.dll` resources |
| Toolbar button set, menu layout, command names, column headers | Toolbar glyph artwork (use any open icon set) |
| Dialog/tab structure, field order, workflows (New User, Delegation, RSoP) | Product name, logos, about-box art, splash screens |
| Sizes/spacing/proportions of the classic MMC look | Fonts — use metric-compatible OFL faces (e.g. Selawik) |
| The `.msc` console layout and snap-in organisation | Any Microsoft screenshot shipped as an asset |

**Safe posture:** *independently authored, visually equivalent.* Reproducing the standard MMC idiom (tree + results
pane + toolbar) is not copying; copying individual artwork, or the names/branding, is.

---

## 1. Source corpora indexed

| Repo | Base raw URL | AD-relevant images |
|---|---|---|
| `MicrosoftDocs/windowsserverdocs` | `https://raw.githubusercontent.com/MicrosoftDocs/windowsserverdocs/main/WindowsServerDocs/…` | 1,449 |
| `MicrosoftDocs/SupportArticles-docs` | `https://raw.githubusercontent.com/MicrosoftDocs/SupportArticles-docs/main/…` | 453 |
| `MicrosoftDocs/win32` (`desktop-src/AD`, `desktop-src/ADSI`) | `https://raw.githubusercontent.com/MicrosoftDocs/win32/main/…` | 34 |
| `MicrosoftDocs/windows-powershell-docs` | (no AD console images) | 0 |

> Browse instead of raw: swap `https://raw.githubusercontent.com/<repo>/main/` for `https://github.com/<repo>/blob/main/` to get the image inside GitHub's UI, or open the article itself on learn.microsoft.com.

---

## 2. The console catalogue

| # | Console | Launch | What it manages | Where its images are indexed |
|---|---|---|---|---|
| 1 | **Active Directory Users and Computers (ADUC)** | `dsa.msc` | users, computers, groups, OUs, delegation, FSMO, Attribute Editor | `Support: server AD` / `Support: client AD` (property sheets, Kerberos delegation); classic era → §4 |
| 2 | **Active Directory Administrative Center (ADAC)** | `dsac.exe` | recycle bin, FGPP/PSO, PowerShell History Viewer | `AD DS (core)` → `…/get-started/adac/media/**` |
| 3 | **Active Directory Domains and Trusts** | `domain.msc` | functional levels, UPN suffixes, trusts | `AD DS (core)` (forest-recovery, trusts); classic era → §4 |
| 4 | **Active Directory Sites and Services** | `dssite.msc` | sites, subnets, site links, bridgeheads, NTDS settings | `AD DS (core)` (deploy/RODC, forest-recovery); classic era → §4 |
| 5 | **Active Directory Schema** | `schmmgmt.msc` | attribute/class definitions, schema master | `Win32 AD / ADSI` (`schemacont.png`); classic era → §4 |
| 6 | **ADSI Edit** | `adsiedit.msc` | raw DN/attribute editing | `AD DS (core)` → `manage/forest-recovery-guide/media/adsi*.png`; `Win32 AD / ADSI` |
| 7 | **LDP** | `ldp.exe` | LDAP browse/search/modify, controls, policy views | `AD DS (core)` → `plan/security-best-practices/media/**/ldp-*.png`, `forest-recovery-guide/media/ldp*.png` |
| 8 | **Group Policy Management Console (GPMC)** | `gpmc.msc` | GPOs, links, scope, delegation, RSoP | `Support: * Group Policy`; `AD FS` (`gpmc1..9`) |
| 9 | **DNS Manager** | `dnsmgmt.msc` | AD-integrated zones, records, aging/scavenging, DNSSEC | `DNS Manager / networking` |
| 10 | **Certificate Authority / PKI (AD CS)** | `certsrv.msc`, `pkiview.msc` | templates, CA config, AIA/CRL, OCSP | `AD CS / PKI`, `Support: PKI` |
| 11 | **AD FS Management** | AD FS console | federation trusts, claim rules, relying parties | `AD FS` |
| 12 | **Server Manager** (+ AD DS Config Wizard) | `servermanager.exe` | role install, DC promotion, RODC, forest/child domains | `AD DS (core)` → `deploy/**`; `RSAT / Server Manager`; `Server Manager / Admin Center` |
| 13 | **Windows Admin Center** | web | modern web administration | `Server Manager / Admin Center` |
| 14 | **Resultant Set of Policy** | `rsop.msc` | applied-policy reporting | `DNS Manager / networking`, Group Policy areas |
| 15 | **DFS Management** | `dfsmgmt.msc` | SYSVOL-relevant DFS namespaces/replication | `Support: server networking/DNS` |
| 16 | **Windows LAPS** | LAPS UI / Intune | local admin password management | `Windows LAPS` |

---

## 3. Index by area

Counts are rows in `IMAGE-URL-INDEX.tsv`. `→` shows the path fragment to grep.

| Group | Rows | Notable path fragments |
|---|---|---|
| `AD DS (core)` | 567 | `identity/ad-ds/get-started/adac/media/**` (ADAC, 28) · `deploy/media/**` (Server Manager/AD DS wizard, 177) · `deploy/RODC/media/**` · `manage/media/**` (204) · `manage/forest-recovery-guide/media/**` (ADSI Edit `adsi*.png`, LDP `ldp*.png`) · `manage/component-updates/media/**` (80) · `plan/media/**` + `plan/security-best-practices/media/**` (109) · `get-started/virtual-dc/media/**` (38) |
| `AD FS` | 431 | `identity/ad-fs/{operations,deployment,design,development,troubleshooting,technical-reference}/media/**` |
| `DNS Manager / networking` | 259 | `networking/media/Add-a-DNS-Resource-Record/**`, `Create-a-DNS-Zone`, `Edit-a-DNS-Zone`, `View-DNS-Resource-Records…`, `Set-Access-Scope…`, `configure-aging-scavenging`, `dnssec-*`, `ipam_DNS*`, `dns-configuration.png` |
| `Support: server AD` | 147 | `support/windows-server/active-directory/media/**` — `configure-kerberos-constrained-delegation/active-directory-users-computers.png`, `…/aduc-*`, `multiple-tabs-of-user-property-missing/**`, `replication-error-*/**`, RODC, LDS, event-1644 LDAP analysis |
| `Security / Kerberos` | 105 | `security/media/**`, `security/kerberos/media/**` — `computer-account-properties-msds-supportedencryptiontypes.png`, protected accounts, RC4 |
| `Support: server networking/DNS` | 89 | `support/windows-server/networking/media/**` |
| `Support: client networking/DNS` | 77 | `support/windows-client/networking/media/**` |
| `RSAT / Server Manager` | 55 | `administration/media/install-remote-server-administration-tools/**`, performance-tuning, WSU |
| `Support: server security` | 51 | `support/windows-server/windows-security/media/**` (incl. `ad-sites-and-services.png`, `schema-search.png`) |
| `AD CS / PKI` | 36 | `identity/ad-cs/media/**` — certificate templates, CA properties, AIA, OCSP, ML-DSA |
| `Support: client Group Policy` | 35 | `support/windows-client/group-policy/media/**` |
| `Win32 AD / ADSI object model` | 34 | `win32/desktop-src/ADSI/images/**` (`adsiexmo.png`, `schemacont.png`), `desktop-src/AD/images/**` (`domain-trust.png`, `forests.png`) |
| `Support: client AD` | 20 | `support/windows-client/active-directory/media/**` |
| `Support: server Group Policy` | 18 | `support/windows-server/group-policy/media/**` (`gpmc-*`) |
| `Support: PKI` | 18 | `support/windows-server/certificates-and-public-key-infrastructure-pki/media/**` |
| `Server Manager / Admin Center` | 16 | `get-started/media/**` (`windows-admin-center.png`) |
| `Windows LAPS` | 13 | `identity/laps/media/**` |

Quick recipes:

```bash
cd Monarchy/reference
# every ADAC screenshot URL
awk -F'\t' '$1=="AD DS (core)" && $3 ~ /adac\// {print $4}' IMAGE-URL-INDEX.tsv
# everything mentioning ADUC
grep -i 'aduc\|users-and-computers' IMAGE-URL-INDEX.tsv
# all GPMC shots
awk -F'\t' '$1 ~ /Group Policy/ {print $4}' IMAGE-URL-INDEX.tsv
# DNS Manager only
awk -F'\t' '$1 ~ /DNS Manager/ && $3 ~ /DNS|dns/ {print $4}' IMAGE-URL-INDEX.tsv
```

---

## 4. Classic consoles — article references (the images Microsoft withdrew)

The current Microsoft docs no longer serve inline images for the **classic** console documentation (ADUC, Sites and Services, Domains and Trusts, Schema, DNS Manager) — verified: the `previous-versions` pages return zero `<img>` tags. These are the four seams to close, with the article URLs to consult (and to crawl via the Wayback Machine / `archive.org` CDX for the historical screenshots).

### 4.1 Windows 2000 / 2003 era (the model Monarchy targets)

| Topic | URL |
|---|---|
| **Step-by-Step Guide to Managing the Active Directory** (Win2000 — ADUC, Domains and Trusts, sites) | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb742437(v=technet.10)` |
| Managing Active Directory from MMC (Win2003 — `dsa.msc`/`domain.msc`/`dssite.msc` command-line options) | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc757197(v=ws.10)` |

### 4.2 Active Directory Sites and Services

| Topic | URL |
|---|---|
| Active Directory Sites and Services (overview) | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc730868(v=ws.11)` |

### 4.3 Active Directory Domains and Trusts

| Topic | URL |
|---|---|
| Create a Forest Trust | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754626(v=ws.11)` |
| Verify a Trust | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753821(v=ws.11)` |
| Remove a Trust | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771137(v=ws.10)` |
| Enable or Disable an Existing Name Suffix from Routing | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc731648(v=ws.11)` |
| Trusts Properties — General Tab | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd145414(v=ws.11)` |

### 4.4 Active Directory Schema

| Topic | URL |
|---|---|
| Active Directory Schema (overview) | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc771796(v=ws.10)` |
| Install the Active Directory Schema Snap-In | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc732110(v=ws.11)` |
| Install the Schema Snap-In (2008) | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc794773(v=ws.10)` |
| Install the AD Schema snap-in (2003, creates `schmmgmt.msc`) | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755885(v=ws.10)` |
| Administration tools for the Active Directory schema | `https://learn.microsoft.com/en-us/previous-versions/orphan-topics/ws.10/cc773292(v=ws.10)` |

### 4.5 DNS Manager

| Topic | URL |
|---|---|
| DNS Tools and Settings | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197560(v=ws.10)` |
| DNS Tools (DNS Manager capabilities) | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753579(v=ws.11)` |
| Configure a New DNS Server | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771031(v=ws.10)` |
| DNS: scavenging should be enabled | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff807390(v=ws.10)` |
| DNS Zones (DNSSEC signing wizard) | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn593642(v=ws.11)` |
| Manage DNS zones using DNS server (current) | `https://learn.microsoft.com/en-us/windows-server/networking/dns/manage-dns-zones` |

### 4.6 Recovering the withdrawn screenshots via Wayback

The Internet Archive is intermittently offline, but the CDX API is the tool:

```bash
# list archived snapshots of a classic article
curl -s "http://web.archive.org/cdx/search/cdx?url=technet.microsoft.com/en-us/library/cc730868*&output=text&fl=timestamp,original,statuscode&collapse=urlkey"

# list archived IMAGES under an article prefix
curl -s "http://web.archive.org/cdx/search/cdx?url=technet.microsoft.com/en-us/library/cc730868*&output=text&fl=original&filter=original:.*\.(png|gif|jpg)" | sort -u
```

The original TechNet image host was `i.msdn.microsoft.com` / `i1.msdn.microsoft.com`; those image URLs are archived and can be indexed the same way (swap the prefix).

---

## 5. External / community reference sources

Useful when Microsoft has no image at all:

| Source | What it gives |
|---|---|
| `https://learn.microsoft.com/en-us/training/` (AD DS learning paths, e.g. *Active Directory sites, topology and replication*) | current training modules still embed ADUC / Sites screenshots |
| `https://lofl-project.github.io/loflcab/MMC/` | index of MMC files (`dssite.msc`, `domain.msc`, …) and their commands |
| Petri IT Knowledgebase, Netwrix, Cayosoft, 404 Tech Support, Jack Stromberg, Raihan Al-Beruni | hands-on console walkthroughs with screenshots |
| O'Reilly *Active Directory Cookbook* figures | `dsa.msc` / `domain.msc` / `dssite.msc` dialogs |
| `https://commons.wikimedia.org/w/index.php?search=Active+Directory` | freestanding AD screenshots |
| **A Windows host (RSAT → AD DS and AD LDS Tools)** | the authoritative capture route — see §6 |

---

## 6. How to fill the classic-console gap properly

1. **Capture from a real host (authoritative).** A Windows Server eval VM, or a Windows client with **RSAT – AD DS and AD LDS Tools**, gives exact layouts. Capture checklist:
   - **ADUC (`dsa.msc`)**: console root; OU with users/computers/groups; New → User / Group / Computer / OU / Contact; every *User Properties* tab (General, Address, Account, Profile, Telephones, Organization, Member Of, Published Certificates, Object, Security, COM+, Attribute Editor, Environment, Sessions, Remote control, Terminal Services Profile, Dial-in); Group/Computer Properties; Find query builder; Operations Masters; Raise Functional Level; Delegation of Control wizard; View → Advanced Features / Filter Options / Customize Columns.
   - **Domains and Trusts (`domain.msc`)**: root; UPN suffixes; Raise Forest Functional Level; Trusts tab; New Trust wizard; trust properties (Transitive, SID filtering, Selective authentication); Name Suffix Routing; Validate.
   - **Sites and Services (`dssite.msc`)**: Sites tree; Subnets; Inter-Site Transports (IP/SMTP), site links, link bridges; site properties (licensing/GC); Servers → NTDS Settings → connection objects; site-link cost/schedule/interval; View → Show Services Node (Services, Public Key Services, MSMQ); Change Domain Controller.
   - **Schema (`schmmgmt.msc`)**: root; Attributes; Classes; Properties / Attribute Editor.
   - **ADSI Edit (`adsiedit.msc`)**: Connection Settings dialog, naming-context tree, property editor.
   - **DNS Manager (`dnsmgmt.msc`)**: AD-integrated zone, record dialogs, aging/scavenging, DNSSEC, store-in-AD prompt, replication scope.
2. **Wayback CDX** for the historical 2000/2003-era screenshots (§4.6).
3. **Training modules + community** for anything still missing (§5).

---

## 7. Refreshing the index

The `IMAGE-URL-INDEX.tsv` was built from each repo's git tree (metadata only, no blobs):

```bash
gh api "repos/MicrosoftDocs/windowsserverdocs/git/trees/main?recursive=1"     # then filter *.png/.gif/… under WindowsServerDocs/
gh api "repos/MicrosoftDocs/SupportArticles-docs/git/trees/main?recursive=1"  # under support/windows-{server,client}/…
gh api "repos/MicrosoftDocs/win32/git/trees/main?recursive=1"                 # under desktop-src/{AD,ADSI}/
```

To widen further, the same recipe works on any repo — e.g. `MicrosoftDocs/entra-docs` (hybrid/on-prem AD), `MicrosoftDocs/azure-docs`, `MicrosoftDocs/ExchangeDocs`, and the archived `windows-itpro-docs` mirrors.

---

## 8. Cross-references

| Document | Relevance |
|---|---|
| [`AD-RESEARCH-INDEX.md`](AD-RESEARCH-INDEX.md) | Specs, project research, acquired sources |
| [`AD-IMPLEMENTATION-BLUEPRINT.md`](AD-IMPLEMENTATION-BLUEPRINT.md) | Spec→code correlation; the GUI module (`OpenRSAT`) these screenshots are the visual reference for |
| [`AD-1TO1-CONFORMANCE.md`](AD-1TO1-CONFORMANCE.md) | Gap register vs MS AD |
| [`AD-FUNCTIONAL-LEVELS-PRIMER.md`](AD-FUNCTIONAL-LEVELS-PRIMER.md) | Which AD era the console set corresponds to |
