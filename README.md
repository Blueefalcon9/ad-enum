# ad-enum

![PowerShell](https://img.shields.io/badge/powershell-5.1%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Read-only Active Directory enumerator for security configuration reviews. Collects the objects, then
**correlates them into severity-ranked findings** — so the output is a prioritised list, not seven CSVs
you have to join by hand.

**Read-only by design.** Every operation is an LDAP read or a SYSVOL file read. No writes, no password
changes, no exploitation. Safe to run during a configuration review on a production domain.

## Why v2

| Defect in v1 | Effect | Fix |
|---|---|---|
| `Select-Object Name,SamAccountName,DN:DistinguishedName` | `DN:DistinguishedName` is not valid property syntax — **the unconstrained-delegation export had an empty DN column** | Corrected property list |
| GPP `cpassword` only flagged the *file* | the finding is the credential, not the filename | **Decrypts cpassword to plaintext** (AES key is public per MS14-025) |
| Entire SYSVOL scanned for `*.xml` + `Select-String` per file | very slow on real domains | Targets the 6 GPP filenames that can carry cpassword, parses XML directly |
| `Get-ADUser -Filter *` with no paging | timed out or exhausted memory on large domains | `-ResultPageSize` (default 1000) |
| `Get-ADTrust -Server $Domain` with `$Domain` unset | passed `-Server $null` | Central splat honouring `-Server` / `-Credential` everywhere |
| No `-Credential` / `-Server` support | unusable off a domain-joined host | Both supported throughout |
| Raw dumps only | no prioritisation | `findings.csv` / `findings.json`, severity-ranked |

## New checks in v2

Beyond v1's coverage:

- **DCSync rights** — non-default principals holding `DS-Replication-Get-Changes[-All]` on the domain root
- **krbtgt password age** — golden tickets stay valid until it is rotated twice
- **MachineAccountQuota** — `> 0` lets any user create computer accounts, enabling RBCD and shadow-credential chains
- **Protected Users coverage** — tier-0 accounts outside the group
- **Constrained delegation to a DC** — a direct domain-compromise path
- **Unconstrained delegation on non-DC hosts** — separated from DCs, where it is expected
- **Protocol transition** (`TRUSTED_TO_AUTH_FOR_DELEGATION`)
- **Kerberos encryption types** — service accounts without AES, so RC4 tickets can be issued
- **SID history** — a privileged SID here grants invisible access
- **Windows LAPS** as well as legacy LAPS, reported as a coverage percentage
- **Unsupported DC operating systems**, legacy functional levels, external trusts without SID filtering
- **Privileged-group hygiene** — computer accounts in admin groups, populated Account/Print/Server Operators
- **Stale-but-enabled accounts** — prime password-spray targets

## Requirements

- PowerShell 5.1 or later
- **Recommended:** RSAT ActiveDirectory module. Without it the script falls back to ADSI with reduced coverage.
- A domain context, or `-Credential` for cross-domain use

## Usage

```powershell
.\ad-enum.ps1
.\ad-enum.ps1 -Output .\client-ad
.\ad-enum.ps1 -Domain corp.example.com -Server dc01.corp.example.com -Credential (Get-Credential)
.\ad-enum.ps1 -SkipSysvol          # skip the slowest step
```

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Domain` | current | Target domain FQDN |
| `-Output` | `output` | Output directory |
| `-Server` | DC locator | Specific domain controller |
| `-Credential` | — | PSCredential for cross-domain use |
| `-NoADModule` | off | Force ADSI-only mode |
| `-SkipSysvol` | off | Skip the SYSVOL GPP sweep |
| `-PageSize` | `1000` | LDAP page size |

## Output

One CSV and one JSON per category, plus:

- **`findings.csv` / `findings.json`** — correlated findings with severity, affected object, why it matters, and a recommendation
- **`collection_stats.csv`** — object counts per category, so you can tell "zero findings" from "collection failed"

## Reading the results

Severity reflects the *configuration*, not confirmed exploitability. Correlation is what turns an indicator
into a finding: service accounts legitimately hold SPNs, and some accounts genuinely need non-expiring
passwords — a kerberoastable account that is **also** privileged is the finding, and v2 flags that
combination as Critical rather than making you join the CSVs yourself.

Two things are escalations regardless of context:

- **Any `cpassword` in SYSVOL.** The AES key is public, SYSVOL is readable by every authenticated user, and
  v2 prints the plaintext. Treat the credential as already compromised and rotate it.
- **Non-default DCSync rights.** That principal can replicate every password hash in the domain.

`collection_stats.csv` matters more than it sounds: an empty category because a query failed looks identical
to an empty category because the domain is clean. Check it before reporting a clean result.

## Authorized use only

Use this only against a domain you own or have **written** authorization to assess.

## License

MIT — see [LICENSE](LICENSE).
