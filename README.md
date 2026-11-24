# ad-enum

![PowerShell](https://img.shields.io/badge/powershell-5%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Read-only Active Directory enumerator for security configuration reviews. Collects the objects and flags the
misconfigurations that matter in an AD assessment, and writes CSV plus JSON per category.

**Read-only by design.** The script performs no writes, no password changes, and no exploitation. It is built
to be safe to run during a configuration review on a production domain.

## What it collects

| Category | Detail |
|---|---|
| Domain / forest | Functional levels, domain controllers, trusts |
| Privileged groups | Admin group membership, recursively flattened |
| Kerberos exposure | Users with SPNs (kerberoastable), AS-REP preauth disabled |
| Delegation | Unconstrained, constrained, and resource-based constrained |
| Password policy flags | Never-expires, not-required |
| LAPS | Per-computer LAPS state |
| GPP credentials | `cpassword` references in SYSVOL |

## Requirements

- PowerShell 5 or later
- **Recommended:** RSAT ActiveDirectory module. Without it the script falls back to ADSI, which still works
  but collects less.
- A domain-joined context, or credentials for the target domain

## Usage

```powershell
.\ad-enum.ps1
.\ad-enum.ps1 -Output .\output
.\ad-enum.ps1 -Domain corp.example.com -NoADModule
```

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Domain` | current domain | Target domain |
| `-Output` | `output` | Output directory for CSV/JSON |
| `-NoADModule` | off | Force ADSI-only mode, skipping the RSAT module |

## Output

One `.csv` and one `.json` per category in the output directory.

## Reading the results

The flags are **indicators, not findings**. Service accounts legitimately hold SPNs; some accounts genuinely
need non-expiring passwords. What matters is the combination — a kerberoastable account that is also a member
of a privileged group is the finding, and that correlation is yours to make.

Any `cpassword` hit in SYSVOL is an immediate escalation regardless of context: the GPP encryption key is
public, so those credentials should be treated as already compromised.

## Authorized use only

Use this only against systems you own or have **written** authorization to test. Unauthorized scanning and
credential discovery are illegal in most jurisdictions. You are responsible for staying inside your
authorized scope.

## License

MIT — see [LICENSE](LICENSE).
