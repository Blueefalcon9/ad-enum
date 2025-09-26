# ad-enum
Read-only Active Directory enumerator for security configuration reviews.

## Collects
- Domain/forest info, DCs, trusts
- Admin group membership (flattened)
- Users with SPNs / AS-REP preauth disabled
- Delegation (unconstrained, constrained, RBCD)
- Password flags (never expire, not required)
- LAPS state on computers
- GPP `cpassword` references in SYSVOL

## Output
- CSV and JSON per category into `output/`

## Usage
```powershell
.\ad-enum.ps1 -Output .\output
