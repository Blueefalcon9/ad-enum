<# 
.SYNOPSIS
  ad-enum – Read-only Active Directory enumerator for security reviews.
.DESCRIPTION
  Collects key AD objects and flags common risky configurations. Outputs CSV/JSON.
  Requires: PowerShell 5+; Recommended: RSAT ActiveDirectory module. Falls back to ADSI when possible.
#>

[CmdletBinding()]
param(
  [string]$Domain = $null,
  [string]$Output = "output",
  [switch]$NoADModule  # Force ADSI-only mode
)

function Ensure-Output {
  param([string]$Path)
  if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType Directory | Out-Null }
}

function Export-Data {
  param(
    [Parameter(Mandatory=$true)][object]$Data,
    [Parameter(Mandatory=$true)][string]$BaseName
  )
  Ensure-Output -Path $Output
  $csv = Join-Path $Output "$BaseName.csv"
  $json = Join-Path $Output "$BaseName.json"
  $Data | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
  $Data | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 -FilePath $json
  Write-Host "[*] Saved $csv; $json" -ForegroundColor Cyan
}

function Have-ADModule {
  if ($NoADModule) { return $false }
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    return $true
  } catch { return $false }
}

$usingAD = Have-ADModule
if ($usingAD) {
  if ($Domain) { try { Set-ADServerSettings -ViewEntireForest $true } catch {} }
  Write-Host "[*] Using ActiveDirectory module." -ForegroundColor Green
} else {
  Write-Host "[!] ActiveDirectory module unavailable. Using ADSI fallback where possible." -ForegroundColor Yellow
}

# ------------------------
# Helpers
# ------------------------
function Get-CurrentDomainDN {
  if ($Domain) {
    return "DC=" + ($Domain -replace "\.",",DC=")
  } else {
    return ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetDirectoryEntry().distinguishedName
  }
}

$domainDN = Get-CurrentDomainDN

# ------------------------
# Domain / Forest / DCs
# ------------------------
$info = [System.Collections.Generic.List[object]]::new()
try {
  $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
  $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
  $info.Add([pscustomobject]@{
    Forest = $forest.Name
    ForestFunctionalLevel = $forest.ForestMode
    Domain = $d.Name
    DomainFunctionalLevel = $d.DomainMode
    DCs = ($d.DomainControllers | ForEach-Object { $_.Name }) -join ";"
  })
} catch {
  $info.Add([pscustomobject]@{ Forest=""; ForestFunctionalLevel=""; Domain=$Domain; DomainFunctionalLevel=""; DCs="" })
}
Export-Data -Data $info -BaseName "domain_forest_info"

# ------------------------
# Trusts
# ------------------------
try {
  if ($usingAD) {
    $trusts = (Get-ADTrust -Filter * -Server $Domain -ErrorAction SilentlyContinue) | Select-Object Name,Source,Target,Direction,TrustType,IsTransitive
    Export-Data -Data $trusts -BaseName "trusts"
  }
} catch {}

# ------------------------
# Admin groups flatten
# ------------------------
function Expand-GroupMembers {
  param([string]$GroupSam)
  if ($usingAD) {
    $members = Get-ADGroupMember -Identity $GroupSam -Recursive -ErrorAction SilentlyContinue | 
      Select-Object Name,SamAccountName,objectClass,DistinguishedName
    return $members
  } else {
    return @()
  }
}
$da = Expand-GroupMembers -GroupSam "Domain Admins"
$ea = Expand-GroupMembers -GroupSam "Enterprise Admins"
Export-Data -Data $da -BaseName "domain_admins"
Export-Data -Data $ea -BaseName "enterprise_admins"

# ------------------------
# SPN users & AS-REP roastables
# ------------------------
if ($usingAD) {
  $spnUsers = Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties servicePrincipalName |
    Select-Object SamAccountName,DistinguishedName,@{n="SPNs";e={$_.servicePrincipalName -join ";"}}
  Export-Data -Data $spnUsers -BaseName "users_with_spn"

  $asrep = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth |
    Select-Object SamAccountName,DistinguishedName,Enabled,DoesNotRequirePreAuth
  Export-Data -Data $asrep -BaseName "users_asrep_enabled"
}

# ------------------------
# Delegation (unconstrained, constrained, RBCD)
# ------------------------
if ($usingAD) {
  $unconstrained = Get-ADComputer -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" -Properties userAccountControl |
    Select-Object Name,SamAccountName,DN:DistinguishedName
  Export-Data -Data $unconstrained -BaseName "computers_unconstrained_delegation"

  $constrained = Get-ADComputer -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo |
    Select-Object Name,SamAccountName,@{n="AllowedToDelegateTo";e={$_. "msDS-AllowedToDelegateTo" -join ";"}},DistinguishedName
  Export-Data -Data $constrained -BaseName "computers_constrained_delegation"

  # RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
  $rbcd = Get-ADComputer -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Select-Object Name,SamAccountName,DistinguishedName
  Export-Data -Data $rbcd -BaseName "computers_rbcd"
}

# ------------------------
# Password policy indicators
# ------------------------
if ($usingAD) {
  $pwdFlags = Get-ADUser -Filter * -Properties PasswordNeverExpires,PasswordNotRequired,pwdLastSet,Enabled |
    Select-Object SamAccountName,Enabled,PasswordNeverExpires,PasswordNotRequired,pwdLastSet
  Export-Data -Data $pwdFlags -BaseName "users_password_flags"
}

# ------------------------
# LAPS policy presence & Delegation on computers
# ------------------------
if ($usingAD) {
  $laps = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime |
    Select-Object Name,SamAccountName,@{n="LAPS_Expiry";e={$_. "ms-Mcs-AdmPwdExpirationTime"}}
  Export-Data -Data $laps -BaseName "computers_laps_state"
}

# ------------------------
# GPP cpassword discovery in SYSVOL (read-only)
# ------------------------
try {
  $sysvol = "\\$(([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner.Name)\SYSVOL"
  if (Test-Path $sysvol) {
    $gpp = Get-ChildItem -Path $sysvol -Recurse -Filter *.xml -ErrorAction SilentlyContinue |
      Where-Object { Select-String -Path $_.FullName -Pattern "cpassword" -SimpleMatch -Quiet }
    $out = foreach ($f in $gpp) {
      [pscustomobject]@{ File=$f.FullName }
    }
    if ($out) { Export-Data -Data $out -BaseName "sysvol_gpp_cpassword_refs" }
  }
} catch {}

Write-Host "[+] Enumeration complete. Review the CSV/JSON in '$Output'." -ForegroundColor Green
