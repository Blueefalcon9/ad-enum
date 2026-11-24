<#
.SYNOPSIS
  ad-enum - read-only Active Directory enumerator for security configuration reviews.

.DESCRIPTION
  Collects AD objects and flags risky configurations, then correlates them into
  prioritised findings. Performs no writes, no password changes and no
  exploitation: every operation is an LDAP read or a SYSVOL file read.

  Output: one CSV and one JSON per category, plus findings.csv / findings.json
  holding the correlated, severity-ranked results.

.PARAMETER Domain
  Target domain FQDN. Defaults to the current domain.

.PARAMETER Output
  Output directory. Default: output

.PARAMETER Server
  Specific domain controller to query. Defaults to DC locator.

.PARAMETER Credential
  PSCredential for cross-domain or non-domain-joined use.

.PARAMETER NoADModule
  Force ADSI-only mode, skipping the RSAT ActiveDirectory module.

.PARAMETER SkipSysvol
  Skip the SYSVOL GPP sweep (the slowest step on large domains).

.PARAMETER PageSize
  LDAP page size for large result sets. Default: 1000

.EXAMPLE
  .\ad-enum.ps1 -Output .\client-ad

.EXAMPLE
  .\ad-enum.ps1 -Domain corp.example.com -Server dc01.corp.example.com -Credential (Get-Credential)

.NOTES
  Authorized use only. Run this only against a domain you own or have written
  permission to assess.
#>

[CmdletBinding()]
param(
  [string]$Domain,
  [string]$Output = "output",
  [string]$Server,
  [System.Management.Automation.PSCredential]$Credential,
  [switch]$NoADModule,
  [switch]$SkipSysvol,
  [int]$PageSize = 1000
)

$ErrorActionPreference = 'Continue'
$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:Stats    = [ordered]@{}

# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

function Write-Status {
  param([string]$Message, [string]$Level = 'Info')
  $colour = switch ($Level) {
    'Good' { 'Green' } 'Warn' { 'Yellow' } 'Bad' { 'Red' } 'Step' { 'Cyan' }
    default { 'Gray' }
  }
  $prefix = switch ($Level) {
    'Good' { '[+]' } 'Warn' { '[!]' } 'Bad' { '[-]' } 'Step' { '[*]' } default { '   ' }
  }
  Write-Host "$prefix $Message" -ForegroundColor $colour
}

function Add-Finding {
  <#  Severity: Critical | High | Medium | Low | Info  #>
  param(
    [Parameter(Mandatory)][string]$Severity,
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$Detail,
    [string]$Object = '',
    [string]$Recommendation = ''
  )
  $script:Findings.Add([pscustomobject]@{
    Severity       = $Severity
    Title          = $Title
    Object         = $Object
    Detail         = $Detail
    Recommendation = $Recommendation
  })
}

function Export-Data {
  param(
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Data,
    [Parameter(Mandatory)][string]$BaseName
  )
  if (-not (Test-Path $Output)) {
    New-Item -Path $Output -ItemType Directory -Force | Out-Null
  }
  $items = @($Data)
  $script:Stats[$BaseName] = $items.Count
  if ($items.Count -eq 0) {
    Write-Status "$BaseName : 0" 'Info'
    return
  }
  $csv  = Join-Path $Output "$BaseName.csv"
  $json = Join-Path $Output "$BaseName.json"
  try {
    $items | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
    $items | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 -FilePath $json
    Write-Status "$BaseName : $($items.Count)" 'Good'
  } catch {
    Write-Status "Failed to write ${BaseName}: $($_.Exception.Message)" 'Bad'
  }
}

# Common splat for every AD cmdlet, so -Server/-Credential are honoured everywhere.
$script:ADArgs = @{}
if ($Server)     { $script:ADArgs['Server'] = $Server }
elseif ($Domain) { $script:ADArgs['Server'] = $Domain }
if ($Credential) { $script:ADArgs['Credential'] = $Credential }

function Test-ADModule {
  if ($NoADModule) { return $false }
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    return $true
  } catch {
    return $false
  }
}

$usingAD = Test-ADModule
if ($usingAD) {
  Write-Status "ActiveDirectory module loaded." 'Good'
} else {
  Write-Status "ActiveDirectory module unavailable - ADSI fallback (reduced coverage)." 'Warn'
}

# ---------------------------------------------------------------------------
# Domain / forest
# ---------------------------------------------------------------------------

Write-Status "Collecting domain and forest information" 'Step'

$domainObj = $null
$forestObj = $null
try {
  if ($usingAD) {
    $domainObj = Get-ADDomain @script:ADArgs -ErrorAction Stop
    $forestObj = Get-ADForest @script:ADArgs -ErrorAction Stop
  }
} catch {
  Write-Status "Get-ADDomain/Forest failed: $($_.Exception.Message)" 'Warn'
}

if (-not $domainObj) {
  try {
    $ctxType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
    $ctx = if ($Domain) {
      New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($ctxType, $Domain)
    } else { $null }
    $d = if ($ctx) {
      [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
    } else {
      [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
    $domainObj = [pscustomobject]@{
      DNSRoot           = $d.Name
      DomainMode        = $d.DomainMode
      DistinguishedName = $d.GetDirectoryEntry().distinguishedName
      PDCEmulator       = $d.PdcRoleOwner.Name
    }
  } catch {
    Write-Status "Cannot determine the domain. Supply -Domain and/or -Credential." 'Bad'
  }
}

$domainDN = if ($domainObj) { $domainObj.DistinguishedName }
            elseif ($Domain) { "DC=" + ($Domain -replace '\.', ',DC=') }
            else { $null }

if (-not $domainDN) {
  Write-Status "No domain DN resolved - aborting." 'Bad'
  exit 1
}
Write-Status "Domain DN: $domainDN" 'Info'

$dcList = @()
try {
  if ($usingAD) {
    $dcList = Get-ADDomainController -Filter * @script:ADArgs -ErrorAction Stop |
      Select-Object Name, HostName, IPv4Address, Site, OperatingSystem,
                    IsGlobalCatalog, IsReadOnly
  }
} catch { }

Export-Data -Data ([pscustomobject]@{
  Forest                = if ($forestObj) { $forestObj.Name } else { '' }
  ForestFunctionalLevel = if ($forestObj) { $forestObj.ForestMode } else { '' }
  Domain                = $domainObj.DNSRoot
  DomainFunctionalLevel = $domainObj.DomainMode
  DomainDN              = $domainDN
  PDCEmulator           = $domainObj.PDCEmulator
  DomainControllers     = ($dcList | ForEach-Object { $_.HostName }) -join ';'
}) -BaseName "domain_forest_info"

Export-Data -Data $dcList -BaseName "domain_controllers"

# Functional level below 2016 means no modern Kerberos hardening options.
if ($domainObj.DomainMode -and "$($domainObj.DomainMode)" -match '2000|2003|2008|2012') {
  Add-Finding -Severity 'Medium' -Title 'Legacy domain functional level' `
    -Object "$($domainObj.DNSRoot)" `
    -Detail "Domain functional level is $($domainObj.DomainMode)." `
    -Recommendation 'Raise to WinThreshold (2016) or later to enable modern Kerberos and LAPS protections.'
}

foreach ($dc in $dcList) {
  if ($dc.OperatingSystem -and $dc.OperatingSystem -match '2003|2008|2012') {
    Add-Finding -Severity 'High' -Title 'Domain controller on an unsupported OS' `
      -Object $dc.HostName -Detail "DC runs $($dc.OperatingSystem)." `
      -Recommendation 'Upgrade or decommission. Unsupported DCs receive no security updates.'
  }
}

# ---------------------------------------------------------------------------
# Trusts
# ---------------------------------------------------------------------------

Write-Status "Collecting trusts" 'Step'
$trusts = @()
if ($usingAD) {
  try {
    $trusts = Get-ADTrust -Filter * @script:ADArgs -ErrorAction Stop |
      Select-Object Name, Source, Target, Direction, TrustType, IntraForest,
                    IsTransitive, SIDFilteringQuarantined, SelectiveAuthentication
  } catch {
    Write-Status "Get-ADTrust failed: $($_.Exception.Message)" 'Warn'
  }
}
Export-Data -Data $trusts -BaseName "trusts"

foreach ($t in $trusts) {
  if (-not $t.IntraForest -and $t.SIDFilteringQuarantined -eq $false) {
    Add-Finding -Severity 'High' -Title 'External trust without SID filtering' `
      -Object $t.Target `
      -Detail "Trust to $($t.Target) ($($t.Direction), $($t.TrustType)) has SID filtering disabled." `
      -Recommendation 'Enable SID filtering; without it the trusted domain can inject privileged SIDs.'
  }
}

# ---------------------------------------------------------------------------
# Privileged groups
# ---------------------------------------------------------------------------

Write-Status "Flattening privileged group membership" 'Step'

$privilegedGroups = @(
  'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
  'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
  'DnsAdmins', 'Group Policy Creator Owners', 'Cert Publishers'
)

$allPrivMembers = [System.Collections.Generic.List[object]]::new()
foreach ($groupName in $privilegedGroups) {
  if (-not $usingAD) { break }
  try {
    $grp = Get-ADGroup -Identity $groupName @script:ADArgs -ErrorAction Stop
  } catch {
    continue
  }
  try {
    $members = Get-ADGroupMember -Identity $grp -Recursive @script:ADArgs -ErrorAction Stop
  } catch {
    Write-Status "Could not expand ${groupName}: $($_.Exception.Message)" 'Warn'
    continue
  }
  foreach ($m in $members) {
    $enabled = $null
    if ($m.objectClass -eq 'user') {
      try { $enabled = (Get-ADUser -Identity $m.DistinguishedName -Properties Enabled @script:ADArgs).Enabled } catch { }
    }
    $allPrivMembers.Add([pscustomobject]@{
      Group             = $groupName
      Name              = $m.Name
      SamAccountName    = $m.SamAccountName
      ObjectClass       = $m.objectClass
      Enabled           = $enabled
      DistinguishedName = $m.DistinguishedName
    })
  }
}
Export-Data -Data $allPrivMembers -BaseName "privileged_group_members"

# Nested computer objects in privileged groups are almost always a mistake.
foreach ($m in ($allPrivMembers | Where-Object { $_.ObjectClass -eq 'computer' })) {
  Add-Finding -Severity 'High' -Title 'Computer account in a privileged group' `
    -Object $m.SamAccountName `
    -Detail "Computer $($m.SamAccountName) is a member of $($m.Group)." `
    -Recommendation 'Remove. Anyone with local SYSTEM on that host inherits the group rights.'
}

$daCount = @($allPrivMembers | Where-Object { $_.Group -eq 'Domain Admins' -and $_.ObjectClass -eq 'user' }).Count
if ($daCount -gt 10) {
  Add-Finding -Severity 'Medium' -Title 'Large Domain Admins membership' `
    -Object 'Domain Admins' -Detail "$daCount user accounts are effective members of Domain Admins." `
    -Recommendation 'Reduce to a minimal, audited set; use tiered administration.'
}

foreach ($g in @('Account Operators','Print Operators','Server Operators','DnsAdmins')) {
  $n = @($allPrivMembers | Where-Object { $_.Group -eq $g }).Count
  if ($n -gt 0) {
    Add-Finding -Severity 'High' -Title "Members present in $g" -Object $g `
      -Detail "$g has $n member(s). This group grants a well-known privilege escalation path." `
      -Recommendation "Empty $g unless there is a documented need."
  }
}

# ---------------------------------------------------------------------------
# Users: Kerberos exposure and password flags
# ---------------------------------------------------------------------------

Write-Status "Collecting user accounts (paged)" 'Step'

$userProps = @(
  'SamAccountName','DistinguishedName','Enabled','servicePrincipalName',
  'DoesNotRequirePreAuth','PasswordNeverExpires','PasswordNotRequired',
  'pwdLastSet','LastLogonDate','AdminCount','TrustedForDelegation',
  'msDS-AllowedToDelegateTo','userAccountControl','whenCreated','Description',
  'msDS-SupportedEncryptionTypes','SIDHistory'
)

$users = @()
if ($usingAD) {
  try {
    $users = Get-ADUser -Filter * -Properties $userProps -ResultPageSize $PageSize `
               @script:ADArgs -ErrorAction Stop
  } catch {
    Write-Status "Get-ADUser failed: $($_.Exception.Message)" 'Bad'
  }
}
Write-Status "Enumerated $($users.Count) user object(s)" 'Info'

$now = Get-Date

function Get-PwdAge {
  param($PwdLastSet)
  if (-not $PwdLastSet) { return $null }
  try {
    $dt = if ($PwdLastSet -is [datetime]) { $PwdLastSet }
          else { [datetime]::FromFileTime([int64]$PwdLastSet) }
    if ($dt.Year -lt 1700) { return $null }
    return [int]($now - $dt).TotalDays
  } catch { return $null }
}

# --- kerberoastable ---------------------------------------------------------
$spnUsers = foreach ($u in ($users | Where-Object { $_.servicePrincipalName })) {
  [pscustomobject]@{
    SamAccountName = $u.SamAccountName
    Enabled        = $u.Enabled
    SPNs           = ($u.servicePrincipalName -join ';')
    AdminCount     = $u.AdminCount
    PasswordAgeDays = Get-PwdAge $u.pwdLastSet
    EncryptionTypes = $u.'msDS-SupportedEncryptionTypes'
    Description    = $u.Description
    DistinguishedName = $u.DistinguishedName
  }
}
Export-Data -Data $spnUsers -BaseName "users_kerberoastable_spn"

foreach ($s in ($spnUsers | Where-Object { $_.Enabled -and $_.AdminCount -eq 1 })) {
  Add-Finding -Severity 'Critical' -Title 'Kerberoastable privileged account' `
    -Object $s.SamAccountName `
    -Detail "Enabled account with an SPN and AdminCount=1 (SPNs: $($s.SPNs)). Its TGS can be requested by any domain user and cracked offline, yielding privileged credentials." `
    -Recommendation 'Move to a group-managed service account (gMSA), or set a 25+ character random password and remove AdminCount.'
}
foreach ($s in ($spnUsers | Where-Object { $_.Enabled -and $_.AdminCount -ne 1 -and $_.PasswordAgeDays -gt 365 })) {
  Add-Finding -Severity 'High' -Title 'Kerberoastable account with a stale password' `
    -Object $s.SamAccountName `
    -Detail "Enabled SPN account; password last set $($s.PasswordAgeDays) days ago." `
    -Recommendation 'Rotate to a long random password or migrate to a gMSA.'
}
# RC4-only service accounts weaken offline cracking resistance.
foreach ($s in ($spnUsers | Where-Object { $_.Enabled -and ($_.EncryptionTypes -eq $null -or $_.EncryptionTypes -eq 0 -or ($_.EncryptionTypes -band 0x18) -eq 0) })) {
  Add-Finding -Severity 'Medium' -Title 'Service account without AES Kerberos encryption' `
    -Object $s.SamAccountName `
    -Detail "msDS-SupportedEncryptionTypes does not advertise AES, so RC4 TGS tickets can be issued and cracked faster." `
    -Recommendation 'Set msDS-SupportedEncryptionTypes to AES128+AES256 (0x18) after confirming service support.'
}

# --- AS-REP roastable -------------------------------------------------------
$asrep = foreach ($u in ($users | Where-Object { $_.DoesNotRequirePreAuth })) {
  [pscustomobject]@{
    SamAccountName = $u.SamAccountName
    Enabled        = $u.Enabled
    AdminCount     = $u.AdminCount
    PasswordAgeDays = Get-PwdAge $u.pwdLastSet
    DistinguishedName = $u.DistinguishedName
  }
}
Export-Data -Data $asrep -BaseName "users_asrep_roastable"

foreach ($a in ($asrep | Where-Object { $_.Enabled })) {
  $sev = if ($a.AdminCount -eq 1) { 'Critical' } else { 'High' }
  Add-Finding -Severity $sev -Title 'AS-REP roastable account' -Object $a.SamAccountName `
    -Detail "Kerberos pre-authentication is disabled, so an encrypted AS-REP can be requested without credentials and cracked offline." `
    -Recommendation 'Re-enable pre-authentication (clear DONT_REQ_PREAUTH).'
}

# --- password flags ---------------------------------------------------------
$pwdFlags = foreach ($u in $users) {
  [pscustomobject]@{
    SamAccountName       = $u.SamAccountName
    Enabled              = $u.Enabled
    PasswordNeverExpires = $u.PasswordNeverExpires
    PasswordNotRequired  = $u.PasswordNotRequired
    PasswordAgeDays      = Get-PwdAge $u.pwdLastSet
    LastLogonDate        = $u.LastLogonDate
    AdminCount           = $u.AdminCount
    HasSIDHistory        = [bool]$u.SIDHistory
    DistinguishedName    = $u.DistinguishedName
  }
}
Export-Data -Data $pwdFlags -BaseName "users_password_flags"

foreach ($u in ($pwdFlags | Where-Object { $_.Enabled -and $_.PasswordNotRequired })) {
  Add-Finding -Severity 'Critical' -Title 'Account with PASSWD_NOTREQD' -Object $u.SamAccountName `
    -Detail "Enabled account may have an empty password; authentication can succeed with no secret." `
    -Recommendation 'Clear PASSWD_NOTREQD and force a password reset.'
}
foreach ($u in ($pwdFlags | Where-Object { $_.Enabled -and $_.AdminCount -eq 1 -and $_.PasswordNeverExpires })) {
  Add-Finding -Severity 'High' -Title 'Privileged account with a non-expiring password' `
    -Object $u.SamAccountName -Detail "AdminCount=1 and PasswordNeverExpires is set; password age $($u.PasswordAgeDays) days." `
    -Recommendation 'Enforce rotation on privileged accounts, or move the workload to a gMSA.'
}
foreach ($u in ($pwdFlags | Where-Object { $_.Enabled -and $_.HasSIDHistory })) {
  Add-Finding -Severity 'Medium' -Title 'Account with SID history' -Object $u.SamAccountName `
    -Detail "SIDHistory is populated. If it contains a privileged SID it grants that access invisibly." `
    -Recommendation 'Review SIDHistory contents and clear it once migration is complete.'
}

# Stale enabled accounts widen the attack surface and are prime spray targets.
$stale = $pwdFlags | Where-Object {
  $_.Enabled -and $_.LastLogonDate -and (($now - $_.LastLogonDate).TotalDays -gt 180)
}
Export-Data -Data $stale -BaseName "users_stale_enabled"
if (@($stale).Count -gt 0) {
  Add-Finding -Severity 'Medium' -Title 'Stale but enabled user accounts' -Object 'Domain users' `
    -Detail "$(@($stale).Count) enabled account(s) have not logged on in over 180 days." `
    -Recommendation 'Disable or remove. Dormant enabled accounts are preferred password-spray targets.'
}

# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------

Write-Status "Collecting delegation configuration" 'Step'

$computerProps = @(
  'SamAccountName','DistinguishedName','DNSHostName','OperatingSystem',
  'OperatingSystemVersion','userAccountControl','TrustedForDelegation',
  'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity',
  'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime',
  'PrimaryGroupID','LastLogonDate','whenCreated','Enabled'
)

$computers = @()
if ($usingAD) {
  try {
    $computers = Get-ADComputer -Filter * -Properties $computerProps `
                   -ResultPageSize $PageSize @script:ADArgs -ErrorAction Stop
  } catch {
    Write-Status "Get-ADComputer failed: $($_.Exception.Message)" 'Bad'
  }
}
Write-Status "Enumerated $($computers.Count) computer object(s)" 'Info'

$dcNames = @($dcList | ForEach-Object { $_.Name })

# --- unconstrained ----------------------------------------------------------
$unconstrained = foreach ($c in ($computers | Where-Object { $_.TrustedForDelegation })) {
  [pscustomobject]@{
    Name              = $c.Name
    SamAccountName    = $c.SamAccountName
    DNSHostName       = $c.DNSHostName
    OperatingSystem   = $c.OperatingSystem
    IsDomainController = ($dcNames -contains $c.Name)
    DistinguishedName = $c.DistinguishedName
  }
}
Export-Data -Data $unconstrained -BaseName "computers_unconstrained_delegation"

foreach ($c in ($unconstrained | Where-Object { -not $_.IsDomainController })) {
  Add-Finding -Severity 'Critical' -Title 'Unconstrained delegation on a non-DC host' `
    -Object $c.SamAccountName `
    -Detail "$($c.DNSHostName) is trusted for unconstrained delegation. Compromise of this host captures the TGT of any user or computer that authenticates to it, including a DC if coerced." `
    -Recommendation 'Replace with constrained or resource-based constrained delegation, and add privileged users to Protected Users.'
}

# --- constrained ------------------------------------------------------------
$constrained = foreach ($c in ($computers | Where-Object { $_.'msDS-AllowedToDelegateTo' })) {
  [pscustomobject]@{
    Name                = $c.Name
    SamAccountName      = $c.SamAccountName
    AllowedToDelegateTo = ($c.'msDS-AllowedToDelegateTo' -join ';')
    ProtocolTransition  = [bool]($c.userAccountControl -band 0x1000000)
    DistinguishedName   = $c.DistinguishedName
  }
}
Export-Data -Data $constrained -BaseName "computers_constrained_delegation"

foreach ($c in ($constrained | Where-Object { $_.ProtocolTransition })) {
  Add-Finding -Severity 'High' -Title 'Constrained delegation with protocol transition' `
    -Object $c.SamAccountName `
    -Detail "TRUSTED_TO_AUTH_FOR_DELEGATION is set (delegates to: $($c.AllowedToDelegateTo)). The host can impersonate arbitrary users to those services without their involvement." `
    -Recommendation 'Remove protocol transition (use Kerberos-only constrained delegation) where possible.'
}

# Constrained delegation to a DC service is effectively a path to domain compromise.
foreach ($c in $constrained) {
  foreach ($spn in ($c.AllowedToDelegateTo -split ';')) {
    if ($spn -match '^(ldap|cifs|host)/' ) {
      $tgt = ($spn -split '/')[1] -replace '\..*$', ''
      if ($dcNames -contains $tgt) {
        Add-Finding -Severity 'Critical' -Title 'Constrained delegation to a domain controller' `
          -Object $c.SamAccountName `
          -Detail "$($c.SamAccountName) may delegate to $spn on a domain controller. This is a direct domain-compromise path." `
          -Recommendation 'Remove the delegation to DC services immediately.'
      }
    }
  }
}

# --- RBCD -------------------------------------------------------------------
$rbcd = foreach ($c in ($computers | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' })) {
  [pscustomobject]@{
    Name              = $c.Name
    SamAccountName    = $c.SamAccountName
    DistinguishedName = $c.DistinguishedName
    Note              = 'msDS-AllowedToActOnBehalfOfOtherIdentity is set; inspect the security descriptor for the principals allowed to impersonate.'
  }
}
Export-Data -Data $rbcd -BaseName "computers_rbcd"
foreach ($c in $rbcd) {
  Add-Finding -Severity 'Medium' -Title 'Resource-based constrained delegation configured' `
    -Object $c.SamAccountName `
    -Detail "Another principal is permitted to impersonate users to this computer. Review which principal: a writable RBCD attribute is a common escalation primitive." `
    -Recommendation 'Confirm the configured principal is intended and that non-admins cannot write this attribute.'
}

# ---------------------------------------------------------------------------
# LAPS
# ---------------------------------------------------------------------------

Write-Status "Checking LAPS coverage" 'Step'
$servers = $computers | Where-Object {
  $_.Enabled -and $_.OperatingSystem -and $_.OperatingSystem -notmatch 'Server' -and
  ($dcNames -notcontains $_.Name)
}
$lapsState = foreach ($c in ($computers | Where-Object { $_.Enabled -and ($dcNames -notcontains $_.Name) })) {
  $legacy = $c.'ms-Mcs-AdmPwdExpirationTime'
  $modern = $c.'msLAPS-PasswordExpirationTime'
  [pscustomobject]@{
    Name            = $c.Name
    OperatingSystem = $c.OperatingSystem
    LegacyLAPS      = [bool]$legacy
    WindowsLAPS     = [bool]$modern
    Managed         = ([bool]$legacy -or [bool]$modern)
    LastLogonDate   = $c.LastLogonDate
  }
}
Export-Data -Data $lapsState -BaseName "computers_laps_state"

$unmanaged = @($lapsState | Where-Object { -not $_.Managed })
if ($unmanaged.Count -gt 0 -and @($lapsState).Count -gt 0) {
  $pct = [math]::Round(100 * $unmanaged.Count / @($lapsState).Count, 1)
  $sev = if ($pct -gt 50) { 'High' } else { 'Medium' }
  Add-Finding -Severity $sev -Title 'Computers without a managed local administrator password' `
    -Object 'Domain computers' `
    -Detail "$($unmanaged.Count) of $(@($lapsState).Count) enabled non-DC computers ($pct%) have neither legacy LAPS nor Windows LAPS populated, so local admin passwords are likely shared and reusable for lateral movement." `
    -Recommendation 'Deploy Windows LAPS domain-wide and confirm password rotation.'
}

# ---------------------------------------------------------------------------
# krbtgt, machine account quota, Protected Users
# ---------------------------------------------------------------------------

Write-Status "Checking krbtgt, MachineAccountQuota and Protected Users" 'Step'

if ($usingAD) {
  try {
    $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties pwdLastSet, whenCreated `
                @script:ADArgs -ErrorAction Stop
    $age = Get-PwdAge $krbtgt.pwdLastSet
    Export-Data -Data ([pscustomobject]@{
      SamAccountName = 'krbtgt'; PasswordAgeDays = $age; WhenCreated = $krbtgt.whenCreated
    }) -BaseName "krbtgt_status"
    if ($age -and $age -gt 180) {
      Add-Finding -Severity 'High' -Title 'krbtgt password is stale' -Object 'krbtgt' `
        -Detail "The krbtgt password was last set $age days ago. A golden ticket forged from a previously stolen hash remains valid until this is rotated twice." `
        -Recommendation 'Rotate the krbtgt password twice, separated by at least one Kerberos ticket lifetime.'
    }
  } catch {
    Write-Status "krbtgt query failed: $($_.Exception.Message)" 'Warn'
  }

  try {
    $root = Get-ADObject -Identity $domainDN -Properties 'ms-DS-MachineAccountQuota' `
              @script:ADArgs -ErrorAction Stop
    $maq = $root.'ms-DS-MachineAccountQuota'
    Export-Data -Data ([pscustomobject]@{ MachineAccountQuota = $maq }) -BaseName "machine_account_quota"
    if ($maq -and [int]$maq -gt 0) {
      Add-Finding -Severity 'Medium' -Title 'MachineAccountQuota allows computer creation by any user' `
        -Object $domainDN `
        -Detail "ms-DS-MachineAccountQuota is $maq, so any authenticated user can join up to $maq computer accounts. This enables RBCD and shadow-credential escalation chains." `
        -Recommendation 'Set ms-DS-MachineAccountQuota to 0 and delegate machine creation to a specific group.'
    }
  } catch { }

  try {
    $pu = Get-ADGroupMember -Identity 'Protected Users' -Recursive @script:ADArgs -ErrorAction Stop
    Export-Data -Data ($pu | Select-Object Name, SamAccountName, objectClass) `
      -BaseName "protected_users_members"
    $privUsers = @($allPrivMembers | Where-Object { $_.ObjectClass -eq 'user' -and $_.Group -in @('Domain Admins','Enterprise Admins') })
    $puNames = @($pu | ForEach-Object { $_.SamAccountName })
    $unprotected = @($privUsers | Where-Object { $puNames -notcontains $_.SamAccountName })
    if ($unprotected.Count -gt 0) {
      Add-Finding -Severity 'Medium' -Title 'Domain/Enterprise Admins outside Protected Users' `
        -Object 'Protected Users' `
        -Detail "$($unprotected.Count) privileged account(s) are not in Protected Users, so their credentials can still be delegated and cached as NTLM/RC4." `
        -Recommendation 'Add tier-0 accounts to Protected Users after validating application compatibility.'
    }
  } catch {
    Write-Status "Protected Users not available: $($_.Exception.Message)" 'Info'
  }
}

# ---------------------------------------------------------------------------
# Dangerous ACLs on the domain root (DCSync)
# ---------------------------------------------------------------------------

Write-Status "Checking replication rights on the domain root (DCSync)" 'Step'

$dcsyncRights = @()
if ($usingAD) {
  try {
    $guidRepl    = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
    $guidReplAll = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # ...-Get-Changes-All
    $acl = Get-Acl -Path "AD:$domainDN" -ErrorAction Stop
    $builtins = 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|Domain Controllers|Enterprise Read-only Domain Controllers'
    foreach ($ace in $acl.Access) {
      if ($ace.AccessControlType -ne 'Allow') { continue }
      if ($ace.ObjectType -notin @($guidRepl, $guidReplAll)) { continue }
      if ($ace.IdentityReference -match $builtins) { continue }
      $dcsyncRights += [pscustomobject]@{
        Identity   = "$($ace.IdentityReference)"
        Right      = if ($ace.ObjectType -eq $guidReplAll) { 'DS-Replication-Get-Changes-All' }
                     else { 'DS-Replication-Get-Changes' }
        Inherited  = $ace.IsInherited
      }
    }
  } catch {
    Write-Status "Domain-root ACL read failed (AD: drive may be unavailable): $($_.Exception.Message)" 'Warn'
  }
}
Export-Data -Data $dcsyncRights -BaseName "dcsync_rights_non_default"

foreach ($r in $dcsyncRights) {
  Add-Finding -Severity 'Critical' -Title 'Non-default principal holds DCSync rights' `
    -Object $r.Identity `
    -Detail "$($r.Identity) holds $($r.Right) on the domain root, which allows replication of every account's password hashes (DCSync)." `
    -Recommendation 'Remove the replication rights unless this is a documented directory-sync service.'
}

# ---------------------------------------------------------------------------
# GPP cpassword in SYSVOL
# ---------------------------------------------------------------------------

if (-not $SkipSysvol) {
  Write-Status "Sweeping SYSVOL for Group Policy Preferences passwords" 'Step'

  # The AES-256 key for GPP cpassword was published by Microsoft in MS14-025,
  # so any cpassword value is recoverable plaintext, not a protected secret.
  $gppKey = [byte[]]@(
    0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
    0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
  )

  function Unprotect-Cpassword {
    param([string]$Cpassword)
    if ([string]::IsNullOrWhiteSpace($Cpassword)) { return $null }
    try {
      $pad = $Cpassword.Length % 4
      $b64 = if ($pad -gt 0) { $Cpassword + ('=' * (4 - $pad)) } else { $Cpassword }
      $bytes = [Convert]::FromBase64String($b64)
      $aes = [System.Security.Cryptography.Aes]::Create()
      $aes.Key = $gppKey
      $aes.IV  = New-Object byte[] 16
      $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
      $dec = $aes.CreateDecryptor()
      $plain = $dec.TransformFinalBlock($bytes, 0, $bytes.Length)
      $aes.Dispose()
      return [System.Text.Encoding]::Unicode.GetString($plain).TrimEnd([char]0)
    } catch {
      return "<decrypt failed: $($_.Exception.Message)>"
    }
  }

  $pdc = if ($domainObj.PDCEmulator) { $domainObj.PDCEmulator } else { $Domain }
  $sysvolRoot = "\\$pdc\SYSVOL"
  $gppResults = [System.Collections.Generic.List[object]]::new()

  # Only the GPP files that can carry cpassword, rather than every XML in SYSVOL.
  $gppFileNames = @('Groups.xml','Services.xml','ScheduledTasks.xml',
                    'DataSources.xml','Printers.xml','Drives.xml')

  if (Test-Path $sysvolRoot) {
    try {
      $policyPath = Join-Path $sysvolRoot "$($domainObj.DNSRoot)\Policies"
      $searchRoot = if (Test-Path $policyPath) { $policyPath } else { $sysvolRoot }
      $files = Get-ChildItem -Path $searchRoot -Recurse -Include $gppFileNames `
                 -File -ErrorAction SilentlyContinue
      foreach ($f in $files) {
        try {
          [xml]$xml = Get-Content -Path $f.FullName -Raw -ErrorAction Stop
        } catch { continue }
        $nodes = $xml.SelectNodes('//*[@cpassword]')
        foreach ($n in $nodes) {
          $cp = $n.GetAttribute('cpassword')
          if ([string]::IsNullOrWhiteSpace($cp)) { continue }
          $gppResults.Add([pscustomobject]@{
            File        = $f.FullName
            Element     = $n.LocalName
            UserName    = $n.GetAttribute('userName')
            NewName     = $n.GetAttribute('newName')
            RunAs       = $n.GetAttribute('runAs')
            Cpassword   = $cp
            Plaintext   = Unprotect-Cpassword $cp
            Changed     = $n.GetAttribute('changed')
          })
        }
      }
    } catch {
      Write-Status "SYSVOL sweep failed: $($_.Exception.Message)" 'Warn'
    }
  } else {
    Write-Status "SYSVOL not reachable at $sysvolRoot" 'Warn'
  }

  Export-Data -Data $gppResults -BaseName "sysvol_gpp_cpassword"

  foreach ($g in $gppResults) {
    Add-Finding -Severity 'Critical' -Title 'Group Policy Preferences password in SYSVOL' `
      -Object "$($g.UserName)" `
      -Detail "$($g.File) contains a cpassword for '$($g.UserName)'. The AES key is public (MS14-025), so this decrypts to plaintext and SYSVOL is readable by every authenticated user." `
      -Recommendation 'Delete the GPP item, rotate the exposed credential immediately, and treat it as compromised.'
  }
} else {
  Write-Status "SYSVOL sweep skipped (-SkipSysvol)" 'Info'
}

# ---------------------------------------------------------------------------
# Findings summary
# ---------------------------------------------------------------------------

Write-Status "Writing findings" 'Step'

$sevOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }
$sorted = $script:Findings | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Title
Export-Data -Data $sorted -BaseName "findings"

Export-Data -Data ([pscustomobject]$script:Stats) -BaseName "collection_stats"

Write-Host ""
Write-Host "================ ad-enum summary ================" -ForegroundColor Cyan
foreach ($sev in @('Critical','High','Medium','Low','Info')) {
  $n = @($script:Findings | Where-Object { $_.Severity -eq $sev }).Count
  if ($n -eq 0) { continue }
  $colour = switch ($sev) {
    'Critical' { 'Red' } 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' }
  }
  Write-Host ("  {0,-9} {1}" -f $sev, $n) -ForegroundColor $colour
}
Write-Host "=================================================" -ForegroundColor Cyan

foreach ($f in ($sorted | Where-Object { $_.Severity -in @('Critical','High') } | Select-Object -First 15)) {
  Write-Host ("  [{0}] {1} - {2}" -f $f.Severity, $f.Title, $f.Object) -ForegroundColor Red
}

Write-Host ""
Write-Status "Complete. CSV/JSON per category plus findings.csv in '$Output'." 'Good'
Write-Status "Flags are indicators, not confirmed findings - correlate before reporting." 'Info'
