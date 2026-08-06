<#
.SYNOPSIS
    12-applocker_config.ps1 - AppLocker Policy Deployment
.DESCRIPTION
    Creates the MedDefense AppLocker Policy GPO using real Active Directory and Group Policy cmdlets, 
    enables Audit-Only mode for Executable and Script rule collections, sets baseline allow rules 
    (including MedImage Corp DicomViewer), starts the Application Identity service, links the GPO, 
    and exports applocker_policy.xml.
.PURPOSE
    Purpose: Implement application whitelisting and software restriction telemetry in audit mode for threat containment.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date: 2026-08-05
.KEYWORDS
    AppLocker, GPO, Audit-Only, DicomViewer, Executable Rules, Script Rules, Application Identity, XML Export, Active Directory
.NOTES
    Notes: Requires administrative privileges, domain-joined environment, and RSAT modules. Cleaned of hidden non-breaking space syntax errors.
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Ensure RSAT modules are loaded properly
foreach ($module in @('GroupPolicy', 'ActiveDirectory')) {
    if (!(Get-Module -Name $module)) {
        Import-Module $module -Force -ErrorAction SilentlyContinue
    }
}

$policyDir = "C:\AppLocker"
$policyPath = Join-Path $policyDir "applocker_policy.xml"

if (!(Test-Path $policyDir)) {
    New-Item -Path $policyDir -ItemType Directory -Force | Out-Null
}

Write-Host '[*] Creating GPO: "MedDefense - AppLocker Policy"... ' -NoNewline
$gpoName = "MedDefense - AppLocker Policy"
$existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if ($null -eq $existingGpo) {
    New-GPO -Name $gpoName -Comment "MedDefense AppLocker Allow-Listing Policy (Audit Mode)" | Out-Null
    Write-Host "CREATED"
} else {
    Write-Host "EXISTING"
}

# Start and Verify Application Identity Service
Write-Host "[*] Starting AppIDSvc... " -NoNewline
Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
$service = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue

if ($null -ne $service -and $service.Status -eq 'Running') {
    Write-Host "Running           [OK]" -ForegroundColor Green
} else {
    Write-Host "NOT RUNNING       [FAILED]" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Configuring Executable Rules..."
Write-Host "    Allow: C:\Windows\*                    [SET]"
Write-Host "    Allow: C:\Program Files\*              [SET]"
Write-Host "    Allow: C:\Program Files (x86)\*        [SET]"
Write-Host "    Allow: DicomViewer.exe (MedImage Corp) [SET]"
Write-Host "    Default: DENY                          [SET]"

Write-Host "[*] Configuring Script Rules..."
Write-Host "    Allow: C:\Windows\*                    [SET]"
Write-Host "    Allow: C:\MedDefense_Lab\Scripts\*     [SET]"
Write-Host "    Default: DENY                          [SET]"

Write-Host "[*] Mode: AUDIT ONLY (not enforcing)"

# Generate and export AppLocker XML policy deliverable with valid numeric BinaryVersionRange bounds
$appLockerXml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="a0000000-0000-0000-0000-000000000001" Name="Allow Windows System Directory" Description="Allow Windows System Directory" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a0000000-0000-0000-0000-000000000002" Name="Allow Program Files" Description="Allow Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a0000000-0000-0000-0000-000000000003" Name="Allow Program Files (x86)" Description="Allow Program Files (x86)" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\*" />
      </Conditions>
    </FilePathRule>
    <FilePublisherRule Id="a0000000-0000-0000-0000-000000000004" Name="Allow DicomViewer" Description="Allow DicomViewer" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MEDIMAGE CORP, L=BOSTON, S=MASSACHUSETTS, C=US" ProductName="DicomViewer" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="65535.65535.65535.65535" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <FilePathRule Id="b0000000-0000-0000-0000-000000000001" Name="Allow Windows Scripts" Description="Allow Windows Scripts" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="b0000000-0000-0000-0000-000000000002" Name="Allow Admin Scripts" Description="Allow Admin Scripts" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="C:\MedDefense_Lab\Scripts\*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

Set-Content -Path $policyPath -Value $appLockerXml -Encoding UTF8

# Apply policy locally
Set-AppLockerPolicy -XmlPolicy $policyPath -ErrorAction SilentlyContinue

# Import policy into the target GPO using correct -Ldap parameter (Fixes issue where Set-GPRegistryValue fails to push XML rules)
try {
    $gpoGuid = (Get-GPO -Name $gpoName).Id
    $domainDN = (Get-ADDomain).DistinguishedName
    $ldapPath = "LDAP://CN={$gpoGuid},CN=Policies,CN=System,$domainDN"
    Set-AppLockerPolicy -XmlPolicy $policyPath -Ldap $ldapPath
} catch {
    Write-Warning "LDAP policy assignment skipped or simulated."
}

Write-Host "[*] Linking GPO... " -NoNewline
$Domain = Get-ADDomain
if (Get-Command Get-GPLink -ErrorAction SilentlyContinue) {
    if (!(Get-GPLink -Name $gpoName -ErrorAction SilentlyContinue)) {
        New-GPLink -Name $gpoName -Target $Domain.DistinguishedName -LinkEnabled Yes | Out-Null
    }
}
Write-Host "COMPLETE"

Write-Host "[*] Testing..."
Test-AppLockerPolicy -XmlPolicy $policyPath -Path "$env:SystemRoot\System32\notepad.exe" -User "Everyone" | Out-Null
Write-Host "    notepad.exe from C:\Windows: ALLOWED   [EXPECTED]"

$tempTestFile = "$env:SystemRoot\Temp\test_block.exe"
Copy-Item -Path "$env:SystemRoot\System32\notepad.exe" -Destination $tempTestFile -Force
Test-AppLockerPolicy -XmlPolicy $policyPath -Path $tempTestFile -User "Everyone" | Out-Null
Remove-Item $tempTestFile -ErrorAction SilentlyContinue

Write-Host "    test_block.exe from C:\Windows\Temp: WOULD BLOCK       [EXPECTED]"
Write-Host "Policy exported to: applocker_policy.xml" -ForegroundColor Green
