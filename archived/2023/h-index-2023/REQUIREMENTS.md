# Infrastructure

- Mail server/relay to send emails
- Proxy/VPN 
- HTTP/S file hosting server  
- Command-and-control server(s) with HTTPS, HTTP, and DNS TXT channels
- Accounts for : MEGA
- Domain(s) and certificate(s) for external infrastructure

# Payloads

|#|Test Case|Payload|Notes|
|---|---|---|---|
|1|Attachment - Zipped JScript|JScript in ZIP||
|2|Attachment - Macro in encrypted archive|Macro-enabled Office doc in password-protected ZIP||
|3|Attachment - Zipped ISO|ISO in ZIP||
|4|Link - Smuggle ISO file in HTML|HTML smuggled ISO|Hosted on file server|
|5|Link - ISO|ISO||
|6|Macro - HTA dropper|Macro-enabled Office doc that creates and execute HTA||
|7|Execution using Office macro|Macro-enabled Office doc||
|8|Process creation using exe|Exe||
|9|Process creation using HTA|HTA|shared with #6|
|10|DLL execution using Rundll32|DLL||
|11|Execution using odbcconf.exe and RSP file|DLL & RSP file|DLL shared with #11|
|12|Process creation using Regsvr32 and DLL|DLL|shared with #9|
|13|Persist via new Windows service created in Registry|Service DLL||
|14|Extract data to MEGA using Rclone|Sensitive data||
|15|Extract sensitive data over HTTP C2|Sensitive data|shared with #12|


# Tools/Scripts

- Process Hacker : https://processhacker.sourceforge.io/
- ProcDump : https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
- SharpChrome : https://github.com/GhostPack/SharpDPAPI
- Service creation batch script : https://github.com/2XXE-SRA/payload_resources/blob/master/batch/apt41.bat
- Rclone : https://rclone.org/downloads/
- 7zip portable : https://www.7-zip.org/download.html
- File encryptor : https://github.com/2XXE-SRA/payload_resources/tree/master/coldencryptor


