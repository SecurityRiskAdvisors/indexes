# Infrastructure

- Mail server/relay to send emails
- Proxy/VPN 
- Proxy/VPN in non-standard geolocation
- HTTP/S file hosting server  
- Command-and-control server(s) with HTTPS, HTTP, and DNS TXT channels
- Command-and-control channel over Dropbox
- Internal command-and-control over SMB
- Accounts for : Dropbox, NordVPN, MEGA
- Domain(s) and certificate(s) for external infrastructure

# Payloads

|#|Test Case|Payload|Notes|
|---|---|---|---|
|1|Link - ISO|ISO||
|2|Attachment - Zipped ISO|ISO in ZIP||
|3|Attachment - Zipped macro|Macro-enabled Office doc in ZIP||
|4|Link - Smuggle ISO file in HTML|HTML smuggled ISO|Hosted on file server|
|5|Process creation using exe|Exe||
|6|Process creation using LNK to execute exe|LNK that targets exe|shared with #5|
|7|Execution using Office macro|Macro-enabled Office doc|shared with #3|
|8|Macro - HTA dropper|Macro-enabled Office doc that creates and execute HTA||
|9|Persist via new Windows service created in Registry|Service DLL||
|10|Process creation using HTA|HTA|shared with #8|
|11|DLL execution using Rundll32|DLL||
|12|Execution using odbcconf.exe and RSP file|DLL & RSP file|DLL shared with #11|
|13|Process creation using Regsvr32 and DLL|DLL|shared with #11|
|14|Execution via DLL Search Order Hijacking|shared with #11|
|15|Extract sensitive data over HTTP|Sensitive data||
|16|Extract data to MEGA using Rclone|Sensitive data|shared with #15|

# Tools/Scripts

- Net Scan : https://www.softperfect.com/products/networkscanner/
- AdFind : http://www.joeware.net/freetools/tools/adfind/
- AdFind batch script : https://github.com/2XXE-SRA/payload_resources/blob/master/batch/bazar_adf.bat
- Service creation batch script : https://github.com/2XXE-SRA/payload_resources/blob/master/batch/apt41.bat
- reGeorg webshell : https://github.com/sensepost/reGeorg
- File encryptor : https://github.com/2XXE-SRA/payload_resources/tree/master/coldencryptor
- Rubeus : https://github.com/GhostPack/Rubeus
- NordVPN : https://nordvpn.com/download/
- ProcDump : https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
- SharpChrome : https://github.com/GhostPack/SharpDPAPI
- 7zip portable : https://www.7-zip.org/download.html
- Rclone : https://rclone.org/downloads/
