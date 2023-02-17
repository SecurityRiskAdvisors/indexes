# Infrastructure

- Mail server/relay to send emails
- Proxy/VPN 
- Proxy/VPN in non-standard geolocation
- HTTP/S file hosting server  
- Command-and-control server(s) with HTTPS, HTTP, and DNS TXT channels
- Accounts for : MEGA
- Domain(s) and certificate(s) for external infrastructure

# Payloads

|#|Test Case|Payload|Notes|
|---|---|---|---|
|1|Link - Zipped VBScript|VBScript in ZIP||
|2|Link - ISO|ISO||
|3|Attachment - Zipped ISO|ISO in ZIP||
|4|Attachment - Zipped macro|Macro-enabled Office doc in ZIP||
|5|Link - Smuggle ISO file in HTML|HTML smuggled ISO|Hosted on file server|
|6|Process creation using exe|Exe||
|7|Process creation using VBScript|VBScript||
|8|Macro - HTA dropper|Macro-enabled Office doc that creates and execute HTA||
|9|Execution using Office macro|Macro-enabled Office doc|shared with #2|
|10|Process creation using HTA|HTA|shared with #7|
|11|DLL execution using Rundll32|DLL||
|12|Execution using Office macro|Macro-enabled Office doc|shared with #3|
|13|Process creation using Regsvr32 and DLL|DLL|shared with #9|
|14|Persist via new Windows service created in Registry|Service DLL||

# Tools/Scripts

- AAD Internals PowerShell : https://aadinternals.com/aadinternals/
- Service creation batch script : https://github.com/2XXE-SRA/payload_resources/blob/master/batch/apt41.bat
- 7zip portable : https://www.7-zip.org/download.html
- File encryptor : https://github.com/2XXE-SRA/payload_resources/tree/master/coldencryptor
- Rubeus : https://github.com/GhostPack/Rubeus
- Process Hacker : https://processhacker.sourceforge.io/
- ProcDump : https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
- SharpChrome : https://github.com/GhostPack/SharpDPAPI
- Rclone : https://rclone.org/downloads/
- SessionGopher : https://github.com/Arvanaghi/SessionGopher
- AD Explorer : https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
