# Infrastructure

- Mail server/relay to send emails
- Proxy/VPN 
- Proxy/VPN in non-standard geolocation
- HTTP/S file hosting server 
- Command-and-control server(s) with HTTPS and HTTP channels
- Accounts for : Cloud storage provider (exfil), remote assistance service (if applicable)
- Domain(s) and certificate(s) for infrastructure
- MQTT broker

## Payloads

|#|Test Case|Payload|Notes|
|---|---|---|---|
|1|Attachment - ISO|ISO||
|2|Link - Zipped DLL via sharing|DLL in zip||
|3|Attachment - Macro|Macro-enabled Office document||
|4|Macro - Remote Template|Office document that loads remotely-hosted macro-enabled template||
|5|Load known-abusable kernel driver|Windows driver|refer to notebook for example drivers + hashes|
|6|DLL execution using Rundll32|DLL||
|7|Sideload a DLL into a legitimate application|DLL|can be shared with #6 as long as exported functions are as expected|
|8|Register Security Service Provider (SSP) in LSASS|SSP DLL|refer to notebook for instructions on creating DLL|
|9|<Exfiltration>|Sensitive data|Use dlptest.com for sample data|

# Tools/Scripts

- Remote assistance tool such as TeamViewer, GoTo, or AnyConnect
- SharpHound : https://github.com/BloodHoundAD/SharpHound
- AADInternals : https://github.com/Gerenios/AADInternals
- Mimikatz : https://github.com/gentilkiwi/mimikatz
- Rubeus : https://github.com/GhostPack/Rubeus
- ProcDump : https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
- Nanodump : https://github.com/fortra/nanodump
- SharpDPAPI : https://github.com/GhostPack/SharpDPAPI
- File encryptor : https://github.com/2XXE-SRA/payload_resources/tree/master/coldencryptor
