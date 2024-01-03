# Infrastructure

- Mail server/relay to send emails
- Proxy/VPN 
- Proxy/VPN in non-standard geolocation
- HTTP/S file hosting server 
- Command-and-control server(s) with HTTPS and HTTP channels
- Accounts for : Cloud storage provider (exfil, sharing), remote assistance service (if applicable)
- Domain(s) and certificate(s) for infrastructure

## Payloads

|#|Test Case|Payload|Notes|
|---|---|---|---|
|1|Attachment - ISO|ISO||
|2|Attachment - Macro|Macro-enabled Office document||
|3|Link - Zipped DLL via sharing|DLL in zip||
|4|DLL execution using Rundll32|DLL||
|5|Sideload a DLL into a legitimate application|DLL|can be shared with #4 as long as exported functions are as expected|
|6|Load known-abusable kernel driver|Windows driver|refer to notebook for example drivers + hashes|
|7|Register Security Service Provider (SSP) in LSASS|SSP DLL|refer to notebook for instructions on creating DLL|
|8|<Exfiltration>|Sensitive data|Use dlptest.com for sample data|
|9|Macro - Remote Template|Office document that loads remotely-hosted macro-enabled template||


# Tools/Scripts

- Remote assistance tool such as TeamViewer, GoTo, or AnyConnect
- Net Scan : https://www.softperfect.com/products/networkscanner/
- SharpHound : https://github.com/BloodHoundAD/SharpHound
- SharpDPAPI : https://github.com/GhostPack/SharpDPAPI
- Rubeus : https://github.com/GhostPack/Rubeus
- Mimikatz : https://github.com/gentilkiwi/mimikatz
- Nanodump : https://github.com/fortra/nanodump
- ProcDump : https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
- File encryptor : https://github.com/2XXE-SRA/payload_resources/tree/master/coldencryptor
- AADInternals : https://github.com/Gerenios/AADInternals

