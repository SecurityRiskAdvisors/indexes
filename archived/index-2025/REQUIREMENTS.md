# Infrastructure

- Mail server/relay to send emails
- Proxy/VPN in non-standard geolocation
- HTTP/S file hosting server
- Command-and-control server(s) with HTTPS and HTTP channels
- Accounts for : Cloud storage providers, remote assistance services
- Domain(s) and certificate(s) for infrastructure 
- HTTPS AitM proxy server (e.g. [Evilginx](https://github.com/kgretzky/evilginx2))
- An IaaS (AWS/Azure) tenant

# Payloads

- DLL payload for `DLL execution using Rundll32`
- DLL payload for `Sideload a DLL into a legitimate application`. 
  - This can be the same as the previous DLL payload as long as the appropriate exports are present
- Macro-enabled Office document for `Attachment - Macro`
- HTML file with file smuggling JavaScript for `Attachment - Smuggle ISO file in HTML`

# Tools/Scripts

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
