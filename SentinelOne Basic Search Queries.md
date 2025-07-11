**Basic Queries**

**Basic Query Templates for Common IOCs**

<ins>Add UserHashes (MD5, SHA1, SHA256)
```
file.hash = "44d88612fea8a8f36de82e1278abb02f"
```
<ins>IP Addresses
```
network.dst_ip = "x.x.x.x"
network.src_ip = "x.x.x.x"
```
<ins>Domains
```
dns.query = "maliciousdomain.com"
```
<ins>URLs
```
network.http.url = "http://maliciousdomain.com/path"
```
<ins>File Names / Paths
```
file.name = "malware.exe"
file.path = "C:\\Users\\User\\AppData\\malware.exe"
```
<ins>Registry Keys
```
registry.key_path = "HKCU\\Software\\MaliciousKey"
```
<ins>Processes
```
process.name = "malicious.exe"
process.cmdline contains "suspicious_argument"
```
<ins>Parent-Child Process Relationships
```
process.parent.name = "powershell.exe" AND process.name = "cmd.exe"
```
<ins>PowerShell or Script Execution
```
process.name = "powershell.exe" AND process.cmdline contains "Invoke-WebRequest"
```
<ins>File Creation or Modification
```
file.operation = "create" AND file.path contains "temp"
```

**A bit more Advanced & Thematic Query Examples**

<ins>Persistence Mechanisms
```
registry.key_path contains "Run" AND registry.value_data contains "powershell"
```
```
file.path contains "Startup" AND file.name = "malicious.exe"
```

<ins>Lateral Movement
```
process.name = "wmic.exe" AND process.cmdline contains "process call create"
```
```
process.name = "psexec.exe"
```

<ins>Privilege Escalation
```
process.name = "cmd.exe" AND process.cmdline contains "net localgroup administrators"
```
```
process.name = "schtasks.exe" AND process.cmdline contains "/create"
```

<ins>Living off the Land Binaries (LOLBins)
```
process.name in ("mshta.exe", "regsvr32.exe", "rundll32.exe") AND process.cmdline contains "http"
```

<ins>Defense Evasion
```
process.name = "powershell.exe" AND process.cmdline contains "Bypass"
```
```
process.name = "vssadmin.exe" AND process.cmdline contains "delete shadows"
```

<ins>Suspicious PowerShell Usage
```
process.name = "powershell.exe" AND process.cmdline contains "IEX"
```
```
process.name = "powershell.exe" AND process.cmdline contains "DownloadString"
```

<ins>Encoded or Obfuscated Commands
```
process.cmdline contains "FromBase64String"
```
```
process.cmdline contains "JAB"  // Common in obfuscated PowerShell
```

<ins>Suspicious File Drops
```
file.operation = "create" AND file.path contains "\\AppData\\Local\\Temp\\"
```

<ins>Suspicious Network Connections
```
network.dst_port = 4444 OR network.dst_port = 3389
```
```
network.http.user_agent contains "curl" OR network.http.user_agent contains "python"
```

<ins>Suspicious DNS Queries
```
dns.query contains ".xyz" OR dns.query contains ".top"
```

<ins>Search for
```

```

<ins>Search for
```

```

<ins>Search for
```

```
