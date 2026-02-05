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
tgt.process.cmdline contains:matchcase "\"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Microsoft.Management.Services.IntuneWindowsAgent.exe\""
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

**THREAT HUNTING QUERIES**

**User Account Operations**

<ins>Search for Add User
```
ProcessCmd RegExp "net\s+user(?:(?!\s+/add)(?:.|\n))*\s+/add"
```
<ins>Search for Delete User
```
ProcessCmd RegExp "net\s+user(?:(?!\s+/delete)(?:.|\n))*\s+/delete"
```
<ins>Search for Domain User Query
```
ProcessCmd RegExp "net\s+user(?:(?!\s+/domain)(?:.|\n))*\s+/domain"
```
<ins>Search for Add User to AD
```
ProcessCmd ContainsCIS "dsadd user"
```
<ins>Search for Add Local User via PowerShell
```
ProcessCmd ContainsCIS "powershell.exe New-LocalUser"
```

**Authentication & Privilege Escalation**

<ins>Search for Query Local Admin Group
```
ProcessCmd ContainsCIS "net localgroup administrators"
```
<ins>Search for Whoami Command
```
ProcessCmd ContainsCIS "whoami"
```

**Suspicious PowerShell Activity**

<ins>Search for PowerShell with Network Connections
```
DstIP Is Not Empty AND ProcessName ContainsCIS "powershell"
```
<ins>Search for PowerShell Running as SYSTEM
```
ProcessName ContainsCIS "powershell" AND User ContainsCIS "SYSTEM"
```
<ins>Search for PowerShell Scheduled Task Creation
```
ParentProcessName = "Windows PowerShell" AND ProcessName = "Task Scheduler Configuration Tool"
```
<ins>Search for Suspicious PowerShell Commands
```
ProcessName ContainsCIS "powershell" AND (
  ProcessCmd ContainsCIS "Invoke-Expression" OR
  ProcessCmd ContainsCIS "-encodedcommand" OR
  ProcessCmd ContainsCIS "hidden" OR
  ProcessCmd ContainsCIS "write-host" OR
  ProcessCmd ContainsCIS "Get-NetIPConfiguration"
)
```

**File & Registry Operations**

<ins>Search for Shell Process Creating or Modifying Files
```
(ProcessName ContainsCIS "windows command processor" OR ProcessName ContainsCIS "powershell") AND
(FileModifyAt > "Mar 26, 2017 00:00:10" OR FileCreatedAt > "Mar 26, 2017 00:00:31")
```
<ins>Search for Registry Alteration via Command Line
```
ProcessCmd RegExp "reg\s+add" OR ProcessCmd RegExp "reg\s+del"
```
<ins>Search for Registry Persistence
```
ProcessCmd ContainsCIS "reg add" AND (ProcessCmd ContainsCIS "Run" OR ProcessCmd ContainsCIS "Null")
```

**Network & Reconnaissance**

<ins>Search for List SPNs in Domain
```
ProcessCmd ContainsCIS "setspn" AND ProcessCmd RegExp "-t" AND ProcessCmd RegExp "-q */*"
```
<ins>Search for Query Logged-in Users
```
ProcessCmd ContainsCIS "quser"
```
<ins>Search for Qwinsta Sessions
```
ProcessCmd ContainsCIS "qwinsta"
```
<ins>Search for Netstat, IPConfig, Arp, etc.
```
ProcessCmd RegExp "ipconfig" OR ProcessCmd RegExp "net\s+view" OR ProcessCmd RegExp "arp -a" OR ProcessCmd RegExp "netstat"
```
<ins>High‑Confidence C2: Suspicious Outbound IP Connections|Look for outbound connections to rare/external IPs|Filters internal traffic|Good baseline for beacon discovery
```
agent.uuid = "ENTER UUID" AND event.type = "IP Connect"event.network.direction = "OUTGOING"event.network.connectionStatus = "SUCCESS"not (  dst.ip.address startswith "10."  or dst.ip.address startswith "172.16."  or dst.ip.address startswith "172.17."  or dst.ip.address startswith "172.18."  or dst.ip.address startswith "172.19."  or dst.ip.address startswith "172.20."  or dst.ip.address startswith "172.21."  or dst.ip.address startswith "172.22."  or dst.ip.address startswith "172.23."  or dst.ip.address startswith "172.24."  or dst.ip.address startswith "172.25."  or dst.ip.address startswith "172.26."  or dst.ip.address startswith "172.27."  or dst.ip.address startswith "172.28."  or dst.ip.address startswith "172.29."  or dst.ip.address startswith "172.30."  or dst.ip.address startswith "172.31."  or dst.ip.address startswith "192.168.")
```
<ins>C2 via DNS: Suspicious or Algorithmic Domains | Detect DGA‑like or suspicious DNS activity|Catches DGA domains,Randomized subdomains,Malware DNS beacons
```
event.type = "DNS Resolved"and (length(event.dns.queryName) > 35  or event.dns.queryName matches "^[a-z0-9]{15,}\\.")
```
<ins>DNS queries from unusual processes|Malware often does DNS from non‑browser processes|Great signal for LOLBins and loaders
```
P
```
<ins>
```
P
```
<ins>
```
P
```

**System & Task Management**

<ins>Search for Unusual Scheduled Task Creation
```
ProcessCmd ContainsCIS "schtasks" AND processName != "Manages scheduled tasks"
```
<ins>Search for Current Running Processes
```
ProcessCmd ContainsCIS "tasklist"
```
<ins>Search for System Info Gathering
```
ProcessCmd ContainsCIS "systeminfo"
```

**Persistence & Exploitation**

<ins>Search for svchost.exe in Unusual Context
```
processImagePath = "C:\\Windows\\System32\\svchost.exe" AND
User NOT IN ("NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\NETWORK SERVICE")
```
<ins>Search for Suspicious Parent Process (svchost.exe)
```
ProcessName ContainsCIS "Host Process for Windows Services" AND
ParentProcessName NOT IN ("Host Process for Windows Services", "Services and Controller app")
```

**Miscellaneous Suspicious Behavior**

<ins>Search for Enable SMBv1
```
ProcessCmd = "REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v SMB1 /t REG_DWORD /d 1 /f"
```
<ins>Search for Execute File in AppData
```
ProcessCmd ContainsCIS "/FILE" AND ProcessCmd ContainsCIS "Appdata"
```
<ins>Search for Clear Event Logs
```
ProcessCmd ContainsCIS "wevtutil cl system" OR ProcessCmd ContainsCIS "Clear-EventLog"
```
