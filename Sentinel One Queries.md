**HUNTING QUERIES (they work)**

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
<ins>Search for 
```

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
<ins>Search for 
```

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
<ins>Search for 
```

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
<ins>Search for 
```

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
<ins>Search for 
```

```

**==================TO TEST ====================**

<ins>1. Detect Suspicious Processes
```
src.process.cmdline OR src.process.displayName OR src.process.parent.name OR src.process.user contains "powershell.exe" AND command_line contains "-enc"
```

<ins>2. Find Unauthorized Software Installations
```
event_type contains "installation" AND NOT publisher contains "Microsoft Corporation" AND NOT publisher contains "Google LLC" AND NOT publisher contains "Apple Inc."
```

<ins>3. Search for Specific Malware Hashes
```
file_hash in ["hash1", "hash2", "hash3"]
```

<ins>4. Detect Lateral Movement Attempts
```
event_type contains "network_connection" AND destination_port in [445, 3389] AND direction contains "outbound" AND NOT is_encrypted
```

<ins>5. Identify Persistence Mechanisms
```
event_type contains "registry_change" AND registry_key contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
```

<ins>6. Investigate Privilege Escalation Attempts
```
process_name in ["schtasks.exe", "runas.exe", "psexec.exe"] AND elevated_privileges
```

<ins>7. Monitor RDP Logins
```
event_type contains "login" AND login_type contains "RDP" AND timestamp within last 24 hours AND NOT source_ip in ["trusted_IP1", "trusted_IP2"]
```

<ins>8. Detect Suspicious File Modifications
```
event_type contains "file_modification" AND file_extension in [".ps1", ".bat", ".exe", ".dll"] AND file_path contains "Temp"
```

<ins>9. Investigate High-Severity Threats
```
event_type contains "threat" AND severity in ["high", "critical"] AND timestamp within last 7 days
```

<ins>10. Look for Data Exfiltration
```
event_type contains "network_connection" AND NOT destination_ip in ["internal_IP_range"] AND bytes_sent > 10000000 AND timestamp within last 24 hours
```

<ins>11. Detect Suspicious PowerShell Activity
```
process_name contains "powershell.exe" AND command_line contains "-nop -w hidden"
```

<ins>12. Investigate High CPU Usage Processes
```
process_name exists AND cpu_usage > 80
```

<ins>13. Search for Processes Making Network Connections
```
process_name exists AND event_type contains "network_connection"
```

<ins>14. Identify Processes Accessing Sensitive Files
```
file_path contains "C:\\Windows\\System32" AND process_name exists
```

<ins>15. Detect Unusual Parent-Child Process Relationships
```
parent_process_name contains "explorer.exe" AND process_name contains "cmd.exe"
```

<ins>16. Look for Newly Created Files
```
event_type contains "file_creation" AND timestamp within last 24 hours
```

<ins>17. Find Threats with Suspicious File Extensions
```
file_extension in [".exe", ".dll", ".bat", ".ps1"] AND event_type contains "threat"
```

<ins>18. Investigate Large Outbound Network Traffic
```
event_type contains "network_connection" AND bytes_sent > 50000000
```

<ins>19. Search for Terminated Processes
```
event_type contains "process_termination"
```

<ins>20. Investigate Processes with High Memory Usage
```
process_name exists AND memory_usage > 500MB
```

<ins>21. Search for Suspicious Scheduled Tasks
```
process_name contains "schtasks.exe" AND command_line contains "create"
```

<ins>22. Identify Processes Persisting in Startup
```
registry_key contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" OR file_path contains "Startup"
```

<ins>23. Detect Lateral Movement Tools
```
process_name in ["wmiexec.exe", "psexec.exe", "mimikatz.exe"]
```

<ins>24. Search for Ransomware Behavior
```
file_extension in [".encrypted", ".locked", ".crypto"] AND event_type contains "file_modification"
```

<ins>25. Investigate Suspicious DNS Queries
```
event_type contains "dns_query" AND query_name contains ".xyz" OR query_name contains ".ru"
```

<ins>26. Look for Processes Running from Temp Directory
```
process_name exists AND file_path contains "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp"
```

<ins>27. Search for Processes with Unusual Command Line Length
```
process_name exists AND command_line_length > 500
```

<ins>28. Monitor for Kernel-Level Threats
```
event_type contains "kernel_thread" AND severity in ["high", "critical"]
```

<ins>29. Investigate Suspicious Service Creations
```
process_name contains "services.exe" AND command_line contains "create"
```

<ins>30. Detect Unauthorized USB Device Usage
```
event_type contains "usb_device_connection" AND NOT device_id in ["trusted_device_id1", "trusted_device_id2"]
```




