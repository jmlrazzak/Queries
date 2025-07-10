**HUNTING QUERIES (they work)
**User Account Operations

Add User
```
ProcessCmd RegExp "net\s+user(?:(?!\s+/add)(?:.|\n))*\s+/add"
```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```
TEXT FIELD
```

```

==================TO TEST ====================
1. Detect Suspicious Processes
```
src.process.cmdline OR src.process.displayName OR src.process.parent.name OR src.process.user contains "powershell.exe" AND command_line contains "-enc"
```

2. Find Unauthorized Software Installations
```
event_type contains "installation" AND NOT publisher contains "Microsoft Corporation" AND NOT publisher contains "Google LLC" AND NOT publisher contains "Apple Inc."
```

3. Search for Specific Malware Hashes
```
file_hash in ["hash1", "hash2", "hash3"]
```

4. Detect Lateral Movement Attempts
```
event_type contains "network_connection" AND destination_port in [445, 3389] AND direction contains "outbound" AND NOT is_encrypted
```

5. Identify Persistence Mechanisms
```
event_type contains "registry_change" AND registry_key contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
```

6. Investigate Privilege Escalation Attempts
```
process_name in ["schtasks.exe", "runas.exe", "psexec.exe"] AND elevated_privileges
```

7. Monitor RDP Logins
```
event_type contains "login" AND login_type contains "RDP" AND timestamp within last 24 hours AND NOT source_ip in ["trusted_IP1", "trusted_IP2"]
```

8. Detect Suspicious File Modifications
```
event_type contains "file_modification" AND file_extension in [".ps1", ".bat", ".exe", ".dll"] AND file_path contains "Temp"
```

9. Investigate High-Severity Threats
```
event_type contains "threat" AND severity in ["high", "critical"] AND timestamp within last 7 days
```

10. Look for Data Exfiltration
```
event_type contains "network_connection" AND NOT destination_ip in ["internal_IP_range"] AND bytes_sent > 10000000 AND timestamp within last 24 hours
```

11. Detect Suspicious PowerShell Activity
```
process_name contains "powershell.exe" AND command_line contains "-nop -w hidden"
```

12. Investigate High CPU Usage Processes
```
process_name exists AND cpu_usage > 80
```

13. Search for Processes Making Network Connections
```
process_name exists AND event_type contains "network_connection"
```

14. Identify Processes Accessing Sensitive Files
```
file_path contains "C:\\Windows\\System32" AND process_name exists
```

15. Detect Unusual Parent-Child Process Relationships
```
parent_process_name contains "explorer.exe" AND process_name contains "cmd.exe"
```

16. Look for Newly Created Files
```
event_type contains "file_creation" AND timestamp within last 24 hours
```

17. Find Threats with Suspicious File Extensions
```
file_extension in [".exe", ".dll", ".bat", ".ps1"] AND event_type contains "threat"
```

18. Investigate Large Outbound Network Traffic
```
event_type contains "network_connection" AND bytes_sent > 50000000
```

19. Search for Terminated Processes
```
event_type contains "process_termination"
```

20. Investigate Processes with High Memory Usage
```
process_name exists AND memory_usage > 500MB
```

21. Search for Suspicious Scheduled Tasks
```
process_name contains "schtasks.exe" AND command_line contains "create"
```

22. Identify Processes Persisting in Startup
```
registry_key contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" OR file_path contains "Startup"
```

23. Detect Lateral Movement Tools
```
process_name in ["wmiexec.exe", "psexec.exe", "mimikatz.exe"]
```

24. Search for Ransomware Behavior
```
file_extension in [".encrypted", ".locked", ".crypto"] AND event_type contains "file_modification"
```

25. Investigate Suspicious DNS Queries
```
event_type contains "dns_query" AND query_name contains ".xyz" OR query_name contains ".ru"
```

26. Look for Processes Running from Temp Directory
```
process_name exists AND file_path contains "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp"
```

27. Search for Processes with Unusual Command Line Length
```
process_name exists AND command_line_length > 500
```

28. Monitor for Kernel-Level Threats
```
event_type contains "kernel_thread" AND severity in ["high", "critical"]
```

29. Investigate Suspicious Service Creations
```
process_name contains "services.exe" AND command_line contains "create"
```

30. Detect Unauthorized USB Device Usage
```
event_type contains "usb_device_connection" AND NOT device_id in ["trusted_device_id1", "trusted_device_id2"]
```




