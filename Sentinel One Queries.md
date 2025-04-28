
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




