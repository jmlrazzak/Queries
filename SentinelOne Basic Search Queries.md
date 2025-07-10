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
