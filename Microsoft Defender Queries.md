
**<ins>SHOW all TABLES in Defender**
```
//SHOW ALL TABLES IN SENTINEL 
search * 
| summarize count() by $table 
| project TableName= $table
```

**<ins>identify a URL in the environment**
```
// identify a URL in the environment , if you see in DeviceNetworkEvents table and the ActionType is ConnectionSuccess then communication was made. 
let url = "BAD.COM"; 
search in (EmailUrlInfo, UrlClickEvents, DeviceNetworkEvents,DeviceFileEvents,DeviceEvents,BehaviorEntities) 
Timestamp between (ago(30d) .. now()) 
and (RemoteUrl has url 
or FileOriginUrl has url 
or FileOriginReferrerUrl has url 
or Url has url 
) 
| take 100 //remove to see everything or edit to see a specific number of events
```

**<ins>Network connections to (DOMAIN/URL or IP) (last 100 days)**
```
//network connections to (DOMAIN/URL) (last 100 days)
let C2Domains = dynamic(["google.com", "edge.com"]);
DeviceNetworkEvents
| where Timestamp >= ago(100d)
| where RemoteUrl has_any (C2Domains) or RemoteIP has_any (C2Domains)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName, InitiatingProcessFileName,
          RemoteUrl, RemotePort, RemoteIP, ReportId
| order by Timestamp desc
```

**<ins>see URL hits, Logs network connections initiated by processes, such as a browser clicking and connecting to a URL**
```
//see URL hits, Logs network connections initiated by processes, such as a browser clicking and connecting to a URL 
DeviceNetworkEvents 
| where RemoteUrl has_any ("BAD.COM")  
| take 10
```

**<ins>Displays events where mail forwarding rules were created or modified, including the user responsible**
```
//This query will show you the details of the events where mail forwarding rules were created or modified, including the user (AccountDisplayName) who performed the action.
let dest_email = ""; // enter here destination email as seen in the alert or leave blank if not known
CloudAppEvents
| where Timestamp >= ago(100d) //put specified number of days back you would like to search
| where ActionType in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule") //set new inbox rule related operations
| where RawEventData contains "ForwardingAddress" or RawEventData contains "ForwardingSmtpAddress"
| extend ForwardingMailToAddress = tostring(parse_json(RawEventData.Parameters)[1].Value) //this is to parse out parameters from rawdata if its there
| extend MailboxInQuestion = tostring(parse_json(RawEventData).["ObjectId"]) // Extracts the Forwarding Address Value
| project Timestamp, ActionType, UserThatCreatedTheForwardingRule= AccountDisplayName, IPAddress, MailboxInQuestion, ForwardingMailToAddress, RuleConfig = RawEventData.Parameters, RawEventData
| where RuleConfig has dest_email
```

**<ins>See all Browser extensions in your environment**
```
DeviceTvmBrowserExtensions
| summarize by ExtensionId
```

**<ins>List Devices where Browser extensions are installed | will need to run the above Query first to get all the extensions in the environment then paste**
```
//list devices where any of extensions are installed
let ExtensionIds = dynamic([
  "gaaceiggkkiffbfdpmfapegoiohkiipl", "fihnjjcciajhdojfnbdddfaoknhalnja", "pocpnlppkickgojjlmhdmidojbmbodfm", "ddkjiahejlhfcafbddmgiahcphecmpfh", "nngceckbapebfimnlniiiahkandclblb", "fdpohaocaechififmbbbbbknoalclacl"
]);
let ExtHits =
DeviceTvmBrowserExtensions
| where ExtensionId in (ExtensionIds)
| project DeviceId, BrowserName, ExtensionId, ExtensionName, ExtensionVersion, ExtensionRisk;
ExtHits
| join kind=leftouter (
    DeviceInfo
    | project DeviceId, DeviceName, OSPlatform, LoggedOnUsers
) on DeviceId
| summarize
    Devices = make_set(DeviceName),
    DeviceCount = dcount(DeviceId)
  by BrowserName, ExtensionId, ExtensionName, ExtensionVersion, ExtensionRisk
| order by DeviceCount desc
```

**<ins>LOLBins & Scripted Execution
Suspicious PowerShell (EncodedCommand / IEX / DownloadString)**
```
let lookback = 100d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-enc","-EncodedCommand","IEX","Invoke-Expression","DownloadString","-nop","-w hidden")
| project Timestamp, DeviceName, InitiatingProcessParentFileName, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```

**<ins>mshta.exe executing remote content**
```
let lookback = 100d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "mshta.exe"
| where ProcessCommandLine matches regex @"https?://"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

**<ins>rundll32.exe suspicious script or URL invocation**
```
let lookback = 100d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript:", "vbscript:", "url.dll,FileProtocolHandler", "shell32.dll,ShellExec_RunDLL", "http://", "https://")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**<ins>regsvr32.exe living-off-the-land (scrobj.dll / remote scriptlet)**
```
let lookback = 100d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has_any ("scrobj.dll","http://","https://") or ProcessCommandLine has "/u"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**<ins>certutil.exe abused for download/decoding**
```
let lookback = 100d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache","-split","-f","-decode","-decodehex","http://","https://")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**<ins>bitsadmin file download usage**
```
let lookback = 100d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("bitsadmin.exe","bitsadmin")
| where ProcessCommandLine has_any ("transfer","addfile","/download","http://","https://")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

**<ins>Run keys modified to launch from user-writable paths**
```
let lookback = 100d;
let RunKeys = dynamic([
  @"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  @"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  @"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  @"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
]);
DeviceRegistryEvents
| where Timestamp >= ago(lookback)
| where RegistryKey has_any (RunKeys)
| where RegistryValueData has_any ("\\AppData\\","\\Temp\\","%APPDATA%","%TEMP%",".js",".vbs",".ps1")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**<ins>Office apps spawning scripts/LOLBins**
```
let lookback = 100d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE")
| where FileName in~ ("wscript.exe","cscript.exe","powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","cmd.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```

**<ins>New local admin accounts created**
```
let lookback = 100d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("net.exe","net1.exe","cmd.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("localgroup administrators","/add","New-LocalUser","Add-LocalGroupMember")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

**<ins>Credential Access & Discovery| procdump / comsvcs.dll targeting LSASS**
```
let lookback = 100d;
// procdump against lsass or comsvcs.dll abuse (MiniDump)
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("procdump.exe","procdump64.exe","rundll32.exe")
| where ProcessCommandLine has_any ("-ma lsass","-ma lsass.exe","comsvcs.dll","MiniDump")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

**<ins>Credential Access & Discovery| Unusual enumeration commands (net, whoami, dsquery, nltest)**
```
let lookback = 100d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("net.exe","net1.exe","whoami.exe","nltest.exe","dsquery.exe","dsget.exe","adfind.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```

**<ins>Phishing & Email‑borne Threats | Emails with Chrome Web Store links containing extension IDs**
```
let lookback = 100d;
let ExtIdRegex = @"/([a-p]{32})(?:\\?|/|$)";
EmailUrlInfo
| where Timestamp >= ago(lookback)
| where UrlDomain == "chrome.google.com" and Url has "/webstore/detail/"
| extend ExtensionId = tostring(extract(ExtIdRegex, 1, Url))
| where isnotempty(ExtensionId)
| join kind=inner (EmailEvents | where Timestamp >= ago(lookback) | project NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url, ExtensionId
| order by Timestamp desc
```

**<ins>Phishing & Email‑borne Threats | Search for malicious links where user was allowed to proceed through VIA SafeClicks**
```
// Search for malicious links where user was allowed to proceed through VIA SafeClicks
UrlClickEvents
| where Timestamp >= ago(200d)
| where ActionType == "ClickAllowed" or IsClickedThrough =="0" or IsClickedThrough =="1" //for IsClickedThrough 1=True 0=False
//IsClickedThrough = True (or 1): The user was presented with a warning page (e.g., that the link was suspicious, blocked, or a threat was detected), but they chose to click through the warning and visit the original dangerous destination.
//IsClickedThrough = False (or 0):The user was not presented with a warning page (the click was allowed without intervention).The user was presented with a warning but did not proceed to the original URL.
//| where ThreatTypes has "Phish"
//| where AccountUpn has "mbratton" //enter users name
| summarize by Timestamp, IsClickedThrough, AccountUpn, Url
```

**<ins>Phishing & Email‑borne Threats | Messages delivering potentially dangerous archives/scripts**
```
let lookback = 100d;
EmailAttachmentInfo
| where Timestamp >= ago(lookback)
| where FileType in~ ("zip","7z","rar","iso") or FileName endswith ".js" or FileName endswith ".vbs" or FileName endswith ".lnk"
| join kind=inner (EmailEvents | where Timestamp >= ago(lookback) | project NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, FileName, FileType, SHA256
| order by Timestamp desc
```

**<ins>dentity & Cloud Abuse | OAuth consent spikes / risky app grants**
```
let lookback = 100d;
// Look for app consents/service principal creations (tune ActionType values per tenant)
IdentityDirectoryEvents
| where Timestamp >= ago(lookback)
| where ActionType has_any ("Consent to application","Add service principal","Add OAuth2PermissionGrant")
| summarize Count=count(), Examples=make_set(AdditionalFields, 5) by ActionType, bin(Timestamp, 1d)
| order by Timestamp desc
```

**<ins>Network/DNS Heuristics | Execution from user‑writable paths**
```
let lookback = 100d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FolderPath has_any ("\\AppData\\Local\\","\\AppData\\Roaming\\","\\Temp\\","\\Public\\")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**<ins>SMB PIPES and SMB TRAFFIC**
```
//Hunt for SMB to the internet
let range = 100d;
union DeviceNetworkEvents, DeviceProcessEvents
| where Timestamp >= ago(range)
//Connections have RemotePort set to 445
//NetworkSignatureInspected have LocalPort set to 445
| where LocalPort == 445 and Protocol has "Tcp" and isnotempty(RemoteIP) //we exclude RemotePort == 445 because we want to block all local 445 traffic 
| where not(ipv4_is_private(RemoteIP)) or 
not(ipv4_is_private(LocalIP))
| where RemoteIPType != "Private"
```

**<ins>export the list of PuTTY sessions**
```
//The command was used to export the list of PuTTY sessions | the command itself is where Putty stores its data | https://documentation.help/PuTTY/faq.settings.html
DeviceProcessEvents
| where ProcessCommandLine in~ 
("powershell.exe", "powershell_ise.exe") or FileName in~ ("powershell.exe", "powershell_ise.exe") 
| where InitiatingProcessCommandLine has "HKCU\\Software\\SimonTatham\\Putty\\Sessions"
 | join ( 
DeviceRegistryEvents
| where RegistryKey has "HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY" or PreviousRegistryKey has "HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY"
) on DeviceName
```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```


**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```


**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```

**<ins>TEXT**
```

```




