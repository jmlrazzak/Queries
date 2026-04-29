
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

**<ins>Network connections grouped by user and site with visit counts and last seen**
```
let C2Domains = dynamic(["google.com", "edge.com"]);
DeviceNetworkEvents
| where Timestamp >= ago(100d)
| where RemoteUrl has_any (C2Domains) or RemoteIP has_any (C2Domains)
| summarize 
    VisitCount = count(), 
    LastVisited = max(Timestamp) 
    by InitiatingProcessAccountName, RemoteUrl
| sort by VisitCount desc
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

**<ins>URL Clicks | make sure if the user actually clicked creating a Click event + endpoint browser network activity**
```
//to make sure if the user actually clicked creating a Click event + endpoint browser network activity (maps to device/browser)
//this is a certain and easy way to show the user 100% clicked and there was 100% network activity due to the click
//remove or change the user to look into below
let TimeRange = 100d;
let SearchWord = "github";
let JoinWindow = 5m;
let Browsers = dynamic(["msedge.exe","chrome.exe","firefox.exe","brave.exe","opera.exe"]);
let Clicks =
UrlClickEvents
| where Timestamp >= ago(TimeRange)
| where tolower(Url) has SearchWord
| where ActionType == "ClickAllowed"
| extend ClickTime = Timestamp
| extend ClickHost = tostring(parse_url(Url).Host)
| project
    ClickTime,
    AccountUpn,
    Workload,
    ActionType,
    IsClickedThrough,
    Url,
    ClickHost,
    UrlChain,
    IPAddress,
    ThreatTypes,
    DetectionMethods,
    ReportId,
    NetworkMessageId;
let BrowserNet =
DeviceNetworkEvents
| where Timestamp >= ago(TimeRange)
| where InitiatingProcessFileName in~ (Browsers)
| where isnotempty(RemoteUrl)
| where InitiatingProcessAccountUpn has "jrazzak@blueally.com" // specify the user you want to dive into
| extend NetTime = Timestamp
| extend NetHost = tostring(parse_url(RemoteUrl).Host)
| project
    NetTime,
    DeviceName,
    DeviceId,
    InitiatingProcessAccountUpn,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    RemoteUrl,
    NetHost,
    RemoteIP,
    RemotePort,
    Protocol,
    ActionType;
Clicks
| join kind=leftouter BrowserNet on $left.ClickHost == $right.NetHost
//| where NetTime between (ClickTime - JoinWindow .. ClickTime + JoinWindow)
// Prefer UPN match when available
| where isempty(InitiatingProcessAccountUpn) or tolower(InitiatingProcessAccountUpn) == tolower(AccountUpn)
| summarize
    ClickEvents = count(),
    FirstClick = min(ClickTime),
    LastClick  = max(ClickTime),
    MatchedEndpointEvents = countif(isnotempty(DeviceName)),
    Devices = make_set(DeviceName, 10),
    BrowsersUsed = make_set(InitiatingProcessFileName, 10),
    SampleClickedUrls = make_set(Url, 10),
    SampleRemoteUrls  = make_set(RemoteUrl, 10)
  by AccountUpn, ClickHost
| order by ClickEvents desc
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

**<ins>Teams PSTN call audit record**
```
//Teams PSTN call audit record (all information you will need for an investigation for the external number)
CloudAppEvents
| where Application == "Microsoft Teams"
| where RawEventData has_any ("15044000163") //external caller number you want to get info on
| extend Data = parse_json(RawEventData)
| mv-expand Attendee = Data.Attendees
| extend
    ExternalCallerNumber = tostring(Data.UserId), 
    InternalUserDisplayName = tostring(Attendee.DisplayName), 
    InternalUserUPN = tostring(Attendee.UPN), 
    InternalUserObjectId = tostring(Attendee.UserObjectId), 
    RecipientType = tostring(Attendee.RecipientType), 
    ProviderType = tostring(Attendee.ProviderType), 
    CallOutcome = tostring(Data.ItemName), 
    CallId = tostring(Data.CallId), CallJoinTime = todatetime(Data.JoinTime), 
    CallLeaveTime = todatetime(Data.LeaveTime), 
    DeviceUsed = tostring(Data.DeviceInformation), 
    UserAgent = tostring(Data.ExtraProperties[0].Value)
| project
    Timestamp,
    ExternalCallerNumber,
    InternalUserDisplayName,
    InternalUserUPN,
    InternalUserObjectId,
    RecipientType,
    ProviderType,
    CallOutcome,
    CallJoinTime,
    CallLeaveTime,
    CallId,
    DeviceUsed,
    UserAgent
| order by Timestamp desc

//add this to then Correlate all calls from this number
| summarize CallAttempts = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
  by ExternalCallerNumber, InternalUserUPN
```

**<ins>CLICK INVESTIGATION FULL**
```
======================= Investigation to see if a user actually clicked or if the malicious traffic is stemming form something else =================

Step 1 — Pull the raw event details (this is the fastest truth)
Reminder: This table is fundamentally “network connections initiated by processes running on the endpoint.”

//Run this for the exact domain and time window. This will show InitiatingProcessFileName, CommandLine, Parent, ActionType, ports, etc.
let Domain = "pornotreno.com";
let StartTime = datetime(2026-04-01 00:00:01); // adjust (UTC vs local)
let EndTime   = datetime(2026-04-28 23:59:59); // adjust
DeviceNetworkEvents
| where Timestamp between (StartTime .. EndTime)
| where isnotempty(RemoteUrl)
| where tolower(RemoteUrl) has Domain
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessAccountUpn,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    InitiatingProcessCreationTime,
    InitiatingProcessParentFileName,
    InitiatingProcessParentId,
    InitiatingProcessParentCreationTime,
    ActionType,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    Protocol,
    LocalIP,
    LocalPort,
    ReportId,
    AdditionalFields
| order by Timestamp desc


Step 2 — Correlate to the process event (confirm what actually ran)
This joins the network event to the corresponding process creation details (hashes, signer, parent cmdline, etc.). This is how you distinguish “browser running normally” vs “browser spawned by something weird.”

let Domain = dynamic(["pornotreno.com", "classicpornvids.com", "eporncam.com", "eporncam.com", "xml.clixvista.com", "xml.clickmi.net", "creative.bestjavporn.live", "angelporno.com", "kalyteroporno.com", "pornhub.com"]);
let Lookback = 30d;
let Net =
DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| where isnotempty(RemoteUrl)
| where tolower(RemoteUrl) has_any (Domain)
| project NetTime=Timestamp, DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessAccountName,
         InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, Protocol, ActionType, ReportId;
let Proc =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| project ProcTime=Timestamp, DeviceId, ProcessId, FileName, FolderPath, ProcessCommandLine,
         InitiatingProcessParentFileName, InitiatingProcessCommandLine,
         SHA1, SHA256, AccountName;
Net
| join kind=leftouter Proc on DeviceId
| where ProcessId == InitiatingProcessId
| project
    NetTime, DeviceName, InitiatingProcessAccountName,
    InitiatingProcessFileName, FileName,
    ProcessCommandLine,
    InitiatingProcessParentFileName, InitiatingProcessCommandLine,
    SHA1, SHA256,
    RemoteUrl, RemoteIP, RemotePort, Protocol, ActionType, ReportId
| order by NetTime desc


Step 3 — Confirm user session context (was the user actively logged on?)
If the user wasn’t interactively logged in, that strongly supports “background / automated” causes.

let Domain = "pornotreno.com";
let Lookback = 30d;
let Window = 30m;
let Net =
DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| where isnotempty(RemoteUrl)
| where tolower(RemoteUrl) has Domain
| project NetTime=Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountUpn,
         InitiatingProcessFileName, InitiatingProcessId, RemoteUrl;
DeviceLogonEvents
| where Timestamp >= ago(Lookback)
| where ActionType == "LogonSuccess"
| where LogonType in~ ("Interactive","RemoteInteractive","Unlock","CachedInteractive")
| project LogonTime=Timestamp, DeviceId, AccountName, LogonType
| join kind=rightouter Net on DeviceId
| where AccountName == InitiatingProcessAccountName
| where LogonTime between (NetTime - Window .. NetTime + Window)
| project NetTime, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, LogonTime, LogonType
| order by NetTime desc


Step 4 — Check if this is one-off noise or a pattern (and what process drives it)
Instead of summarizing by URL only, summarize by process and parent process.

let SearchWord = "porn";
let Lookback = 30d;
let DontWantToSee = dynamic(["system", "local service", "network service", "root"]);
DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| where isnotempty(RemoteUrl)
| where tolower(RemoteUrl) contains SearchWord
   // or tolower(RemoteIP) contains SearchWord
| where tolower(InitiatingProcessAccountName) !in (DontWantToSee)
| where InitiatingProcessAccountName contains "carlosgarciaseverich"
| summarize
    Hits=count(),
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    SampleUrls=make_set(RemoteUrl, 5)
  by DeviceName,
     InitiatingProcessAccountName,
     InitiatingProcessFileName,
     InitiatingProcessParentFileName
| order by LastSeen desc
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




