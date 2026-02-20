
**<ins>SHOW ALL TABLES IN SENTINEL**
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




