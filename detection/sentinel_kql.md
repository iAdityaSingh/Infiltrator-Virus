# Microsoft Defender / Sentinel KQL equivalents

Adapt table and column names to your workspace and validate before relying on them.

## 1. SMTP from a scripting runtime
```kql
DeviceNetworkEvents
| where RemotePort in (25, 465, 587, 2525, 1025)
| where InitiatingProcessFileName in~ ("python.exe", "pythonw.exe", "node.exe", "powershell.exe", "wscript.exe", "cscript.exe")
| summarize Connections = count(), First = min(Timestamp), Last = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| where Connections >= 3
```

## 2. Regular-interval (beacon-like) SMTP from non-mail processes
```kql
DeviceNetworkEvents
| where RemotePort in (25, 465, 587, 2525)
| where InitiatingProcessFileName !in~ ("outlook.exe", "olk.exe", "thunderbird.exe")
| sort by DeviceName asc, RemoteIP asc, Timestamp asc
| extend PrevTime = prev(Timestamp), SameFlow = (DeviceName == prev(DeviceName) and RemoteIP == prev(RemoteIP))
| where SameFlow
| extend GapSec = datetime_diff('second', Timestamp, PrevTime)
| summarize Count = count(), AvgGap = avg(GapSec), StdGap = stdev(GapSec)
    by DeviceName, RemoteIP, InitiatingProcessFileName
| where Count >= 5 and AvgGap > 0 and StdGap / AvgGap < 0.15
```
