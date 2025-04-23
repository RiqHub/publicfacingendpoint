---

![image](https://github.com/user-attachments/assets/918895bb-55e7-45a5-9fc6-b3bee09ed336)

---

## 🧰 Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## 📓 Scenario 

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

## ⏲️ Timeline 

### 1. Verify Devices Open To The Internet

Multiple VM's were found to be internet facing, We will focus on `windows-target-1` for the purpose of this lab.

**Query used to find**

```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing = True
|order by Timestamp desc
```


![image](https://github.com/user-attachments/assets/736b8e42-3590-46eb-b627-d64ba2e779d9)

---

### 2. Detect Logon Traffic

Checked to see what type of logon activity was happening. Multiple Remote Ip's were found to be trying to get inside the device. 

**Query used:**

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```


![image](https://github.com/user-attachments/assets/3cfe9046-c6b8-4b29-af5d-4f1e7267a1e3)


---

### 3. Check IP's for Any Sucessful logons

No successful logons from the IP address listed where successful. But just to be thorough we also checked if any one was able to login at all and we did find familiar users had logged on so no foul play was suggested. 

**Query's Used**

```kql
let RemoteIPsInQuestion = dynamic(["197.210.194.240","91.238.181.40", "88.214.25.74", "92.255.85.172", "185.42.12.59", "147.45.112.27", "196.251.84.131"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where ActionType == "LogonSuccess"
```


---


## 📖 Summary 





