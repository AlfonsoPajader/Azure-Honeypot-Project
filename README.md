# Azure-Honeypot-Project

# Objective
A honeypot will be created using a VM in Azure. The VM's RDP port will be open for attackers. Meanwhile, the creator will be able collect and analyze logs with the help of a geographical map. Attackers will be plotted on to the map as they try to go for the honeypot.

# Skills Learned
- Developed a vulnerable VM in Azure to act as a honeypot.
- Proficiency in analyzing and interpreting host logs. 
- Knowledge of event id, network protocols, and security vulnerabilities.
- Ability to understand powershell script.

# Tools Used
- Microsoft Azure: Microsoft Sentinel, Resource Group, Virtual Machine, Log Analytics Workspace, Microsoft Defender for Cloud
- Powershell
- Windows Event Viewer

# Steps 
1. Create **Resource Group**
2. Create **Virtual Machine** -> "Azure Virtual Machine"
	- 2nd half keep everything as default and create an admin account
	- Had to change to Zone 2 to get Size: Standard_D2s_v3
3. Create **Log Analytics Workspace** 
	1. Once created, click on it -> Virtual machines (depracated) -> *your virtual machine*
	2. Connect. 
4. Change settings in **Microsoft Defender for Cloud**
	1. In Defender plans, enable all plans except SQL servers on machines, Save
	2. In Data collection, select "All Events", Save
5. Add **Microsoft Sentinel** to *your workspace*
6. Connect to your virtual machine
	1. Virtual Machines -> *your vm* -> Overview -> copy the "Public IP address" from the right hand side
	2. For MAC, used Microsoft Remote Desktop
	3. Uncheck all privacy settings during first sign in 
7. Within VM
	1. Open "Event Viewer" -> Windows Logs -> Security -> Filter Current Log..." -> input "4625" on Event ID section  **WHAT IS 4625 - CREATE A NOTE**
	2. Turn off Windows Defender Firewall
8. Create [IPGeoLocation](https://ipgeolocation.io/signup) account
	1. Dashboard -> Copy API Key
9. Running a Power Script
	1. Copy [Powershell Script](https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1?source=post_page-----5e338bdc62ee--------------------------------)
	2. In PowerShell ISE, File -> New
	3. Paste Script
	4. Change the API key with IPGeoLocation API key from Step 8
10. Create a custom log in Log Analytics Workspace
	1. *workspace* -> Tables -> Create -> New custom log (MMA-based)
	2. save

*PowerShell Script:*
**NOTE:** first line is the name of your custom log
```
RDP_Fail_With_Geo_Location_CL  
  
| extend username = extract(@"username:([^,]+)", 1, RawData),  
  
timestamp = extract(@"timestamp:([^,]+)", 1, RawData),  
  
latitude = extract(@"latitude:([^,]+)", 1, RawData),  
  
longitude = extract(@"longitude:([^,]+)", 1, RawData),  
  
sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),  
  
state = extract(@"state:([^,]+)", 1, RawData),  
  
label = extract(@"label:([^,]+)", 1, RawData),  
  
destination = extract(@"destinationhost:([^,]+)", 1, RawData),  
  
country = extract(@"country:([^,]+)", 1, RawData)  
  
| where destination != "samplehost"  
  
| where sourcehost != ""  
  
| summarize event_count=count() by latitude, longitude, sourcehost, label, destination, country
```

11. Create a workbook in **Microsoft Sentinel**
	1. Microsoft Sentinel -> *your log analysis workbook* > Workbooks > Add Workbook
	2. Edit and remove everything until it's empty
	3. Run the query to test
	4. Change the visualization to "map", Save
12. Monitor the Sentinel Workbook and the VM Powerscript

---

# REF

