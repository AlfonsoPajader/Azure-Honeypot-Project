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
1. Create a Microsoft Azure account
2. Create **Resource Group**
   <img width="796" alt="1" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/400a8ae0-d49e-4d87-b5c0-5aeb5086e8ac">
   
3. Create **Virtual Machine** -> "Azure Virtual Machine"
	- 2nd half keep everything as default and create an admin account
	- Had to change to Zone 2 to get Size: Standard_D2s_v3
<img width="803" alt="2" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/fe25fa9b-41ce-4b5e-b87a-d50f4e733651">
 
 <img width="580" alt="3" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/c9fd4f6e-6a58-4639-a677-08935b7ab21a">

<img width="820" alt="4" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/ac27e2f2-20d3-43a4-be44-8cbfbbe7fbfb">

4. Create **Log Analytics Workspace** 
	1. Once created, click on it -> Virtual machines (depracated) -> *your virtual machine*
	2. Connect.
 
 <img width="726" alt="5" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/e226b975-01d9-427e-b471-b371e23f7d37">

<img width="1504" alt="6" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/d9be4ab1-c1de-4588-8c4d-3388f743899a">

5. Change settings in **Microsoft Defender for Cloud**
	1. In Defender plans, enable all plans except SQL servers on machines, Save
 <img width="1483" alt="7" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/b883a5a8-5f0c-4efb-87e7-756d907aeb32">

<img width="1491" alt="8" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/4e916c22-8520-43e9-b627-c43cc48668a6">
	2 . In Data collection, select "All Events", Save

<img width="1190" alt="9" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/89370284-8a54-4284-bec2-ed8e3fde2ec5">

6. Add **Microsoft Sentinel** to *your workspace*
   
7. Connect to your virtual machine
	1. Virtual Machines -> *your vm* -> Overview -> copy the "Public IP address" from the right hand side
	2. For MAC, used Microsoft Remote Desktop
	3. Uncheck all privacy settings during first sign in
<img width="1198" alt="10" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/80c6417c-d913-4ba7-8456-65ac3fc11ff5">

8. Within VM
	1. Open "Event Viewer" -> Windows Logs -> Security -> Filter Current Log..." -> input "4625" on Event ID section  **WHAT IS 4625 - CREATE A NOTE**
<img width="544" alt="11" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/2361221f-c54f-48f8-8d4f-a23dc03cf5b1">
	2. Turn off Windows Defender Firewall

<img width="1100" alt="12" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/1a2a0556-f1cb-4c4e-8b9a-a811c0b3eab9">

9. Create [IPGeoLocation](https://ipgeolocation.io/signup) account
	1. Dashboard -> Copy API Key

10. Running a Power Script
	1. Copy [Powershell Script](https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1?source=post_page-----5e338bdc62ee--------------------------------)
	2. In PowerShell ISE, File -> New
	3. Paste Script
	4. Change the API key with IPGeoLocation API key from Step 8
<img width="1344" alt="13" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/d64fd1c4-6681-42b3-b0d1-9b18810796b8">

<img width="980" alt="14" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/c352a7a3-50d3-4206-b75b-90cf2b6d28e4">

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

11. Create a custom log in Log Analytics Workspace
	1. *workspace* -> Tables -> Create -> New custom log (MMA-based)
<img width="866" alt="15" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/c5aa51ce-d255-43c1-a6a7-c6ffe3deb880">

<img width="1501" alt="Screenshot 2024-06-06 at 12 33 31 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/8fc138b9-646f-4152-8645-7a5f1f4e2650">

<img width="744" alt="Screenshot 2024-06-05 at 11 51 33 PM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/dad92bd0-3a2b-4a34-995b-74f9690eac7e">

<img width="726" alt="Screenshot 2024-06-05 at 11 52 01 PM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/24f56d49-4ee0-47c1-89b0-73249a5629db">
	2. Save
<img width="319" alt="Screenshot 2024-06-06 at 12 30 22 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/7f897cac-351a-48f0-8f56-f5be50c5eb60">

12. Create a workbook in **Microsoft Sentinel**
	1. Microsoft Sentinel -> *your log analysis workbook* > Workbooks > Add Workbook
<img width="1228" alt="Screenshot 2024-06-06 at 12 32 05 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/26e96e75-9dd3-422f-8e3a-f66dd3dbdff0">

 	2. Edit and remove everything until it's empty

	3. Run the query to test
<img width="1503" alt="Screenshot 2024-06-05 at 11 54 51 PM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/7add3e7d-ac83-4ea2-962d-c1ebe1741632">

<img width="1501" alt="Screenshot 2024-06-06 at 12 33 31 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/8fc138b9-646f-4152-8645-7a5f1f4e2650">
	4. Change the visualization to "map", Save

<img width="725" alt="Screenshot 2024-06-05 at 11 50 31 PM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/dc0c1abc-c0fb-4b7d-a6ab-edfc789dc051">

<img width="712" alt="Screenshot 2024-06-06 at 12 34 32 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/22ddc49c-365b-4ea9-a2ca-22ff6d59700d">


13. Monitor the Sentinel Workbook and the VM Powerscript
<img width="663" alt="Screenshot 2024-06-06 at 12 35 41 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/564b25e7-ecaa-493d-8daa-c74e44550f2f">

# Reflection
<img width="619" alt="Screenshot 2024-06-07 at 8 08 21 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/edeb8b7b-fbec-4271-82cf-c296b829f93a">


# REF

