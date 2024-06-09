# Azure-Honeypot-Project

# Objective
A honeypot will be created using a VM in Azure. The VM's firewall and RDP port will be open for attackers. Meanwhile, analysts can collect and analyze logs of the attacks. The live attacks towards the honeypot will be plotted on to the geographical Azure Sentinel map.

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
## 1. Create a Microsoft Azure account
## 2. Create **Resource Group**
<img width="796" alt="1" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/400a8ae0-d49e-4d87-b5c0-5aeb5086e8ac">
   
## 3. Create **Virtual Machine** -> "Azure Virtual Machine"
### i. 2nd half keep everything as default and create an admin account
### ii. Had to change to Zone 2 to get Size: Standard_D2s_v3

<img width="803" alt="2" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/fe25fa9b-41ce-4b5e-b87a-d50f4e733651">
 
<img width="580" alt="3" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/c9fd4f6e-6a58-4639-a677-08935b7ab21a">

<img width="820" alt="4" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/ac27e2f2-20d3-43a4-be44-8cbfbbe7fbfb">

## 4. Create **Log Analytics Workspace** 
### i. Once created, click on it -> Virtual machines (depracated) -> *your virtual machine*
### ii. Connect.
 
 <img width="726" alt="5" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/e226b975-01d9-427e-b471-b371e23f7d37">

<img width="1504" alt="6" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/d9be4ab1-c1de-4588-8c4d-3388f743899a">

## 5. Change settings in **Microsoft Defender for Cloud**
### i. In Defender plans, enable all plans except SQL servers on machines, Save
 <img width="1483" alt="7" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/b883a5a8-5f0c-4efb-87e7-756d907aeb32">

<img width="1491" alt="8" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/4e916c22-8520-43e9-b627-c43cc48668a6">

### ii. In Data collection, select "All Events", Save

<img width="1190" alt="9" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/89370284-8a54-4284-bec2-ed8e3fde2ec5">

## 6. Add **Microsoft Sentinel** to *your workspace*
   
## 7. Connect to your virtual machine
### i. Virtual Machines -> *your vm* -> Overview -> copy the "Public IP address" from the right hand side
### ii. For MAC, used Microsoft Remote Desktop
### iii. Uncheck all privacy settings during first sign in
<img width="1198" alt="10" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/80c6417c-d913-4ba7-8456-65ac3fc11ff5">

## 8. Within VM
### i. Open "Event Viewer" -> Windows Logs -> Security -> Filter Current Log..." -> input "4625" on Event ID section  
<img width="544" alt="11" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/2361221f-c54f-48f8-8d4f-a23dc03cf5b1">

### ii. Turn off Windows Defender Firewall

<img width="1100" alt="12" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/1a2a0556-f1cb-4c4e-8b9a-a811c0b3eab9">

## 9. Create [IPGeoLocation](https://ipgeolocation.io/signup) account
### i. Dashboard -> Copy API Key

## 10. Running a Power Script
### i. Copy [Powershell Script](https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1?source=post_page-----5e338bdc62ee--------------------------------)
### ii. In PowerShell ISE, File -> New
### iii. Paste Script
### iv. Change the API key with IPGeoLocation API key from Step 8
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

## 11. Create a custom log in Log Analytics Workspace
### 1. *workspace* -> Tables -> Create -> New custom log (MMA-based)
 
 <img width="725" alt="Screenshot 2024-06-05 at 11 50 31 PM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/28405b89-6ec2-40fb-a393-9cea17b219fd">

<img width="744" alt="Screenshot 2024-06-05 at 11 51 33 PM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/5fb30e44-3000-45be-8c08-41d9be648c9e">

<img width="726" alt="Screenshot 2024-06-05 at 11 52 01 PM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/094806b0-cf24-44a0-b050-9a239c3a7e93">
 ### 2. Save
  
 <img width="319" alt="Screenshot 2024-06-06 at 12 30 22 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/9d35964e-17aa-4c11-ae09-b5ddddbb2273">

 

## 12. Create a workbook in **Microsoft Sentinel**
### i. Microsoft Sentinel -> *your log analysis workbook* > Workbooks > Add Workbook
<img width="1228" alt="Screenshot 2024-06-06 at 12 32 05 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/95cb8fb4-0e4f-494a-b76a-25439e2236c9">

### ii. Edit and remove everything until it's empty
	
### iii. Run the query to test
<img width="1501" alt="Screenshot 2024-06-06 at 12 33 31 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/af77b073-1c3d-4fc9-8066-082b155896b3">
	
### iv. Change the visualization to "map", Save
 <img width="712" alt="Screenshot 2024-06-06 at 12 34 32 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/87663982-8170-415e-b4ac-610f5a9799c0">


## 13. Monitor the Sentinel Workbook and the VM Powerscript
<img width="663" alt="Screenshot 2024-06-06 at 12 35 41 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/564b25e7-ecaa-493d-8daa-c74e44550f2f">

# Reflection
<img width="619" alt="Screenshot 2024-06-07 at 8 08 21 AM" src="https://github.com/AlfonsoPajader/Azure-Honeypot-Project/assets/142128030/edeb8b7b-fbec-4271-82cf-c296b829f93a">
After 24 hours, more logs have been captured and displayed on the map. Most of the attacks are originating from the Netherlands. Vulnerabilities such as firewall and ports need to be appropriately considered to have a secure host. Given the map, it can give insights on how to improve one's security posture and response.

# Reference
 - [Josh Makada](https://youtu.be/RoZeVbbZ0o0?si=VXqGOxIOS2tumEdc)

