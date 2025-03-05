# Home SOC in Azure - Security Operations Center Lab

## Project Overview
This project demonstrates the setup of a basic Security Operations Center (SOC) in Azure using a free Azure subscription. The lab includes deploying a virtual machine (VM) as a honeypot, forwarding logs to a central repository, and integrating Microsoft Sentinel to analyze real-world attack data.

## Key Components:
- **Azure VM as a Honeypot**
- **Log Analytics Workspace for Log Collection**
- **Microsoft Sentinel for Security Monitoring**
- **Threat Mapping with Log Data Visualization**

---

## Step 1: Setting Up the Azure Environment
1. **Create an Azure Resource Group**:
   - Navigate to Azure Portal and create a resource group named **SOC-Lab**.
   - Set the location to **East US 2**.
   ![1](https://github.com/user-attachments/assets/63de7e36-e9c0-4477-8b98-321007527af8)

2. **Create a Virtual Machine**:
   - Deploy a VM named **CORP-NET-EAST-117**.
   - Assign a **Public IP** to expose it to the internet.
   - Attach a **Network Security Group (NSG)**.

3. **Configure Network Security Group (NSG) Rules**:
   - Added an inbound rule to allow all traffic (**WARNING: Not Secure**) for testing attack detection.
   - Rule Name: `WARNING_AllowAnyCustomAnyInbound`.

    ![2 1](https://github.com/user-attachments/assets/666d516c-9b0e-4b34-9623-3aad0f38357b)
   ![2 2](https://github.com/user-attachments/assets/1d6bad73-fe59-4c4d-b245-b9cb4458d6bc)

   ![4](https://github.com/user-attachments/assets/dca2f86e-377b-45bb-8591-10b87cec1513)


---

## Step 2: Configuring Logging and Monitoring
4. **Set Up a Log Analytics Workspace**:
   - Created `LAW-SOC-Lab` for collecting security logs.
   - Linked the workspace to the SOC-Lab resource group.
  ![5](https://github.com/user-attachments/assets/402a6304-58ba-4225-b63a-fede26fed4a9)

   
5. **Enable Microsoft Sentinel**:
   - Connected Sentinel to the Log Analytics Workspace.
   - Configured data connectors to collect logs from the VM.
![5 1](https://github.com/user-attachments/assets/2ab81fd2-c1f7-4cee-8046-7f4dde7b8597)

   
6. **Install Azure Monitor Agent**:
   - Installed `AzureMonitorWindowsAgent` on the VM.
   - Verified provisioning status as `Succeeded`.
   ![5 2](https://github.com/user-attachments/assets/a652ed1a-b0f6-49d7-a0c4-7c68d5830a7d)

---

## Step 3: Analyzing Attack Data
7. **Collecting Security Events**:
   - Queried failed login attempts (Event ID: 4625) using the Log Analytics Workspace.
   - Detected multiple failed login attempts from external IPs.
  ![5 5](https://github.com/user-attachments/assets/0745b1b1-f288-4c49-a093-ea67b98ab61a)

   
8. **Geo-Tracking Attack Sources**:
   - Created a watchlist in Microsoft Sentinel named `geoip`.
   - Used the following **Kusto Query Language (KQL)** script to extract attack locations:
   
   ```kql
   let GeoIPDB_FULL = _GetWatchlist("geoip");
   let WindowsEvents = SecurityEvent;
   WindowsEvents | where EventID == 4625
   | order by TimeGenerated desc
   | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
   | summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
   | project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,
   friendly_location = strcat(cityname, " (", countryname, ")");
   ```
   ![5 4](https://github.com/user-attachments/assets/a7aa6542-2e41-4808-abb2-f002a67c8191)


---

## Step 4: Visualizing Attacks with a Heat Map
9. **Configuring the Threat Map**:
   - Created a map visualization in Sentinel.
   - Used the following JSON configuration for the heat map:

![6](https://github.com/user-attachments/assets/e4e0700b-1421-4a67-bdad-686eb11455c9)

   ```json
   {
       "type": 3,
       "content": {
           "version": "KqlItem/1.0",
           "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
           "size": 3,
           "timeContext": {
               "durationMs": 2592000000
           },
           "queryType": 0,
           "resourceType": "microsoft.operationalinsights/workspaces",
           "visualization": "map",
           "mapSettings": {
               "locInfo": "LatLong",
               "locInfoColumn": "countryname",
               "latitude": "latitude",
               "longitude": "longitude",
               "sizeSettings": "FailureCount",
               "sizeAggregation": "Sum",
               "opacity": 0.8,
               "labelSettings": "friendly_location",
               "legendMetric": "FailureCount",
               "legendAggregation": "Sum",
               "itemColorSettings": {
                   "nodeColorField": "FailureCount",
                   "colorAggregation": "Sum",
                   "type": "heatmap",
                   "heatmapPalette": "greenRed"
               }
           }
       },
       "name": "query - 0"
   }
   ```

---

## Project Outcome
- Successfully set up a SOC environment in Azure.
- Identified and logged real-world attack attempts.
- Created a dynamic **heatmap visualization** tracking global attacks.
- Demonstrated **log analysis skills** and **KQL querying expertise**.

## Future Enhancements
- Automate detection and response using Sentinel playbooks.
- Implement stricter security controls while maintaining honeypot functionality.
- Enhance visualization with Power BI integration.



