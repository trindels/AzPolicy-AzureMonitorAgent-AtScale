# Azure Policy implementation for Azure Monitor Agent (AtScale)
 
The actions executed in this script:
- Deploy custom Azure Policy Definitions that extend or improve the capabilities of our existing built-in policies:
    - Support for User Assigned Managed Identities that do not exist in the same subscription as the Azure VM resources
    - Include / Exclude Tag filtering for the association of Data Collection Rules to Azure Resources
- Create Policy Assignments for the following actions:
    - Associate a User Assigned Managed Identity to Windows and Linux Virtual Machines Running on Azure
    - Deploy the Azure Monitoring Agent using the UAMI to Windows and Linux Virtual Machines Running on Azure
    - Deploy the Azure Monitoring Agent using System Assigned identity to Windows and Linux Arc Servers
    - Associate Data Collection Rules to Windows Servers, both Azure and Arc
    - Associate Data Collection Rules to Linux Servers, both Azure and Arc
- Create the appropriate RBAC assignments for a UAMI that is used for executing deployment / remediation tasks on behalf of Azure Policy.

All policy assignments are implemented using the Deploy If Not Exists effect.
- For brownfield resources, customers will need to run remediation tasks to trigger the deployment of these configurations.
- For greenfield resources, a deployment task will automatically be created to push these configurations.