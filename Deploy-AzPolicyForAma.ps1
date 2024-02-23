<#
Assign RBAC
Set this to $true if you want to manually assign the Policy UAMI RBAC Permissions.
This may be needed if the person creating the policy assignments does not have
User Access Administrator or RBAC Permissions on the designated scopes.
#>
$assignRbac = $true 

<# 
Assign Policy
Set this to $true if you want the policy assignments to be created with this script.
This may need to be set to $false if you want someone to manually run this script for RBAC only purposes.
#>
$assignPolicy = $true

<#
Tenant Id / Subscription ID Placeholder - Used in Testing with a Subscription Scope
#>
$tenantId = "00000000-0000-0000-0000-000000000000"
$subscriptionId = "00000000-0000-0000-0000-000000000000"
$rgName = "rgName"

<#
User Assigned Managed Identity to be assigned to the Azure Virtual Machines
#>
$vmUAMIsubId = "00000000-0000-0000-0000-000000000000"
$vmUAMIrgName = "vm-uami-rgName"
$vmUAMIname = "vm-uami-name" 
$vmUAMIid = "/subscriptions/$($vmUAMIsubId)/resourceGroups/$($vmUAMIrgName)/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($vmUAMIname)"

<#
User Assigned Managed Identity leveraged by Azure Policy for Remediation Tasks
#>
$policyUAMIsubId = "00000000-0000-0000-0000-000000000000"
$policyUAMIrgName = "policy-uami-rgName"
$policyUAMIname = "policy-uami-name"
$policyUAMIid = "/subscriptions/$($policyUAMIsubId)/resourceGroups/$($policyUAMIrgName)/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($policyUAMIname)"

<#
Azure Resource Location to Save Custom Policy Definitions
#>
#$policySaveLocation = "/providers/Microsoft.Management/managementGroups/$($tenantId)" # For Management Groups
$policySaveLocation = "/subscriptions/$($subscriptionId)" # For Subscriptions

<#
Azure Scope to Assign Policy Definitions
#>
#$policyScope = "/providers/Microsoft.Management/managementGroups/$($tenantId)" # For Management Groups: Tenant Root Group
$policyScope = "/subscriptions/$($subscriptionId)" # For Subscriptions
#$policyScope = "/subscriptions/$($subscriptionId)/resourceGroups/$($rgName)" # For Resource Groups

<#
Data Collection Rule Ids
#>
$dcrSubscriptionId = "00000000-0000-0000-0000-000000000000"
$dcrRgName = "dcr-rgName"

$dcrWindowsGeneralName = "prod-sentinel-windows-dcr"
$dcrWindowsAddsName = "prod-sentinel-windows-ad-dcr"
$dcrWindowsAddsDnsName = "prod-sentinel-windows-ad-dns-dcr"
$dcrLinuxGeneralName = "prod-sentinel-linux-dcr"

$windowsGeneralDcrId = "/subscriptions/$($dcrSubscriptionId)/resourceGroups/$($dcrRgName)/providers/Microsoft.Insights/dataCollectionRules/$($dcrWindowsGeneralName)"
$windowsAddsDcrId = "/subscriptions/$($dcrSubscriptionId)/resourceGroups/$($dcrRgName)/providers/Microsoft.Insights/dataCollectionRules/$($dcrWindowsAddsName)"
$windowsAddsDnsDcrId = "/subscriptions/$($dcrSubscriptionId)/resourceGroups/$($dcrRgName)/providers/Microsoft.Insights/dataCollectionRules/$($dcrWindowsAddsDnsName)"
$linuxGeneralDcrId = "/subscriptions/$($dcrSubscriptionId)/resourceGroups/$($dcrRgName)/providers/Microsoft.Insights/dataCollectionRules/$($dcrLinuxGeneralName)"

<#
Windows DCR Tagging
#>
$windowsExclude_TagName = "DCR-Windows-General"
$windowsExclude_TagValues = @( "False" )
$windowsAd_TagName = "DCR-Windows-AD"
$windowsAd_TagValues = @( "True" )
$windowsAdDns_TagName = "DCR-Windows-AD-DNS"
$windowsAdDns_TagValues = @( "True" )

<#
Azure Policy Definition Ids that will be used in this script
If you want to custom definite the Resource Id for these policies, then enter the Resource Id in the value.
If you want the script to search for the Resource Id, then leave the value as an empty string.
#>
$policyDefinitionIdsToUse = @{
    'd367bd60-64ca-4364-98ea-276775bddd94' = ""
    '637125fd-7c39-4b94-bb0a-d331faf333a9' = ""
    'eab1f514-22e3-42e3-9a1f-e1dc9199355c' = ""
    '94f686d6-9a24-4e19-91f1-de937dc171a4' = ""
    'ae8a10e6-19d6-44a3-a02d-a2bdfc707742' = ""
    '2ea82cdd-f2e8-4500-af75-67a2e084ca74' = ""
    '845857af-0333-4c5d-bbbc-6076697da122' = ""
}


<#
Import Custom Azure Policy Definitions from *.policyDefinition.json files (if not already imported)
#>
$policyDefRoot = '/providers/Microsoft.Authorization/policyDefinitions/'
$customPolicyDefinitionList = Get-AzPolicyDefinition -Custom
$customPolicyDefinitionFiles = Get-ChildItem -Path "./policyDefinitions" -Filter *.policyDefinition.json
foreach ( $file in $customPolicyDefinitionFiles ) {
    $policy = Get-Content -Path $file.FullName | ConvertFrom-Json
    $policyPath = "$($policySaveLocation)$($policyDefRoot)$($policy.name)"

    if ( $policyPath -notin $customPolicyDefinitionList.PolicyDefinitionId ) {
        $resName = $policySaveLocation.split("/")[-1]
        if ( $policySaveLocation -like "/providers/Microsoft.Management/managementGroups/*" ) {
            New-AzPolicyDefinition -Name $policy.name -Policy $file.FullName -ManagementGroupName $resName
        }
        elseif ( $policySaveLocation -like "/subscriptions/*" ) {
            New-AzPolicyDefinition -Name $policy.name -Policy $file.FullName -SubscriptionId $resName
        }
    }
}

<#
PolicyDefinitionId Reference Mapping
This section aquires the appropriate Policy Definition Ids (Custom or Built-In) to use in the Policy Assignments.
The only changes 
#>
$customPolicyDefinitionList = Get-AzPolicyDefinition -Custom
$builtinPolicyDefinitionList = Get-AzPolicyDefinition -BuiltIn
$defIds = @()
foreach( $_ in $policyDefinitionIdsToUse.Keys ) {
    if ( $_ -ne "" -and $policyDefinitionIdsToUse.$($_) -eq "" ) {
        $defIds += $_
    }
}
foreach ( $defId in $defIds ) {
    # If Policy Definition Id Resource Id has alreayd been entered above, then do not search
    #if ( $defId -eq "" -or $policyDefinitionIdsToUse.$($defId) -ne "" ) {
    #    Write-Host( "Skipping: $($defId)" )
    #    continue
    #} 
    
    # Does a Custom or Built-In Policy Definition Id exist?  (Custom Gets Priority over Built-In)
    $customPolicyPath = "$($policySaveLocation)$($policyDefRoot)$($defId)"
    $builtInPolicyPath = "$($policyDefRoot)$($defId)"
    if ( $customPolicyPath -in $customPolicyDefinitionList.PolicyDefinitionId ) {
        $policyDefinitionIdsToUse.$($defId) = $customPolicyPath
    } elseif ( $builtInPolicyPath -in $builtinPolicyDefinitionList.PolicyDefinitionId ) {
        $policyDefinitionIdsToUse.$($defId) = $builtInPolicyPath
    } else {
        throw( "Policy Definition Id not found: $($defId)." )
    }
}

<#
List of Policy Assignments to Create
- assignmentName = Policy Assignment Name
- policyDefId = Policy Definition Id to Assign
- policySetDefId = Policy Set Definition Id to Assign
- scopes = List of Scopes to Assign the Policy to
    typical values include:
    - /subscriptions/{subscriptionId}
    - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
    - /managementGroups/{managementGroupId}
- parameters = Policy or Policy Set Parameters
- roles = List of RBAC Roles to Assign to the Policy UAMI
#> 
$assignments = @{
    "1.1" = @{
        "assignmentName" = "Policy-1.1"
        "policyDefId" = "$($policyDefinitionIdsToUse.'d367bd60-64ca-4364-98ea-276775bddd94')"
        "scopes" = @( $policyScope )
        "parameters" = @{
            "userAssignedManagedIdentityResourceId" = $vmUAMIid
            "effect" = "DeployIfNotExists"
        }
        "roles" = @(
            "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c" #User Access Administrator
            "/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" #Contributor
        )
    }
    "1.2" = @{
        "assignmentName" = "Policy-1.2"
        "policyDefId" = "$($policyDefinitionIdsToUse.'637125fd-7c39-4b94-bb0a-d331faf333a9')"
        "scopes" = @( $policyScope )
        "parameters" = @{
            "userAssignedManagedIdentityResourceId" = $vmUAMIid
            "scopeToSupportedImages" = $true
            "listOfWindowsImageIdToInclude" = @()
            "effect" = "DeployIfNotExists"
        }
        "roles" = @(
            "/providers/microsoft.authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c" #Virtual Machine Contributor
        )
    }
    "1.3" = @{
        "assignmentName" = "Policy-1.3"
        "policyDefId" = "$($policyDefinitionIdsToUse.'eab1f514-22e3-42e3-9a1f-e1dc9199355c')"
        "scopes" = @( $policyScope )
        "parameters" = @{
            "listOfWindowsImageIdToInclude" = @()
            "dcrResourceId" = $windowsGeneralDcrId
            "resourceType" = "Microsoft.Insights/dataCollectionRules"
            "tagAction" = "exclude"
            "tagName" = $windowsExclude_TagName
            "tagValues" = $windowsExclude_TagValues
            "effect" = "DeployIfNotExists"
        }
        "roles" = @(
            "/providers/microsoft.authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa" #Monitoring Contributor
            "/providers/microsoft.authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293" #Log Analytics Contributor
        )
    }
    "1.4" = @{
        "assignmentName" = "Policy-1.4"
        "policyDefId" = "$($policyDefinitionIdsToUse.'eab1f514-22e3-42e3-9a1f-e1dc9199355c')"
        "scopes" = @( $policyScope )
        "parameters" = @{
            "listOfWindowsImageIdToInclude" = @()
            "dcrResourceId" = $windowsAddsDcrId
            "resourceType" = "Microsoft.Insights/dataCollectionRules"
            "tagAction" = "include"
            "tagName" = $windowsAd_TagName
            "tagValues" = $windowsAd_TagValues
            "effect" = "DeployIfNotExists"
        }
        "roles" = @(
            "/providers/microsoft.authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa" #Monitoring Contributor
            "/providers/microsoft.authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293" #Log Analytics Contributor
        )
    }
    "1.5" = @{
        "assignmentName" = "Policy-1.5"
        "policyDefId" = "$($policyDefinitionIdsToUse.'eab1f514-22e3-42e3-9a1f-e1dc9199355c')"
        "scopes" = @( $policyScope )
        "parameters" = @{
            "listOfWindowsImageIdToInclude" = @()
            "dcrResourceId" = $windowsAddsDnsDcrId
            "resourceType" = "Microsoft.Insights/dataCollectionRules"
            "tagAction" = "include"
            "tagName" = $windowsAdDns_TagName
            "tagValues" = $windowsAdDns_TagValues
            "effect" = "DeployIfNotExists"
        }
        "roles" = @(
            "/providers/microsoft.authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa" #Monitoring Contributor
            "/providers/microsoft.authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293" #Log Analytics Contributor
        )
    }
    "1.6" = @{
        "assignmentName" = "Policy-1.6"
        "policyDefId" = "$($policyDefinitionIdsToUse.'94f686d6-9a24-4e19-91f1-de937dc171a4')"
        "scopes" = @( $policyScope )
        "parameters" = @{
            "effect" = "DeployIfNotExists"
        }
        "roles" = @(
            "/providers/Microsoft.Authorization/roleDefinitions/cd570a14-e51a-42ad-bac8-bafd67325302" #Azure Connected Machine Resource Administrator
        )
    }
    "1.7" = @{
        "assignmentName" = "Policy-1.7"
        "policyDefId" = "$($policyDefinitionIdsToUse.'ae8a10e6-19d6-44a3-a02d-a2bdfc707742')"
        "scopes" = @( $policyScope )
        "parameters" = @{
            "userAssignedManagedIdentityResourceId" = $vmUAMIid
            "scopeToSupportedImages" = $true
            "listOfLinuxImageIdToInclude" = @()
            "effect" = "DeployIfNotExists"
        }
        "role" = @(
            "/providers/microsoft.authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c" #Virtual Machine Contributor
        )
    }
    "1.8" = @{
        "assignmentName" = "Policy-1.8"
        "policyDefId" = "$($policyDefinitionIdsToUse.'2ea82cdd-f2e8-4500-af75-67a2e084ca74')"
        "scopes" = @( $policyScope )
        "parameters" = @{
            "listOfLinuxImageIdToInclude" = @()
            "dcrResourceId" = $linuxgeneralDcrId
            "resourceType" = "Microsoft.Insights/dataCollectionRules"
            "effect" = "DeployIfNotExists"
        }
        "roles" = @(
            "/providers/microsoft.authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa" #Monitoring Contributor
            "/providers/microsoft.authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293" #Log Analytics Contributor
        )
    }
    "1.9" = @{
        "assignmentName" = "Policy-1.9"
        "policyDefId" = "$($policyDefinitionIdsToUse.'845857af-0333-4c5d-bbbc-6076697da122')"
        "scopes" = @( $policyScope )
        "parameters" = @{
            "effect" = "DeployIfNotExists"
        }
        "roles" = @(
            "/providers/Microsoft.Authorization/roleDefinitions/cd570a14-e51a-42ad-bac8-bafd67325302" #Azure Connected Machine Resource Administrator
        )
    }
}

# Create RBAC Assignments
if ( $assignRbac ) { 
    $policyUAMIdata = $policyUAMIid.Split("/")
    $policyUAMI = Get-AzUserAssignedIdentity -Name $policyUAMIdata[8] -ResourceGroupName $policyUAMIdata[4] -SubscriptionId $policyUAMIdata[2]

    foreach ($key in $assignments.Keys) {
        $assignValue = $assignments.$key
        foreach ($scope in $assignValue.scopes) {
            foreach ($roleId in $assignValue.roles) { 
                New-AzRoleAssignment -ObjectId $policyUAMI.PrincipalId -RoleDefinitionId $roleId.split("/")[4] -Scope $scope -ErrorAction SilentlyContinue
            }
        }
    }
}

# Create Azure Policy Assignments
$newPolicyAssignments = @()
if ( $assignPolicy ) {
    $policyUAMIdata = $policyUAMIid.Split("/")
    $policyUAMI = Get-AzUserAssignedIdentity -Name $policyUAMIdata[8] -ResourceGroupName $policyUAMIdata[4] -SubscriptionId $policyUAMIdata[2]

    foreach ($key in $assignments.Keys) {
        $assignValue = $assignments.$key
        foreach ($scope in $assignValue.scopes) {
            if ( $null -ne $assignValue.policyDefId -and $null -ne $assignValue.policySetDefId ) {
                Write-Error "Policy Definition and Policy Set Definition are both set. Please only set one or the other."
                break
            } elseif ( $null -ne $assignValue.policyDefId ) {
                $policyDefObj = Get-AzPolicyDefinition -Id $assignValue.policyDefId
                $newPolicyAssignments += New-AzPolicyAssignment `
                    -Name $assignValue.assignmentName `
                    -DisplayName $assignValue.assignmentName `
                    -PolicyDefinition $policyDefObj `
                    -PolicyParameterObject $assignValue.parameters `
                    -Scope $scope `
                    -IdentityType "UserAssigned" `
                    -IdentityId $policyUAMI.Id `
                    -Location $policyUAMI.Location `
                    -ErrorAction Continue
            } elseif ( $null -ne $assignValue.policySetDefId ) {
                $policySetObj = Get-AzPolicySetDefinition -Id $assignValue.policySetDefId
                $newPolicyAssignments += New-AzPolicyAssignment `
                    -Name $assignValue.assignmentName `
                    -DisplayName $assignValue.assignmentName `
                    -PolicySetDefinition $policySetObj `
                    -PolicyParameterObject $assignValue.parameters `
                    -Scope $scope `
                    -IdentityType "UserAssigned" `
                    -IdentityId $policyUAMI.Id `
                    -Location $policyUAMI.Location `
                    -ErrorAction Continue
            } else {
                Write-Error "Policy Definition or Policy Set Definition is not set. Please set one or the other."
            }
        }
    }
}
