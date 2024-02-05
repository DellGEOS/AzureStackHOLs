# Azure Stack HCI Cluster maintenance deep dive

<!-- TOC -->

- [Azure Stack HCI Cluster maintenance deep dive](#azure-stack-hci-cluster-maintenance-deep-dive)
    - [About the lab](#about-the-lab)
    - [Prerequisites](#prerequisites)
    - [Task 01 - Explore status of the Azure Stack HCI cluster](#task-01---explore-status-of-the-azure-stack-hci-cluster)
    - [Task 02 - Explore Microsoft update level of Azure Stack HCI Cluster](#task-02---explore-microsoft-update-level-of-azure-stack-hci-cluster)
    - [Task 03 - Explore missing Dell updates](#task-03---explore-missing-dell-updates)
    - [Task 04 - Perform "manual" update of Azure Stack HCI Cluster node](#task-04---perform-manual-update-of-azure-stack-hci-cluster-node)
    - [Task 05 - Perform scripted update of Azure Stack HCI Cluster](#task-05---perform-scripted-update-of-azure-stack-hci-cluster)

<!-- /TOC -->

## About the lab

This lab will help you understand cluster maintenance - both how to expore cluster status and how to perform cluster maintenance. This lab is not intended to replace [Dell OpenManage integration with Windows Admin Center](https://github.com/DellGEOS/AzureStackHOLs/blob/main/lab-guides/03-OpenManageExtensionForWAC/readme.md), it just helps explaining entire process in detail.

The lab is based on [AzSHCI and Dell Servers Update](https://github.com/microsoft/MSLab/tree/master/Scenarios/AzSHCI%20and%20Dell%20Servers%20Update) MSLab scenario.

If using virtual environment, dell DSU will obviously not work.

## Prerequisites

To perform following lab you can setup cluster using guides below:

* Hydrate MSLab with LabConfig from [01-HydrateMSLab](../../admin-guides/01-HydrateMSLab/readme.md)

* [Learn How MSLab works](../../admin-guides/02-WorkingWithMSLab/readme.md)

* [Deploy OS on hardware](../../admin-guides/03-DeployPhysicalServersWithMSLab/readme.md)

* [Deploy Azure Stack HCI with PowerShell](../../lab-guides/02-DeployAzureStackHCICluster-PowerShell/readme.md)

Or you can Azure Stack HCI cluster in VMs as demonstrated in [Azure Stack HCI Deployment MSLab Scenario](https://github.com/microsoft/MSLab/tree/master/Scenarios/AzSHCI%20Deployment).

## Task 01 - Explore status of the Azure Stack HCI cluster

> Note: Run all PowerShell code from DC or Management machine

**Step 1** Run PowerShell to fill variables and make sure all management tools are installed

```PowerShell
$ClusterName="AzSHCI-Cluster"
$Nodes=(Get-ClusterNode -Cluster $ClusterName).Name
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell
 
```

**Step 2** Run PowerShell suspend one of the nodes, so we can explore what suspending one node will do to the cluster itself.

```PowerShell
$Node=$Nodes | Select-Object -First 1
Suspend-ClusterNode -Name "$Node" -Cluster $ClusterName -Drain -Wait
 
```

![](./media/powershell01.png)

**Step 3** Explore Cluster Nodes status

```PowerShell
Get-ClusterNode -Cluster $ClusterName
 
```

![](./media/powershell02.png)

**Step 4** Explore Virtual Disk status

> Note: If everything is OK, all Virtual disks HealthStatus will report as Healthy and OperationalStatus as OK

>Note: In this case, cluster node is suspended. The Virtual Disk HealthStatus reports Warning and OperationalStatus reports Degraded.

```PowerShell
Get-VirtualDisk -CimSession $ClusterName
 
```

![](./media/powershell03.png)

**Step 5** Explore Storage Subsystem Status

> Note: Subsystem will be likely unheathy if running in VMs. You can explore more with Get-HealthFault -CimSession $ClusterName

```PowerShell
Get-StorageSubSystem -CimSession $ClusterName -FriendlyName "Clustered Windows Storage on $ClusterName"
 
```

![](./media/powershell04.png)

**Step 6** Explore Repair Jobs

```PowerShell
Get-StorageSubSystem -CimSession $ClusterName -FriendlyName "Clustered Windows Storage on $ClusterName" | Get-StorageJob -CimSession $ClusterName
 
```

![](./media/powershell05.png)

**Step 7** Explore Fault Domains

```PowerShell
Get-StorageFaultDomain -CimSession $ClusterName
 
```

![](./media/powershell06.png)

**Step 8** Explore Storage Maintenance mode

```PowerShell
Get-StorageFaultDomain -CimSession $ClusterName | Where-Object OperationalStatus -eq "In Maintenance Mode"
 
```

![](./media/powershell07.png)

**Step 9** Resume Cluster node again

```PowerShell
$Node=$Nodes | Select-Object -First 1
Resume-ClusterNode -Name "$Node" -Cluster $ClusterName -Failback Immediate
 
```

![](./media/powershell08.png)

## Task 02 - Explore Microsoft update level of Azure Stack HCI Cluster

**Step 1** Populate variables if PowerShell window was closed

```PowerShell
$ClusterName="AzSHCI-Cluster"
$Nodes=(Get-ClusterNode -Cluster $ClusterName).Name
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell
 
```

**Step 2** Explore Microsoft Update level

```PowerShell
#check OS Build Number
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
$NodesInfo  = Invoke-Command -ComputerName $nodes -ScriptBlock {
    Get-ItemProperty -Path $using:RegistryPath
}
$NodesInfo | Select-Object PSComputerName,ProductName,DisplayVersion,CurrentBuildNumber,UBR | Sort-Object PSComputerName | Format-Table -AutoSize
 
```

![](./media/powershell09.png)

> Note: As you can see, registry CurrentVersion contains multiple interesting information, such as version of Azure Stack HCI (21H2), build number and more interestingly UBR (Update Build Revision). UBR directly translates to update level. For example UBR 524 is [February 8 Security Update](https://support.microsoft.com/en-us/topic/february-8-2022-security-update-kb5010354-bc5de80a-8b86-4828-b10f-a4e81dbae329). Release information can be also found in [Microsoft Docs](https://docs.microsoft.com/en-us/azure-stack/hci/release-information#azure-stack-hci-version-21h2-os-build-20348).

## Task 03 - Explore missing Dell updates

> Note: To explore missing hardware/firmware updates command [Dell System Update](https://www.dell.com/support/home/en-us/product-support/product/system-update/docs) can be used.

> Note: You can give it a try in virtual environment, but tool will obviously fail to find any applicable update

**Step 1** Populate variables if PowerShell window was closed

```PowerShell
$ClusterName="AzSHCI-Cluster"
$Nodes=(Get-ClusterNode -Cluster $ClusterName).Name
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell
 
```

**Step 2** Download DSU tool together with Azure Stack HCI catalog to Downloads folder

```PowerShell
#download latest DSU to Downloads https://www.dell.com/support/kbdoc/en-us/000130590/dell-emc-system-update-dsu?lang=en
$LatestDSU="https://dl.dell.com/FOLDER10889507M/1/Systems-Management_Application_RPW7K_WN64_2.0.2.3_A00.EXE"
Start-BitsTransfer -Source $LatestDSU -Destination $env:UserProfile\Downloads\DSU.exe

#Download AzureStackHCI Catalog to Downloads
Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz"
 
```

![](./media/explorer01.png)

**Step 3** Unpack Azure Stack HCI catalog

```PowerShell
Function Expand-GZipArchive{
    Param(
        $infile,
        $outfile = ($infile -replace '\.gz$','')
        )
    $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
    $buffer = New-Object byte[](1024)
    while($true){
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0){break}
        $output.Write($buffer, 0, $read)
        }
    $gzipStream.Close()
    $output.Close()
    $input.Close()
}
Expand-GZipArchive "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz" "$env:UserProfile\Downloads\ASHCI-Catalog.xml"
 
```

![](./media/explorer02.png)

**Step 4** Distribute DSU and catalog to nodes

```PowerShell
$Sessions=New-PSSession -ComputerName $Nodes
$files="$env:UserProfile\Downloads\ASHCI-Catalog.xml","$env:UserProfile\Downloads\DSU.exe"
foreach ($Session in $Sessions){
    foreach ($file in $files){
        Copy-Item -Path $file -Destination $file -ToSession $Session -Recurse -Force
    }
}
$Sessions | Remove-PSSession
 
```

**Step 5** Install DSU into nodes

```PowerShell
Invoke-Command -ComputerName $Nodes -ScriptBlock {
    Start-Process -FilePath "$env:UserProfile\Downloads\DSU.exe" -ArgumentList "/silent" -Wait 
}
 
```

**Step 6** Perform update scan

```PowerShell
Invoke-Command -ComputerName $Nodes -ScriptBlock {
    & "C:\Program Files\Dell\DELL System Update\DSU.exe" --catalog-location="$env:UserProfile\Downloads\ASHCI-Catalog.xml" --preview
}
 
```

**Step 7** Display update scan results

```PowerShell
$ScanResult=Invoke-Command -ComputerName $Nodes -ScriptBlock {
(Get-content "C:\ProgramData\Dell\DELL System Update\dell_dup\DSU_STATUS.json" | ConvertFrom-JSon).systemUpdateStatus.InvokerInfo
}
$ScanResult | Select-Object PSComputerName,StatusMessage
 
```

![](./media/powershell10.png)

## Task 04 - Perform "manual" update of Azure Stack HCI Cluster node

**Step 1** Populate variables if PowerShell window was closed

```PowerShell
$ClusterName="AzSHCI-Cluster"
$Nodes=(Get-ClusterNode -Cluster $ClusterName).Name
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell
 
```

**Step 2** Check if Cluster is ready for patching

> Note: Output will be empty if all is OK

```PowerShell
#Check if all nodes are up
Get-ClusterNode -Cluster $ClusterName | Where-Object State -ne "Up"

#Check for repair jobs
Get-StorageSubSystem -CimSession $ClusterName -FriendlyName "Clustered Windows Storage on $ClusterName" | Get-StorageJob -CimSession $ClusterName

#check for unhealthy disks
Get-VirtualDisk -CimSession $ClusterName | Where-Object HealthStatus -ne "Healthy"
 
```

![](./media/powershell11.png)

**Step 3** If all checks are ok, we can select node to work with

```PowerShell
$Node=$Nodes | Out-GridView -OutputMode Single -Title "Select cluster node to suspend and patch"
 
```

![](./media/powershell12.png)


**Step 4** Make sure Dell binaries are present on server (these steps were already performed in Task 3)

```PowerShell
#download latest DSU to Downloads (link is in latest openmange users guide https://www.dell.com/support/home/en-us/product-support/product/openmanage-integration-microsoft-windows-admin-center/docs)
$LatestDSU="https://downloads.dell.com/omimswac/dsu/Systems-Management_Application_GG4YM_WN64_2.0.2.2_A00.EXE"
Start-BitsTransfer -Source $LatestDSU -Destination $env:UserProfile\Downloads\DSU.exe

#Download AzureStackHCI Catalog to Downloads
Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz"

#Expand Catalog
Function Expand-GZipArchive{
    Param(
        $infile,
        $outfile = ($infile -replace '\.gz$','')
        )
    $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
    $buffer = New-Object byte[](1024)
    while($true){
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0){break}
        $output.Write($buffer, 0, $read)
        }
    $gzipStream.Close()
    $output.Close()
    $input.Close()
}
Expand-GZipArchive "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz" "$env:UserProfile\Downloads\ASHCI-Catalog.xml"
 
#Copy files to node
$Session=New-PSSession -ComputerName $Node
$files="$env:UserProfile\Downloads\ASHCI-Catalog.xml","$env:UserProfile\Downloads\DSU.exe"
foreach ($file in $files){
        Copy-Item -Path $file -Destination $file -ToSession $Session -Recurse -Force
}
$Session | Remove-PSSession

#Install DSU
Invoke-Command -ComputerName $Node -ScriptBlock {
    Start-Process -FilePath "$env:UserProfile\Downloads\DSU.exe" -ArgumentList "/silent" -Wait 
}
 
```

**Step 4** Install all Dell updates

```PowerShell
Invoke-Command -ComputerName $Node -ScriptBlock {
    #create answerfile for DU
    $content='@
    a
    c
    @'
    Set-Content -Path "$env:UserProfile\Downloads\answer.txt" -Value $content -NoNewline
    #Create CMD to install updates
    $content='"C:\Program Files\Dell\DELL System Update\DSU.exe" --catalog-location=ASHCI-Catalog.xml --apply-upgrades <answer.txt'
    Set-Content -Path "$env:UserProfile\Downloads\install.cmd" -Value $content -NoNewline
    #install DSU updates
    Start-Process -FilePath "install.cmd" -Wait -WorkingDirectory "$env:UserProfile\Downloads"
    #display result
    Get-Content "C:\ProgramData\Dell\DELL System Update\dell_dup\DSU_STATUS.json"
}
 
```

![](./media/powershell13.png)


**Step 5** Install all available Microsoft updates

```PowerShell
#Configure virtual account to be able to deploy updates on node
    Invoke-Command -ComputerName $node -ScriptBlock {
        New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
        Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
    } -ErrorAction Ignore

#install Microsoft updates
    #configure what updates will be applied
    $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
        IsPresent=1 and DeploymentAction='Uninstallation' or
        IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
        IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
    Write-Output "$($Node):Installing Microsoft $Updates Updates"
    #perform update
    Invoke-Command -ComputerName $Node -ConfigurationName 'VirtualAccount' {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        $SearchResult = $Searcher.Search($using:SearchCriteriaAllUpdates).Updates
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Downloader = $Session.CreateUpdateDownloader()
        $Downloader.Updates = $SearchResult
        $Downloader.Download()
        $Installer = New-Object -ComObject Microsoft.Update.Installer
        $Installer.Updates = $SearchResult
        $Result = $Installer.Install()
        $Result
    }
#remove temporary virtual account config
    Invoke-Command -ComputerName $Node -ScriptBlock {
        Unregister-PSSessionConfiguration -Name 'VirtualAccount'
        Remove-Item -Path $env:TEMP\VirtualAccount.pssc
    }
 
```

![](./media/powershell14.png)

**Step 6** Suspend cluster node and enable storage maintenance mode

```PowerShell
#Suspend node
Suspend-ClusterNode -Name "$Node" -Cluster $ClusterName -Drain -Wait | Out-Null

#enable storage maintenance mode
Get-StorageFaultDomain -CimSession $ClusterName -FriendlyName $Node | Enable-StorageMaintenanceMode -CimSession $ClusterName
 
```

**Step 7** Restart node, and wait for the node to come up

```PowerShell
Restart-Computer -ComputerName $Node -Protocol WSMan -Wait -For PowerShell
 
```

**Step 8** Resume cluster node and disable storage maintenance mode

```PowerShell
#disable storage maintenance mode
Get-StorageFaultDomain -CimSession $ClusterName -FriendlyName $Node | Disable-StorageMaintenanceMode -CimSession $ClusterName

#resume cluster node
Resume-ClusterNode -Name "$Node" -Cluster $ClusterName -Failback Immediate | Out-Null
 
```

## Task 05 - Perform scripted update of Azure Stack HCI Cluster

**Step 1** Paste code from [MSLab Scenario](https://github.com/microsoft/MSLab/blob/master/Scenarios/AzSHCI%20and%20Dell%20Servers%20Update/Scenario.ps1) into PowerShell window.

> Note: You will be prompted for cluster you want to patch

![](./media/powershell15.png)