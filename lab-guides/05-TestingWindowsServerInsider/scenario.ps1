#region Variables
    #servers list
    $Servers="S2D1","S2D2"
    #alternatively you can generate server names
        #$Servers=1..2 | ForEach-Object {"S2D$_"}

    #Cluster Name
    $ClusterName="S2D-Cluster"

    #Cluster-Aware-Updating role name
    $CAURoleName="S2D-Cl-CAU" #if empty, CAU will not be installed

    #Enable Kernel Soft Reboot? https://learn.microsoft.com/en-us/azure-stack/hci/manage/kernel-soft-reboot
    $KSR=$False

    #Cluster IP
    $ClusterIP="" #If blank (you can write just $ClusterIP="", DHCP will be used). If $DistributedManagementPoint is true, then IP is not used

    #Distributed Cluster ManagementPoint? (Cluster Name in DNS will have IP of every node - like SOFS). If $ClusterIP is set, then $clusterIP will be ignored).
    $DistributedManagementPoint=$False

    #Deploy network using Network ATC? https://learn.microsoft.com/en-us/azure-stack/hci/manage/manage-network-atc?tabs=22H2
    $NetATC=$True

    #Perform Windows update? (for more info visit WU Scenario https://github.com/microsoft/WSLab/tree/dev/Scenarios/Windows%20Update)
    $WindowsUpdate="Recommended" #Can be "All","Recommended" or "None"

    #Dell updates
    $DellUpdates=$False

    #Witness type
    $WitnessType="FileShare" #or Cloud
    $WitnessServer="DC" #name of server where witness will be configured
    #if cloud then configure following (use your own, these are just examples)
    <#
    $CloudWitnessStorageAccountName="MyStorageAccountName"
    $CloudWitnessStorageKey="qi8QB/VSHHiA9lSvz1kEIEt0JxIucPL3l99nRHhkp+n1Lpabu4Ydi7Ih192A4VW42vccIgUnrXxxxxxxxxxxxx=="
    $CloudWitnessEndpoint="core.windows.net"
    #>

    #Delete Storage Pool (like after reinstall there might be data left from old cluster)
    $DeletePool=$False

#endregion

#region Update all servers (2022 and 21H2+ systems, for more info visit WU Scenario https://github.com/microsoft/MSLab/tree/dev/Scenarios/Windows%20Update)
    #check OS Build Number
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
    $ComputersInfo  = Invoke-Command -ComputerName $servers -ScriptBlock {
        Get-ItemProperty -Path $using:RegistryPath
    }
    $ComputersInfo | Select-Object PSComputerName,CurrentBuildNumber,UBR

    #Update servers
    if ($WindowsUpdate -eq "Recommended"){
        #Create virtual account to be able to run command without credssp
        Invoke-Command -ComputerName $servers -ScriptBlock {
            New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
            Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
        } -ErrorAction Ignore
        #sleep a bit
        Start-Sleep 2
        # Run Windows Update via ComObject.
        Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
            $Searcher = New-Object -ComObject Microsoft.Update.Searcher
            $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                    IsPresent=1 and DeploymentAction='Uninstallation' or
                                    IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                    IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
            $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
            if ($SearchResult.Count -gt 0){
                $Session = New-Object -ComObject Microsoft.Update.Session
                $Downloader = $Session.CreateUpdateDownloader()
                $Downloader.Updates = $SearchResult
                $Downloader.Download()
                $Installer = New-Object -ComObject Microsoft.Update.Installer
                $Installer.Updates = $SearchResult
                $Result = $Installer.Install()
                $Result
            }
        }
        #remove temporary PSsession config
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Unregister-PSSessionConfiguration -Name 'VirtualAccount'
            Remove-Item -Path $env:TEMP\VirtualAccount.pssc
        }
    }elseif ($WindowsUpdate -eq "All"){
        # Update servers with all updates (including preview)
        Invoke-Command -ComputerName $servers -ScriptBlock {
            New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
            Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
        } -ErrorAction Ignore
        #sleep a bit
        Start-Sleep 2
        # Run Windows Update via ComObject.
        Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
            $Searcher = New-Object -ComObject Microsoft.Update.Searcher
            $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                    IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                    IsPresent=1 and DeploymentAction='Uninstallation' or
                                    IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                    IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
            $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
            if ($SearchResult.Count -gt 0){
                $Session = New-Object -ComObject Microsoft.Update.Session
                $Downloader = $Session.CreateUpdateDownloader()
                $Downloader.Updates = $SearchResult
                $Downloader.Download()
                $Installer = New-Object -ComObject Microsoft.Update.Installer
                $Installer.Updates = $SearchResult
                $Result = $Installer.Install()
                $Result
            }
        }
        #remove temporary PSsession config
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Unregister-PSSessionConfiguration -Name 'VirtualAccount'
            Remove-Item -Path $env:TEMP\VirtualAccount.pssc
        }
    }
#endregion

#region install required features
    #install features for management (assuming you are running these commands on Windows Server with GUI)
    Install-WindowsFeature -Name NetworkATC,RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-AD-PowerShell,RSAT-AD-AdminCenter,RSAT-DHCP,RSAT-DNS-Server

    #install roles and features on servers
    #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
        if ($result.ExitCode -eq "failed"){
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
        }
    }
    #define and install other features
    $features="Failover-Clustering","RSAT-Clustering-PowerShell","Hyper-V-PowerShell","NetworkATC","Data-Center-Bridging","RSAT-DataCenterBridging-LLDP-Tools","FS-SMBBW","System-Insights","RSAT-System-Insights"
    #optional - affects perf even if not enabled on volumes as filter driver is attached (SR,Dedup) and also Bitlocker, that affects a little bit
    #$features+="Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","BitLocker","RSAT-Feature-Tools-BitLocker"
    Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features}
#endregion

#region configure OS settings
    #Configure Active memory dump https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
        Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
    }

    #Configure high performance power plan
    #set high performance if not VM
    Invoke-Command -ComputerName $servers -ScriptBlock {
        if ((Get-ComputerInfo).CsSystemFamily -ne "Virtual Machine"){
            powercfg /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        }
    }
    #check settings
    Invoke-Command -ComputerName $servers -ScriptBlock {powercfg /list}

    #Delete Storage Pool if there is any from last install
    if ($DeletePool){
        #Grab pools
        $StoragePools=Get-StoragePool -CimSession $Servers -IsPrimordial $False -ErrorAction Ignore
        #remove pools if any
        if ($StoragePools){
            $StoragePools | Remove-StoragePool -Confirm:0
        }
        #Reset disks (to clear spaces metadata)
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Get-PhysicalDisk -CanPool $True | Reset-PhysicalDisk
            $disks=Get-Disk | Where-Object IsBoot -eq $false
            $disks | Set-Disk -IsReadOnly $false
            $disks | Set-Disk -IsOffline $false
            $disks | Clear-Disk -RemoveData -RemoveOEM -Confirm:0
            $disks | get-disk | Set-Disk -IsOffline $true
        }
    }

    #Configure max evenlope size to be 8kb to be able to copy files using PSSession (useful for dell drivers update region and Windows Admin Center)
    Invoke-Command -ComputerName $servers -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 8192}

    #Configure MaxTimeout (10s for Dell hardware - especially if you have HDDs, 30s for Virtual environment https://learn.microsoft.com/en-us/windows-server/storage/storage-spaces/storage-spaces-direct-in-vm)
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $servers[0]).Manufacturer -like "*Dell Inc."){
        Invoke-Command -ComputerName $servers -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00002710}
    }
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $servers[0]).Model -eq "Virtual Machine"){
        Invoke-Command -ComputerName $servers -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530}
    }

#endregion

#region configure OS Security (tbd: https://aka.ms/hci-securitybase)
    #Enable secured core
    Invoke-Command -ComputerName $servers -ScriptBlock {
        #Device Guard
        #REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d 1 /f 
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
        #there s different setting for VM and Bare metal
        if ((Get-CimInstance -ClassName win32_computersystem).Model -eq "Virtual Machine"){
            REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 1 /f
        }else{
            REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 3 /f
        }
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequireMicrosoftSignedBootChain" /t REG_DWORD /d 1 /f

        #Cred Guard
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f

        #System Guard Secure Launch (bare meta only)
        #https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" /v "Enabled" /t REG_DWORD /d 1 /f

        #HVCI
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 1 /f
        #REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d 1 /f
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "HVCIMATRequired" /t REG_DWORD /d 1 /f
    }
#endregion

#region install Dell drivers https://github.com/microsoft/MSLab/tree/master/Scenarios/AzSHCI%20and%20Dell%20Servers%20Update
    if ($DellUpdates -and ((Get-CimInstance -ClassName win32_computersystem -CimSession $Servers[0]).Manufacturer -like "*Dell Inc.")){
        $DSUDownloadFolder="$env:USERPROFILE\Downloads\DSU"

        #Download DSU
        #https://github.com/DellProSupportGse/Tools/blob/main/DART.ps1
        #download latest DSU to Downloads
        $LatestDSU="https://dl.dell.com/FOLDER10889507M/1/Systems-Management_Application_RPW7K_WN64_2.0.2.3_A00.EXE"
        if (-not (Test-Path $DSUDownloadFolder -ErrorAction Ignore)){New-Item -Path $DSUDownloadFolder -ItemType Directory}
        Start-BitsTransfer -Source $LatestDSU -Destination $DSUDownloadFolder\DSU.exe

        #upload DSU to servers
        $Sessions=New-PSSession -ComputerName $Servers
        Invoke-Command -Session $Sessions -ScriptBlock {
            if (-not (Test-Path $using:DSUDownloadFolder -ErrorAction Ignore)){New-Item -Path $using:DSUDownloadFolder -ItemType Directory}
        }
        foreach ($Session in $Sessions){
            Copy-Item -Path "$DSUDownloadFolder\DSU.exe" -Destination "$DSUDownloadFolder" -ToSession $Session -Force -Recurse
        }
        $Sessions | Remove-PSSession
        #install DSU
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Start-Process -FilePath "$using:DSUDownloadFolder\DSU.exe" -ArgumentList "/silent" -Wait 
        }

        #Check compliance
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            & "C:\Program Files\Dell\DELL System Update\DSU.exe" --compliance --output-format="json" --output="$using:DSUDownloadFolder\Compliance.json"
        }         
        #collect results
        $Compliance=@()
        foreach ($Server in $Servers){
            $json=Invoke-Command -ComputerName $server -ScriptBlock {Get-Content "$using:DSUDownloadFolder\Compliance.json"}
            $object = $json | ConvertFrom-Json 
            $components=$object.SystemUpdateCompliance.UpdateableComponent
            $components | Add-Member -MemberType NoteProperty -Name "ClusterName" -Value $ClusterName
            $components | Add-Member -MemberType NoteProperty -Name "ServerName" -Value $Server
            $Compliance+=$Components
        }

        #display results
        $Compliance | Out-GridView

        #Or just choose what updates to install
        #$Compliance=$Compliance | Out-GridView -OutputMode Multiple

        #Install Dell updates https://www.dell.com/support/home/en-us/product-support/product/system-update/docs
        $UpdateNames=(($Compliance | Where-Object {$_.NodeName -eq $Node -and $_.compliancestatus -eq $false}).PackageFilePath | Split-Path -Leaf) -join ","
        Invoke-Command -ComputerName $servers -ScriptBlock {
            & "C:\Program Files\Dell\DELL System Update\DSU.exe" --update-list="$using:UpdateNames" --apply-upgrades --apply-downgrades
        }
    }
#endregion

#region restart servers to apply
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell -Force
    Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up
    #make sure computers are restarted
    Foreach ($Server in $Servers){
        do{$Test= Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM}while ($test.TcpTestSucceeded -eq $False)
    }
#endregion

#region Create cluster
    #Create Cluster
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $Servers[0]).Manufacturer -like "*Dell*"){
        #Disable USB NIC used by iDRAC to communicate to host just for test-cluster
        Disable-NetAdapter -CimSession $Servers -InterfaceDescription "Remote NDIS Compatible Device" -Confirm:0
    }
    #Test-Cluster -Node $servers -Include "Storage Spaces Direct","Inventory","Network","System Configuration","Hyper-V Configuration"
    If ($DistributedManagementPoint){
        New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType "Distributed"
    }else{
        if ($ClusterIP){
            New-Cluster -Name $ClusterName -Node $servers -StaticAddress $ClusterIP
        }else{
            New-Cluster -Name $ClusterName -Node $servers
        }
    }
    Start-Sleep 5
    Clear-DnsClientCache
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $Servers[0]).Manufacturer -like "*Dell Inc."){
        #Enable USB NIC used by iDRAC
        Enable-NetAdapter -CimSession $Servers -InterfaceDescription "Remote NDIS Compatible Device"
    }

    Start-Sleep 5
    Clear-DnsClientCache

    #Configure CSV Cache (value is in MB) - disable if SCM or VM is used. For VM it's just for labs - to save some RAM.
    if (Get-PhysicalDisk -cimsession $servers[0] | Where-Object bustype -eq SCM){
        #disable CSV cache if SCM storage is used
        (Get-Cluster $ClusterName).BlockCacheSize = 0
    }elseif ((Invoke-Command -ComputerName $servers[0] -ScriptBlock {(get-wmiobject win32_computersystem).Model}) -eq "Virtual Machine"){
        #disable CSV cache for virtual environments
        (Get-Cluster $ClusterName).BlockCacheSize = 0
    }

    #ConfigureWitness
    if ($WitnessType -eq "FileShare"){
        ##Configure Witness on WitnessServer
        #Create new directory
            $WitnessName=$Clustername+"Witness"
            Invoke-Command -ComputerName $WitnessServer -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory -ErrorAction Ignore}
            $accounts=@()
            $accounts+="$env:userdomain\$ClusterName$"
            $accounts+="$env:userdomain\$env:USERNAME"
            #$accounts+="$env:userdomain\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession $WitnessServer
        #Set NTFS permissions 
            Invoke-Command -ComputerName $WitnessServer -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
        #Set Quorum
            Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\$WitnessServer\$WitnessName"
    }elseif($WitnessType -eq $Cloud){
        Set-ClusterQuorum -Cluster $ClusterName -CloudWitness -AccountName $CloudWitnessStorageAccountName -AccessKey $CloudWitnessStorageKey -Endpoint $CloudWitnessEndpoint 
    }
#endregion

#region configure Cluster-Aware-Updating and Kernel Soft Reboot
    if ($CAURoleName){
    #Install required features on nodes.
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-WindowsFeature -Name RSAT-Clustering-PowerShell
        }
    #add role
        Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -GroupName $CAURoleName -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose
    #disable self-updating
        Disable-CauClusterRole -ClusterName $ClusterName -Force
    }
    if ($KSR){
        #list cluster parameters - as you can see, CauEnableSoftReboot does not exist
        Get-Cluster -Name $ClusterName | Get-ClusterParameter
        #let's create the value and validate
        Get-Cluster -Name $ClusterName | Set-ClusterParameter -Name CauEnableSoftReboot -Value 1 -Create
        Get-Cluster -Name $ClusterName | Get-ClusterParameter -Name CauEnableSoftReboot
        #to delete it again you can run following command
        #Get-Cluster -Name $ClusterName | Set-ClusterParameter -Name CauEnableSoftReboot -Delete
    }
#endregion

#region Configure networking with NetATC https://techcommunity.microsoft.com/t5/networking-blog/network-atc-what-s-coming-in-azure-stack-hci-22h2/ba-p/3598442
    #make sure NetATC,FS-SMBBW and other required features are installed on servers
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-WindowsFeature -Name NetworkATC,Data-Center-Bridging,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,FS-SMBBW
    }

    #if virtual environment, then skip RDMA config
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $servers[0]).Model -eq "Virtual Machine"){
        Import-Module NetworkATC
        #virtual environment (skipping RDMA config)
        $AdapterOverride = New-NetIntentAdapterPropertyOverrides
        $AdapterOverride.NetworkDirect = 0
        Add-NetIntent -ClusterName $ClusterName -Name ConvergedIntent -Management -Compute -Storage -AdapterName "Ethernet","Ethernet 2" -AdapterPropertyOverrides $AdapterOverride -Verbose #-StorageVlans 1,2
    }else{
    #on real hardware you can configure RDMA
        #grab fastest adapters names (assuming that we are deploying converged intent with just Mellanox or Intel E810)
        $FastestLinkSpeed=(get-netadapter -CimSession $Servers | Where-Object {$_.Status -eq "up" -and $_.HardwareInterface -eq $True}).Speed | Sort-Object -Descending | Select-Object -First 1
        #grab adapters
        $AdapterNames=(Get-NetAdapter -CimSession $Servers[0] | Where-Object {$_.Status -eq "up" -and $_.HardwareInterface -eq $True} | where-object Speed -eq $FastestLinkSpeed | Sort-Object Name).Name
        #$AdapterNames="SLOT 3 Port 1","SLOT 3 Port 2"
        Import-Module NetworkATC
        Add-NetIntent -ClusterName $ClusterName -Name ConvergedIntent -Management -Compute -Storage -AdapterName $AdapterNames -Verbose #-StorageVlans 1,2
    }

    #check
    Start-Sleep 20 #let intent propagate a bit
    Write-Output "applying intent"
    do {
        $status=Get-NetIntentStatus -ClusterName $ClusterName
        Write-Host "." -NoNewline
        Start-Sleep 5
    } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")

    #remove if necessary
        <#
        Invoke-Command -ComputerName $servers[0] -ScriptBlock {
            $intents = Get-NetIntent
            foreach ($intent in $intents){
                Remove-NetIntent -Name $intent.IntentName
            }
        }
        #>

        #if deploying in VMs, some nodes might fail (quarantined state) and even CNO can go to offline ... go to cluadmin and fix
            #Get-ClusterNode -Cluster $ClusterName | Where-Object State -eq down | Start-ClusterNode -ClearQuarantine
#endregion

#region configure what was/was not configured with NetATC
    if ($NetATC){
        #region Configure what NetATC is not configuring
            #disable unused adapters
            Get-Netadapter -CimSession $Servers | Where-Object Status -ne "Up" | Disable-NetAdapter -Confirm:0

            #Rename and Configure USB NICs (iDRAC Network)
            $USBNics=get-netadapter -CimSession $Servers -InterfaceDescription "Remote NDIS Compatible Device" -ErrorAction Ignore
            if ($USBNics){
                $Network=(Get-ClusterNetworkInterface -Cluster $ClusterName | Where-Object Adapter -eq "Remote NDIS Compatible Device").Network | Select-Object -Unique
                $Network.Name="iDRAC"
                $Network.Role="none"
            }

            #Configure dcbxmode to be host in charge (default is firmware in charge) on mellanox adapters (Dell recommendation)
            #Caution: This disconnects adapters!
            if ((Get-CimInstance -ClassName win32_computersystem -CimSession $servers[0]).Manufacturer -like "*Dell Inc."){
                if (Get-NetAdapter -CimSession $Servers -InterfaceDescription Mellanox*){
                    Set-NetAdapterAdvancedProperty -CimSession $Servers -InterfaceDescription Mellanox* -DisplayName 'Dcbxmode' -DisplayValue 'Host in charge'
                }
            }
            #configure larger receive buffers on Mellanox adapters
            if ((Get-CimInstance -ClassName win32_computersystem -CimSession $servers[0]).Manufacturer -like "*Dell Inc."){
                if (Get-NetAdapter -CimSession $Servers -InterfaceDescription Mellanox*){
                    Set-NetAdapterAdvancedProperty -CimSession $Servers -InterfaceDescription Mellanox* -DisplayName 'Receive buffers' -DisplayValue '4096'
                }
            }

        #endregion

        #region Check settings before applying NetATC
            #Check what networks were excluded from Live Migration
            $Networks=(Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Get-ClusterParameter -Name MigrationExcludeNetworks).Value -split ";"
            foreach ($Network in $Networks){Get-ClusterNetwork -Cluster $ClusterName | Where-Object ID -Match $Network}

            #check Live Migration option (probably bug, because it should default to SMB - version tested 1366)
            Get-VMHost -CimSession $Servers | Select-Object *Migration*

            #Check smbbandwith limit cluster settings (notice for some reason is SetSMBBandwidthLimit=1)
            Get-Cluster -Name $ClusterName | Select-Object *SMB*

            #check SMBBandwidthLimit settings (should be pouplated already with defaults on physical cluster - it calculated 1562500000 bytes per second on 2x25Gbps NICs)
            Get-SmbBandwidthLimit -CimSession $Servers

            #check VLAN settings (notice it's using Adapter Isolation, not VLAN)
            Get-VMNetworkAdapterIsolation -CimSession $Servers -ManagementOS

            #check number of live migrations (default is 1)
            get-vmhost -CimSession $Servers | Select-Object Name,MaximumVirtualMachineMigrations
        #endregion

        #region Adjust NetATC global overrides (assuming there is one vSwitch) (just an example, default settings are fine)
            $vSwitchNics=(Get-VMSwitch -CimSession $Servers[0]).NetAdapterInterfaceDescriptions
            $LinkCapacityInGbps=(Get-NetAdapter -CimSession $Servers[0] -InterfaceDescription $vSwitchNics | Measure-Object Speed -Sum).sum/1000000000

            $overrides=New-NetIntentGlobalClusterOverrides
            $overrides.MaximumVirtualMachineMigrations=4
            $overrides.MaximumSMBMigrationBandwidthInGbps=$LinkCapacityInGbps*0.4 #40%, if one switch is down, LM will not saturate bandwidth
            $overrides.VirtualMachineMigrationPerformanceOption="SMB" #in VMs is Compression selected.
            Set-NetIntent -GlobalClusterOverrides $overrides -Cluster $CLusterName

            Start-Sleep 20 #let intent propagate a bit
            Write-Output "applying overrides intent"
            do {
                $status=Get-NetIntentStatus -Globaloverrides -Cluster $CLusterName
                Write-Host "." -NoNewline
                Start-Sleep 5
            } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")
        #endregion

        #region verify settings again
            #Check Cluster Global overrides
            $GlobalOverrides=Get-Netintent -GlobalOverrides -Cluster $CLusterName
            $GlobalOverrides.ClusterOverride

            #check Live Migration option
            Get-VMHost -CimSession $Servers | Select-Object *Migration*

            #Check LiveMigrationPerf option and Limit (SetSMBBandwidthLimit was 1, now is 0)
            Get-Cluster -Name $ClusterName | Select-Object *SMB*

            #check SMBBandwidthLimit settings
            Get-SmbBandwidthLimit -CimSession $Servers

            #check number of live migrations
            get-vmhost -CimSession $Servers | Select-Object Name,MaximumVirtualMachineMigrations

            #check it in cluster (is only 1 - expected)
            get-cluster -Name $ClusterName | Select-Object Name,MaximumParallelMigrations

        #endregion

        #remove net intent global overrides if necessary
        <#
            Remove-NetIntent -GlobalOverrides -Cluster $ClusterName
            $overrides=New-NetIntentGlobalClusterOverrides
            #add empty intent
            Add-NetIntent -GlobalClusterOverrides $overrides -Cluster $ClusterName
        }
        #>
    }
#endregion

#region Create Fault Domains (just an example) https://docs.microsoft.com/en-us/windows-server/failover-clustering/fault-domains
#note: it is useful to describe location as when fault will happen, in fault description will be location of affected cluster
    #Describe Rack
    $RackFD=New-ClusterFaultDomain -Name "Rack01" -FaultDomainType Rack -Location "Contoso HQ, Room 4010, Aisle A, Rack 01" -CimSession $ClusterName

    #describe Site
    $SiteFD=New-ClusterFaultDomain -Name "SEA" -FaultDomainType Site -Location "Contoso HQ, 123 Example St, Room 4010, Seattle" -CimSession $ClusterName

    #Add nodes to rack
    Foreach ($Server in $Servers) {
        Set-ClusterFaultDomain -Name $Server  -Parent $RackFD.Name -CimSession $ClusterName
    }

    #Add rack to site
    Set-ClusterFaultDomain -Name $RackFD.Name -Parent $SiteFD.Name -CimSession $ClusterName

    #remove default site
    #Get-ClusterFaultDomain -CimSession $ClusterName -Name site* | Remove-ClusterFaultDomain
    
    #validate
    Get-ClusterFaultDomainxml -CimSession $ClusterName

#region more Examples using XML
<#
$numberofnodes=4
$ServersNamePrefix="Axnode"

if ($numberofnodes -eq 4){
    $xml =  @"
<Topology>
<Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
    <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
            <Node Name="$($ServersNamePrefix)1"/>
            <Node Name="$($ServersNamePrefix)2"/>
            <Node Name="$($ServersNamePrefix)3"/>
            <Node Name="$($ServersNamePrefix)4"/>
    </Rack>
</Site>
</Topology>
"@

    Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
}

if ($numberofnodes -eq 8){
    $xml =  @"
<Topology>
<Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
    <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
        <Node Name="$($ServersNamePrefix)1"/>
        <Node Name="$($ServersNamePrefix)2"/>
    </Rack>
    <Rack Name="Rack02" Location="Contoso HQ, Room 4010, Aisle A, Rack 02">
        <Node Name="$($ServersNamePrefix)3"/>
        <Node Name="$($ServersNamePrefix)4"/>
    </Rack>
    <Rack Name="Rack03" Location="Contoso HQ, Room 4010, Aisle A, Rack 03">
        <Node Name="$($ServersNamePrefix)5"/>
        <Node Name="$($ServersNamePrefix)6"/>
    </Rack>
    <Rack Name="Rack04" Location="Contoso HQ, Room 4010, Aisle A, Rack 04">
        <Node Name="$($ServersNamePrefix)7"/>
        <Node Name="$($ServersNamePrefix)8"/>
    </Rack>
</Site>
</Topology>
"@

    Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
}

if ($numberofnodes -eq 16){
    $xml =  @"
<Topology>
<Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
    <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
        <Chassis Name="Chassis01" Location="Rack Unit 1 (Upper)" >
            <Node Name="$($ServersNamePrefix)1"/>
            <Node Name="$($ServersNamePrefix)2"/>
            <Node Name="$($ServersNamePrefix)3"/>
            <Node Name="$($ServersNamePrefix)4"/>
        </Chassis>
        <Chassis Name="Chassis02" Location="Rack Unit 1 (Upper)" >
            <Node Name="$($ServersNamePrefix)5"/>
            <Node Name="$($ServersNamePrefix)6"/>
            <Node Name="$($ServersNamePrefix)7"/>
            <Node Name="$($ServersNamePrefix)8"/>
        </Chassis>
        <Chassis Name="Chassis03" Location="Rack Unit 1 (Lower)" >
            <Node Name="$($ServersNamePrefix)9"/>
            <Node Name="$($ServersNamePrefix)10"/>
            <Node Name="$($ServersNamePrefix)11"/>
            <Node Name="$($ServersNamePrefix)12"/>
        </Chassis>
        <Chassis Name="Chassis04" Location="Rack Unit 1 (Lower)" >
            <Node Name="$($ServersNamePrefix)13"/>
            <Node Name="$($ServersNamePrefix)14"/>
            <Node Name="$($ServersNamePrefix)15"/>
            <Node Name="$($ServersNamePrefix)16"/>
        </Chassis>
    </Rack>
</Site>
</Topology>
"@
    Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
}

#show fault domain configuration
    Get-ClusterFaultDomainxml -CimSession $ClusterName

#>
#endregion

#region more examples using PowerShell
<#
$numberofnodes=4
$ServersNamePrefix="Axnode"

if ($numberofnodes -eq 4){
    New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName

    1..4 | ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_"  -Parent "Rack01" -CimSession $ClusterName}
    Set-ClusterFaultDomain -Name "Rack01" -Parent "SEA"    -CimSession $ClusterName

}

if ($numberofnodes -eq 8){
    New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Rack02"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 02"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Rack03"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 03"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Rack04"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 04"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName

    1..2 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack01"    -CimSession $ClusterName}
    3..4 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack02"    -CimSession $ClusterName}
    5..6 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack03"    -CimSession $ClusterName}
    7..8 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack04"    -CimSession $ClusterName}
    1..4 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}
}

if ($numberofnodes -eq 16){
    New-ClusterFaultDomain -Name "Chassis01" -FaultDomainType Chassis -Location "Rack Unit 1 (Upper)"                               -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Chassis02" -FaultDomainType Chassis -Location "Rack Unit 1 (Upper)"                               -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Chassis03" -FaultDomainType Chassis -Location "Rack Unit 1 (Lower)"                               -CimSession $ClusterName 
    New-ClusterFaultDomain -Name "Chassis04" -FaultDomainType Chassis -Location "Rack Unit 1 (Lower)"                               -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName

    1..4   |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis01" -CimSession $ClusterName}
    5..8   |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis02" -CimSession $ClusterName}
    9..12  |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis03" -CimSession $ClusterName}
    13..16 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis04" -CimSession $ClusterName}

    1..4   |ForEach-Object {Set-ClusterFaultDomain -Name "Chassis0$_" -Parent "Rack01"    -CimSession $ClusterName}
    
    1..1 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}

}
#>
#endregion

#endregion

#region Enable S2D
    #Enable-ClusterS2D
    Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

    #display pool
        Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName

    #Display disks
        Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName | Get-PhysicalDisk -CimSession $ClusterName

    #Get Storage Tiers
        Get-StorageTier -CimSession $ClusterName

    #display pool defaults
        Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName
#endregion

#region create sample volumes
    #create 1TB volume on each node
    foreach ($Server in $Servers){
        New-Volume -StoragePoolFriendlyName  "S2D on $ClusterName" -FriendlyName $Server -Size 1TB -CimSession $ClusterName
    }

    #align volumes ownership to with servers
    foreach ($Server in $Servers){
        Move-ClusterSharedVolume -Name "Cluster Virtual Disk ($Server)" -Node $Server -Cluster $ClusterName
    }
#endregion

#region (optional) Install Windows Admin Center Gateway https://github.com/microsoft/MSLab/tree/master/Scenarios/Windows%20Admin%20Center%20and%20Enterprise%20CA#gw-mode-installation-with-self-signed-cert
    ##Install Windows Admin Center Gateway 
    $GatewayServerName="WACGW"
    #Download Windows Admin Center if not present
    if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")){
        Start-BitsTransfer -Source https://aka.ms/WACDownload -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
        #Or preview (not updated for some time)
        #Start-BitsTransfer -Source https://aka.ms/WACInsiderDownload -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
    }
    #Create PS Session and copy install files to remote server
    #make sure maxevenlope is 8k
    Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 8192}
    $Session=New-PSSession -ComputerName $GatewayServerName
    Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

    #Install Windows Admin Center
    Invoke-Command -Session $session -ScriptBlock {
        Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SSL_CERTIFICATE_OPTION=generate"
    } -ErrorAction Ignore

    $Session | Remove-PSSession

    #Configure Resource-Based constrained delegation
    Install-WindowsFeature -Name RSAT-AD-PowerShell
    $gatewayObject = Get-ADComputer -Identity $GatewayServerName
    $computers = (Get-ADComputer -Filter {OperatingSystem -eq "Azure Stack HCI"}).Name

    foreach ($computer in $computers){
        $computerObject = Get-ADComputer -Identity $computer
        Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
    }

    #update installed extensions
    #https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/configure/use-powershell
        #Copy Posh Modules from wacgw
        $Session=New-PSSession -ComputerName $GatewayServerName
        Copy-Item -Path "C:\Program Files\Windows Admin Center\PowerShell\" -Destination "C:\Program Files\Windows Admin Center\PowerShell\" -Recurse -FromSession $Session
        $Session | Remove-PSSession

        #Import Posh Modules
        $Items=Get-ChildItem -Path "C:\Program Files\Windows Admin Center\PowerShell\Modules" -Recurse | Where-Object Extension -eq ".psm1"
        foreach ($Item in $Items){
            Import-Module $Item.fullName
        }

        #list commands
        Get-Command -Module ExtensionTools

        #grab installed extensions 
        $InstalledExtensions=Get-Extension -GatewayEndpoint https://$GatewayServerName  | Where-Object status -eq Installed
        $ExtensionsToUpdate=$InstalledExtensions | Where-Object IsLatestVersion -eq $False

        foreach ($Extension in $ExtensionsToUpdate){
            Update-Extension -GatewayEndpoint https://$GatewayServerName -ExtensionId $Extension.ID
        }
#endregion
