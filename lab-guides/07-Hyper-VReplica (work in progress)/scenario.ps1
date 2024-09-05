
#more info:
<#
https://web.archive.org/web/20120728195145/http://blogs.technet.com/b/virtualization/
https://web.archive.org/web/20130625014312/http://blogs.technet.com/b/virtualization/

https://web.archive.org/web/20130615050509/http://blogs.technet.com/b/virtualization/archive/2012/07/26/types-of-failover-operations-in-hyper-v-replica.aspx
https://web.archive.org/web/20130615051550/http://blogs.technet.com/b/virtualization/archive/2012/07/31/types-of-failover-operations-in-hyper-v-replica-part-ii-planned-failover.aspx
https://web.archive.org/web/20130614225002/http://blogs.technet.com/b/virtualization/archive/2012/08/08/types-of-failover-operations-in-hyper-v-replica-part-iii-unplanned-failover.aspx
https://web.archive.org/web/20130614221418/http://blogs.technet.com/b/virtualization/archive/2012/08/15/configuring-hyper-v-replica-broker-using-powershell.aspx
#>

#region LAB Config

    #Site1
        #Cluster and RB Name
        $ClusterNameSite1="HVR-Site1"
        $BrokerNameSite1="HVR-Site1RB"

        #Site1Names
        $ServersSite1="S1_W2022_1","S1_W2022_2"

    #Site2
        #Cluster and RB Name
        $ClusterNameSite2="HVR-Site2"
        $BrokerNameSite2="HVR-Site2RB"

        #win2022Names
        $ServersSite2="S2_W2022_1","S2_W2022_2"

    #Site3
        #Cluster and RB Name
        $ClusterNameSite3="HVR-Site3"
        $BrokerNameSite3="HVR-Site3RB"

        #win2022Names
        $ServersSite3="S3_W2022_1","S3_W2022_2"

#endregion

#region Install roles on 2022R2 servers
    #install features for management 
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica

    #install hyper-v and clustering 
    $servers=$ServersSite1+$ServersSite2+$ServersSite3

    Invoke-Command -ComputerName $servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
    foreach ($server in $servers) {Install-WindowsFeature -Name Failover-Clustering,RSAT-Clustering-PowerShell,Hyper-V-PowerShell -ComputerName $server} 
    #restart and wait for computers
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell

#endregion

#region create Clusters

    New-Cluster -Name $ClusterNameSite1 -Node $ServersSite1
    New-Cluster -Name $ClusterNameSite2 -Node $ServersSite2
    New-Cluster -Name $ClusterNameSite3 -Node $ServersSite3
    Start-Sleep 5
    Clear-DnsClientCache

#endregion

#region Configure Site 1 Cluster

    #add csv disks
    $CSV_disks = get-disk -cimsession $ServersSite1[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -gt 10GB}
    $i=1
    foreach ($CSV_disk in $CSV_disks){
        $volumename=("CSV"+($i).ToString())
        $CSV_disk | Initialize-Disk -PartitionStyle GPT
        Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $CSV_disk ) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $volumename -CimSession $ServersSite1[0] -Confirm:$false
        $CSV_disk | set-disk -IsOffline $true
        $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNameSite1
        $clusterDisk=Add-ClusterDisk -Cluster $ClusterNameSite1 -InputObject $ClusterDisk
        $clusterDisk.name = $volumename
        $ClusterSharedVolume = Add-ClusterSharedVolume -Cluster $ClusterNameSite1 -InputObject $ClusterDisk
        $ClusterSharedVolume.Name = $volumename
        $NodeName = (Resolve-DnsName -Name $ClusterSharedVolume.OwnerNode | select -First 1).Name
        $Path = $ClusterSharedVolume.SharedVolumeInfo[0].FriendlyVolumeName.Replace( ":", "$" )
        $FullPath = Join-Path -Path "\\$NodeName" -ChildPath $Path
        Rename-Item -Path $FullPath -NewName $volumename -PassThru
        $i++
    }

    #add witness disks
    $witness_disk = get-disk -cimsession $ServersSite1[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -le 2GB}
    $witness_disk  | Initialize-Disk -PartitionStyle GPT
    Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $witness_disk) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel witness_disk -CimSession $ServersSite1[0] -Confirm:$false
    $witness_disk | Set-Disk -IsOffline $true
    $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNameSite1
    $clusterDisk=Add-ClusterDisk -Cluster $ClusterNameSite1 -InputObject $ClusterDisk
    $clusterDisk.name = "Witness Disk"
    Set-ClusterQuorum -DiskWitness $ClusterDisk -Cluster $ClusterNameSite1

    #test cluster
    Test-Cluster -Cluster $ClusterNameSite1

#endregion

#region Configure Site 2 Cluster
    #add csv disks
    $CSV_disks    = get-disk -cimsession $ServersSite2[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -gt 10GB}
    $i=1
    foreach ($CSV_disk in $CSV_disks){
        $volumename=("CSV"+($i).ToString())
        $CSV_disk      | Initialize-Disk -PartitionStyle GPT
        Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $CSV_disk ) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $volumename -CimSession $ServersSite2[0] -Confirm:$false
        $CSV_disk     | set-disk -IsOffline $true
        $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNameSite2
        $clusterDisk=Add-ClusterDisk -Cluster $ClusterNameSite2 -InputObject $ClusterDisk
        $clusterDisk.name = $volumename
        $ClusterSharedVolume = Add-ClusterSharedVolume -Cluster $ClusterNameSite2 -InputObject $ClusterDisk
        $ClusterSharedVolume.Name = $volumename
        $NodeName = ( Resolve-DnsName -Name $ClusterSharedVolume.OwnerNode | select -First 1).Name
        $Path = $ClusterSharedVolume.SharedVolumeInfo[0].FriendlyVolumeName.Replace( ":", "$" )
        $FullPath = Join-Path -Path "\\$NodeName" -ChildPath $Path
        Rename-Item -Path $FullPath -NewName $volumename -PassThru
        $i++
    }

    #add witness disks
    $witness_disk = get-disk -cimsession $ServersSite2[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -le 2GB}
    $witness_disk  | Initialize-Disk -PartitionStyle GPT
    Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $witness_disk) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel witness_disk -CimSession $ServersSite2[0] -Confirm:$false
    $witness_disk | Set-Disk -IsOffline $true
    $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNameSite2
    $clusterDisk=Add-ClusterDisk -Cluster $ClusterNameSite2 -InputObject $ClusterDisk
    $clusterDisk.name = "Witness Disk"
    Set-ClusterQuorum -DiskWitness $ClusterDisk -Cluster $ClusterNameSite2

    #test cluster
    Test-Cluster -Cluster $ClusterNameSite2

#endregion

#region Configure Site 3 Cluster
    #add csv disks
    $CSV_disks    = get-disk -cimsession $Serverssite3[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -gt 10GB}
    $i=1
    foreach ($CSV_disk in $CSV_disks){
        $volumename=("CSV"+($i).ToString())
        $CSV_disk      | Initialize-Disk -PartitionStyle GPT
        Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $CSV_disk ) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $volumename -CimSession $Serverssite3[0] -Confirm:$false
        $CSV_disk     | set-disk -IsOffline $true
        $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNamesite3
        $clusterDisk=Add-ClusterDisk -Cluster $ClusterNamesite3 -InputObject $ClusterDisk
        $clusterDisk.name = $volumename
        $ClusterSharedVolume = Add-ClusterSharedVolume -Cluster $ClusterNamesite3 -InputObject $ClusterDisk
        $ClusterSharedVolume.Name = $volumename
        $NodeName = ( Resolve-DnsName -Name $ClusterSharedVolume.OwnerNode | select -First 1).Name
        $Path = $ClusterSharedVolume.SharedVolumeInfo[0].FriendlyVolumeName.Replace( ":", "$" )
        $FullPath = Join-Path -Path "\\$NodeName" -ChildPath $Path
        Rename-Item -Path $FullPath -NewName $volumename -PassThru
        $i++
    }

    #add witness disks
    $witness_disk = get-disk -cimsession $Serverssite3[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -le 2GB}
    $witness_disk  | Initialize-Disk -PartitionStyle GPT
    Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $witness_disk) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel witness_disk -CimSession $Serverssite3[0] -Confirm:$false
    $witness_disk | Set-Disk -IsOffline $true
    $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNamesite3
    $clusterDisk=Add-ClusterDisk -Cluster $ClusterNamesite3 -InputObject $ClusterDisk
    $clusterDisk.name = "Witness Disk"
    Set-ClusterQuorum -DiskWitness $ClusterDisk -Cluster $ClusterNamesite3

    #test cluster
    Test-Cluster -Cluster $ClusterNamesite3

#endregion

#region add some blank VMs in site1
    $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterNameSite1).Name
    foreach ($CSV in $CSVs){
        1..3 | ForEach-Object {
            $VMName="TestVM$($CSV)_$_"
            Invoke-Command -ComputerName (Get-ClusterNode -Cluster $ClusterNameSite1).name[0] -ScriptBlock {
                New-VM -Name $using:VMName -NewVHDPath "c:\ClusterStorage\$using:CSV\$using:VMName\Virtual Hard Disks\$using:VMName.vhdx" -MemoryStartupBytes 32MB -NewVHDSizeBytes 32GB -Generation 2 -Path "c:\ClusterStorage\$using:CSV\"
                Start-VM -Name $using:VMName
            }
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterNameSite1
        }
    }
#endregion

#region enable Hyper-V Replica https://techcommunity.microsoft.com/t5/virtualization/hyper-v-replica-powershell-series-creating-hyper-v-replica/ba-p/381905

    #enable firewall rules on servers
    Enable-NetFirewallRule -CimSession ($ServersSite1+$ServersSite2+$ServersSite3) -DisplayName "Hyper-V Replica*"

    #add replica broker role
    Add-ClusterServerRole   -Cluster $ClusterNameSite1 -Name $BrokerNameSite1
    Add-ClusterServerRole   -Cluster $ClusterNameSite2 -Name $BrokerNameSite2
    Add-ClusterServerRole   -Cluster $ClusterNameSite3 -Name $BrokerNameSite3

    #Create temporary cluster Group
    Invoke-Command -ComputerName $CLusterNameSIte1 -ScriptBlock {
        ([wmiclass]"root\MSCluster:MSCluster_ResourceGroup").CreateGroup("$($using:BrokerNameSite1)Temp", 115) | Out-Null
    }
    Invoke-Command -ComputerName $CLusterNameSIte2 -ScriptBlock {
        ([wmiclass]"root\MSCluster:MSCluster_ResourceGroup").CreateGroup("$($using:BrokerNameSite2)Temp", 115) | Out-Null
    }
    Invoke-Command -ComputerName $CLusterNameSIte3 -ScriptBlock {
        ([wmiclass]"root\MSCluster:MSCluster_ResourceGroup").CreateGroup("$($using:BrokerNameSite3)Temp", 115) | Out-Null
    }
    
    #add resources to temp group
    Add-ClusterResource     -Cluster $ClusterNameSite1 -Name "Virtual Machine Replication Broker" -Type "Virtual Machine Replication Broker" -Group "$($BrokerNameSite1)Temp"
    Add-ClusterResource     -Cluster $ClusterNameSite2 -Name "Virtual Machine Replication Broker" -Type "Virtual Machine Replication Broker" -Group "$($BrokerNameSite2)Temp"
    Add-ClusterResource     -Cluster $ClusterNameSite3 -Name "Virtual Machine Replication Broker" -Type "Virtual Machine Replication Broker" -Group "$($BrokerNameSite3)Temp"

    #move resources to temp group
    Move-ClusterResource  -Cluster $ClusterNameSite1 -name $BrokerNameSite1 -Group "$($BrokerNameSite1)Temp"
    Move-ClusterResource  -Cluster $ClusterNameSite2 -name $BrokerNameSite2 -Group "$($BrokerNameSite2)Temp"
    Move-ClusterResource  -Cluster $ClusterNameSite3 -name $BrokerNameSite3 -Group "$($BrokerNameSite3)Temp"

    #remove original group
    Remove-ClusterGroup -Cluster $ClusterNameSite1 -name $BrokerNameSite1 -RemoveResources -Force 
    Remove-ClusterGroup -Cluster $ClusterNameSite2 -name $BrokerNameSite2 -RemoveResources -Force 
    Remove-ClusterGroup -Cluster $ClusterNameSite3 -name $BrokerNameSite3 -RemoveResources -Force 

    #add dependency
    Add-ClusterResourceDependency -Cluster $ClusterNameSite1 "Virtual Machine Replication Broker" $BrokerNameSite1
    Add-ClusterResourceDependency -Cluster $ClusterNameSite2 "Virtual Machine Replication Broker" $BrokerNameSite2
    Add-ClusterResourceDependency -Cluster $ClusterNameSite3 "Virtual Machine Replication Broker" $BrokerNameSite3
   
    #rename temp to original group name
    Get-ClusterGroup "$($BrokerNameSite1)Temp" -Cluster $ClusterNameSite1 | Foreach-Object {$_.Name = $BrokerNameSite1}
    Get-ClusterGroup "$($BrokerNameSite2)Temp" -Cluster $ClusterNameSite2 | Foreach-Object {$_.Name = $BrokerNameSite2}
    Get-ClusterGroup "$($BrokerNameSite3)Temp" -Cluster $ClusterNameSite3 | Foreach-Object {$_.Name = $BrokerNameSite3}

    #start
    Start-ClusterGroup $BrokerNameSite1 -Cluster $ClusterNameSite1
    Start-ClusterGroup $BrokerNameSite2 -Cluster $ClusterNameSite2
    Start-ClusterGroup $BrokerNameSite3 -Cluster $ClusterNameSite3

    #configure replication
    #align CSV with HVR role
    $ownernode=(Get-ClusterGroup -Cluster $ClusterNameSite1 -Name $BrokerNameSite1).OwnerNode
    Move-ClusterSharedVolume -Name CSV1 -Cluster $ClusterNameSite1 -Node $ownernode
    $ownernode=(Get-ClusterGroup -Cluster $ClusterNameSite2 -Name $BrokerNameSite2).OwnerNode
    Move-ClusterSharedVolume -Name CSV1 -Cluster $ClusterNameSite2 -Node $ownernode
    $ownernode=(Get-ClusterGroup -Cluster $ClusterNameSite3 -Name $BrokerNameSite3).OwnerNode
    Move-ClusterSharedVolume -Name CSV1 -Cluster $ClusterNameSite3 -Node $ownernode
    #configure replication
    Invoke-Command -ComputerName ($ServersSite1+$ServersSite2+$ServersSite3) -ScriptBlock {
        Set-VMReplicationServer -ReplicationEnabled $true -AllowedAuthenticationType Kerberos -ReplicationAllowedFromAnyServer $true -DefaultStorageLocation c:\Clusterstorage\CSV1
    }

    #configure Site1 to site2 replication (for some reason it randomly fails for some machines, so keep enabling until it works)
    (Get-ClusterNode -Cluster $ClusterNameSite1).Name | ForEach-Object {
        Invoke-Command -ComputerName $_ -ScriptBlock {
            $VMs=Get-VM
            foreach ($VM in $VMs){
                if ($VM.ReplicationState -eq "Disabled"){
                    $VM | Enable-VMReplication -ReplicaServerName $using:BrokerNameSite2 -ReplicaServerPort 80 -AuthenticationType Kerberos -RecoveryHistory 0 -ReplicationFrequencySec 30
                }
            }
        }
    }

    #start initial replication
    (Get-ClusterNode -Cluster $ClusterNameSite1).Name | ForEach-Object {
        Invoke-Command -ComputerName $_ -ScriptBlock {
            Get-VM | Start-VMInitialReplication
        }
    }

    #extend replication to site 3
    (Get-ClusterNode -Cluster $ClusterNameSite2).Name | ForEach-Object {
        Invoke-Command -ComputerName $_ -ScriptBlock {
            $VMs=Get-VM
            foreach ($VM in $VMs){
                $VM | Enable-VMReplication -ReplicaServerName $using:BrokerNameSite3 -ReplicaServerPort 80 -AuthenticationType Kerberos -RecoveryHistory 0 -ReplicationFrequencySec 300
            }
        }
    }

    #start initial replication
    (Get-ClusterNode -Cluster $ClusterNameSite2).Name | ForEach-Object {
        Invoke-Command -ComputerName $_ -ScriptBlock {
            Get-VM | Start-VMInitialReplication
        }
    }

#endregion

#region move all VMs to their CSVs

    foreach ($ClusterNode in ($ServersSite2,$ServersSite3)){
        $VMs=get-vm -CimSession $ClusterNode
        foreach ($VM in $VMs){
            if ($VM.Name -like "*CSV1*"){
                $PathtoCSV="C:\ClusterStorage\CSV1"
                $DestinationStoragePath="$($PathtoCSV)\$($VM.name)"
                $VM | Move-VMStorage -DestinationStoragePath $DestinationStoragePath
            }
            elseif($VM.Name -like "*CSV2*"){
                $PathtoCSV="C:\ClusterStorage\CSV2"
                $DestinationStoragePath="$($PathtoCSV)\$($VM.name)"
                $VM | Move-VMStorage -DestinationStoragePath $DestinationStoragePath
            }
            elseif($VM.Name -like "*CSV3*"){
                $PathtoCSV="C:\ClusterStorage\CSV3"
                $DestinationStoragePath="$($PathtoCSV)\$($VM.name)"
                $VM | Move-VMStorage -DestinationStoragePath $DestinationStoragePath
            }
            elseif($VM.Name -like "*CSV4*"){
                $PathtoCSV="C:\ClusterStorage\CSV4"
                $DestinationStoragePath="$($PathtoCSV)\$($VM.name)"
                $VM | Move-VMStorage -DestinationStoragePath $DestinationStoragePath
            }
        }
        
    }

#endregion

#region playing with snapshots
    Get-VMSnapshot -VMName TestVMCSV1_1 -CimSession S2_w2022_1 
#endregion

#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
 