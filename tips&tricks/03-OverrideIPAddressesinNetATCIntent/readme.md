# Override IP addresses in NetATC intent

This guide assumes you are running Windows Server 2025 as management machine (it contains network ATC powershell module).

## Identify storage network intent and configure IP override

```PowerShell
$ClusterName="AXClus02"

#make sure NetworkATC is installed
Add-WindowsFeature -Name NetworkATC

#find storage network intent
$intent=Get-NetIntent -ClusterName $ClusterName | Where-Object IntentName -like *storage*

#explore IP override settings
$intent.IPOverride

#configure new override
$Override=New-NetIntentStorageOverrides
$override.EnableAutomaticIPGeneration=$false
Set-NetIntent -ClusterName $ClusterName -Name $intent.IntentName -StorageOverrides $override

#check the setting
(Get-NetIntent -ClusterName $ClusterName -Name $intent.IntentName).IPOverride

```

## Change IP Adresses

Note: This code assumes that you have just 2 SMB NICs. With more just modify the code or let me know and I'll adapt it.

```PowerShell
#find storage network intent
$intent=Get-NetIntent -ClusterName $ClusterName | Where-Object IntentName -like *storage*

#identify adapter names
$AdapterNames=$intent.NetAdapterNamesAsList
$AdapterNames

#if it's only storage, then you'll need to change IP addresses on $adapternames. If it's converged, then adapters will be vSMB(intentname)
if ($intent.IsOnlyStorage){
    $Adapters=$AdapterNames
}else{
    $Adapters=@()
    foreach ($AdapterName in $AdapterNames){
        $Adapters+="vSMB($($intent.IntentName)#$AdapterName)"
    }
}
$Adapters

#and now let's configure static IP address
$Stornet1="172.16.1."
$Stornet2="172.16.2."
$StartIP=1
$Servers=(Get-ClusterNode -Cluster $ClusterName).Name

foreach ($Server in $Servers){
    New-NetIPAddress -IPAddress ($StorNet1+$StartIP.ToString()) -InterfaceAlias $Adapters[0] -CimSession $Server -PrefixLength 24
    New-NetIPAddress -IPAddress ($StorNet2+$StartIP.ToString()) -InterfaceAlias $Adapters[1] -CimSession $Server -PrefixLength 24
    $StartIP++
}

#check IP Adresses
Get-NetIPAddress -CimSession $Servers -AddressFamily IPv4 -InterfaceAlias vsmb* | Select IPAddress,Interfacealias,PSComputername

```

## Revert back

```PowerShell

foreach ($adapter in $Adapters){
    Remove-NetIPAddress -InterfaceAlias $adapter -AddressFamily IPv4 -cimsession $Servers -Confirm:0
}

#find storage network intent
$intent=Get-NetIntent -ClusterName $ClusterName | Where-Object IntentName -like *storage*

#configure new override
$Override=New-NetIntentStorageOverrides
$override.EnableAutomaticIPGeneration=$true
Set-NetIntent -ClusterName $ClusterName -Name $intent.IntentName -StorageOverrides $override

#check the setting
(Get-NetIntent -ClusterName $ClusterName -Name $intent.IntentName).IPOverride

#check IP Adresses (takes some time)
start-sleep 30
Get-NetIPAddress -CimSession $Servers -AddressFamily IPv4 -InterfaceAlias vsmb* | Select IPAddress,Interfacealias,PSComputername

```