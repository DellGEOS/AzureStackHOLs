# Deploy Azure Stack HCI Cluster with Windows Admin Center

<!-- TOC -->

- [Deploy Azure Stack HCI Cluster with Windows Admin Center](#deploy-azure-stack-hci-cluster-with-windows-admin-center)
    - [About the lab](#about-the-lab)
    - [Prerequisites](#prerequisites)
    - [LabConfig](#labconfig)
    - [Task 01 - Deploy Windows Admin Center](#task-01---deploy-windows-admin-center)
        - [Task01a - Deploy Windows Admin Center in GW mode](#task01a---deploy-windows-admin-center-in-gw-mode)
        - [Task01b - Deploy Windows Admin Center on Windows Client Operating system](#task01b---deploy-windows-admin-center-on-windows-client-operating-system)
    - [Task02 - create Azure Stack HCI cluster with Windows Admin Center](#task02---create-azure-stack-hci-cluster-with-windows-admin-center)
        - [Get Started tab](#get-started-tab)
        - [Networking tab](#networking-tab)
        - [Clustering](#clustering)
        - [Storage](#storage)
        - [SDN](#sdn)
    - [Connect to Cluster](#connect-to-cluster)

<!-- /TOC -->

## About the lab

In this lab you will deploy 4 node Azure Stack HCI cluster using Cluster Creation Extension in Windows Admin Center. To simplify lab, Windows Admin Center will be running on Windows Server "WACGW" and you will log into "DC" virtual machine to manage the lab.

Optionally you can deploy Windows 11 machine, and test Azure Stack HCI deployment from there

You can also deploy real physical servers and try deploymemt either from WACGW or Windows 11 VM.

## Prerequisites

* Hydrated MSLab with LabConfig from [01-HydrateMSLab](admin-guides/01-HydrateMSLab/readme.md)

* Understand [how MSLab works](admin-guides/02-WorkingWithMSLab/readme.md)

* Optional - [OS deployed on hardware](admin-guides/03-DeployPhysicalServersWithMSLab/readme.md)

* Optional - Windows 10 or 11 VHD, created with CreateParentDisk.ps1. You can download Windows Client Operating system in [eval center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)

## LabConfig

Below LabConfig will deploy 4 nodes for Azure Stack HCI 21H2. You can modify number of Virtual Machines by modyfing number. You can also modify Parent Disk Name by modifying ParentVHD property.

To deploy not domained VMs, you can uncomment the code for adding not domain joined VMs.

To deploy Windows 11, you can uncomment code for Windows 11 as management machine.

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; DCEdition='4'; Internet=$true ; VMs=@()}

#pre-domain joined
1..4 | ForEach-Object {$VMNames="AzSHCI" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB; MGMTNICs=4 ; NestedVirt=$true}} 

#optional not domain joined
#1..4 | ForEach-Object {$VMNames="AzSHCI" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB; MGMTNICs=4 ; NestedVirt=$true ; Unattend="NoDjoin"}}

#Windows Admin Center gateway
$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2022Core_G2.vhdx' ; MGMTNICs=1 }

#Windows 11 as management machine
#$LabConfig.VMs += @{ VMName = 'Win11'; ParentVHD = 'Win1121H2_G2.vhdx' ; AddToolsVHD = $True ; MGMTNICs=1 }
 
```

Deployment result

![](./media/powershell01.png)

![](./media/hvmanager01.png)

## Task 01 - Deploy Windows Admin Center

Depending if you deployed Windows Client operating system, or Windows Server for Windows Admin Center in Gateway mode, complete Task01a or Task01b

### Task01a - Deploy Windows Admin Center in GW mode

**Step 1** Log in Into DC virtual machine with following credentials

> Username: corp\LabAdmin
 Password: LS1setup!

**Step 2** From start menu, run PowerShell as administrator

**Step 3** To simplify deployment of Windows Admin center in Gateway mode, paste following code into PowerShell window to download and install Windows Admin Center with self-signed certificate, that is also added into trusted root certificate authorities.

```PowerShell
$GatewayServerName="WACGW"
#Download Windows Admin Center if not present
if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")){
    Start-BitsTransfer -Source https://aka.ms/WACDownload -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
}
#Create PS Session and copy install files to remote server
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
$Session=New-PSSession -ComputerName $GatewayServerName
Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

#Install Windows Admin Center
Invoke-Command -Session $session -ScriptBlock {
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SSL_CERTIFICATE_OPTION=generate"
} -ErrorAction Ignore

$Session | Remove-PSSession

#add certificate to trusted root certs
start-sleep 10
$cert = Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My\ |where subject -eq "CN=Windows Admin Center"}
$cert | Export-Certificate -FilePath $env:TEMP\WACCert.cer
Import-Certificate -FilePath $env:TEMP\WACCert.cer -CertStoreLocation Cert:\LocalMachine\Root\
 
```

**Step 4** Validate deployment by opening Edge and navigating to https://wacgw. When asked for Credentials, use following

>Username:corp\LabAdmin
Password:LS1setup!

![](./media/edge01.png)

**Step 5** In Windows Admin Center in Gateway mode it is very useful to configure Kerberos Constrained Delegation for not to be asked for credentials when connecting to remote server - in this case Azure Stack HCI OS. To do it in PowerShell, you can use following code.

```PowerShell
$GatewayServerName="WACGW"
#Configure Resource-Based constrained delegation
$gatewayObject = Get-ADComputer -Identity $GatewayServerName
$computers = (Get-ADComputer -Filter {OperatingSystem -eq "Azure Stack HCI"}).Name

foreach ($computer in $computers){
    $computerObject = Get-ADComputer -Identity $computer
    Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
}
 
```

### Task01b - Deploy Windows Admin Center on Windows Client Operating system

**Step 1** Log in Into Win11 virtual machine with following credentials

> Username: corp\LabAdmin
 Password: LS1setup!

**Step 2** in Edge browser, navigate to https://aka.ms/wacdownload to download Windows Admin Center installer

**Step 3** Run the downloaded file to initiate a setup. You can select default installation options. Finish installation.

**Step 4** Open Windows Admin Center from start menu. 

![](./media/startmenu01.png)

## Task02 - create Azure Stack HCI cluster with Windows Admin Center

**Step 1** In Windows Admin Center click on **+ Add** and in Server clusters window click on Create New. The Cluster Creation extension will run.

![](./media/edge02.png)

**Step 2** In Choose the cluster type click on **Azure Stack HCI** and select **All servers in one site**. Click on **Create**

![](./media/edge03.png)

### Get Started tab

**Step 1** In Deploy and Azure Stack HCI cluster wizard, Check the prerequisites site click **Next**

![](./media/edge04.png)

**Step 2** In **Add servers** specify following username and password, and add servers **AzSHCI1**,**AzSHCI2**,**AzSHCI3** and **AzSHCI4**

>username: corp\LabAdmin
password: LS1setup!

![](./media/edge05.png)

**Step 3** In Join a domain page, click next, as machines are already domain joined.

![](./media/edge06.png)

**Step 4** In Install features page click on **Install features**

![](./media/edge07.png)

> Since this is virtual environment, due to architecture change in windows, Hyper-V has to be installed "manually" - information about nested virtalization not enabled is misleading.

**Step 5** While logged into DC (or Win11) Open PowerShell and paste following script to install Hyper-V

```PowerShell
$Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"
Invoke-Command -ComputerName $Servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
 
```

**Step 6** After you click on Install features again, status will turn into Installed. You can clickt next, once finished.

![](./media/edge09.png)

**Step 7** At Install updates page, click on **Install updates**. Once finished, click on Next

![](./media/edge10.png)

![](./media/edge11.png)

**Step 8** Since this system is virtual, you will not be able to see hardware updates. In case you are deploying physical servers, you would be able to launch Dell OMIMSWAC (Open Manage Integration for Microsoft Windows Admin Center) extension.

![](./media/edge12.png)

**Step 9** In Restart servers page, click restart and wait for servers to come up again. Once finished, click on Networking

![](./media/edge13.png)

![](./media/edge14.png)

### Networking tab

Window Admin Center currently does not support converged networking. In following example we will use 4 NICs - two for east-west and two for north-south traffic.

**Step 1** On Check network adapters page explore adapters and click Next.

![](./media/edge15.png)

**Step 2** On Select management adapters page, select Two physical adapters teamed for management and select first 2 adapters as management. Once all first two adapters are selected, click on **Apply and test**. After all is applied, click **Next**.

![](./media/edge16.png)

![](./media/edge17.png)

![](./media/edge18.png)

**Step 3** On Virtual Switch page keep **Create one virtual switch for compute and storage together** selected and click **Next**

![](./media/edge19.png)

**Step 4** On RDMA page click Next as in Virtual Environment RDMA does not work.

![](./media/edge20.png)

**Step 5** On Define Networks page, fill network adapters names, IP Addresses and VLAN ID as per screenshot below.

Click on **Apply and test** once finished.

When asked for credentials, use following

> username: LabAdmin
password: LS1setup!

When asked for CredSSP, click Yes

Once finished, click Next:Clustering

![](./media/edge21.png)

![](./media/edge22.png)

![](./media/edge23.png)

### Clustering

**Step 1** On Validate the cluster page click on Validate to validate the cluster. Cluster validation will start.

Once validation is completed, click Next.

![](./media/edge24.png)

![](./media/edge25.png)

![](./media/edge26.png)

**Step 2** On Create cluster page fill Cluster Name (AzSHCI-Cluster) and IP Address (10.0.0.111) and click **Create Cluster**. Cluster creation will start.

Once finished, click on **Next: Storage**

![](./media/edge27.png)

![](./media/edge28.png)

![](./media/edge29.png)


### Storage

**Step 1** On Clean drives page, click on Erase Drives. Once erasing is done, click Next

![](./media/edge30.png)

![](./media/edge31.png)

**Step 2** On Check drives page explore disks, and click **Next**

![](./media/edge32.png)

**Step 3** On Validate Storage page, wait for Validate Storage to finish. After validation is finished, explore results and click Next.

![](./media/edge33.png)

![](./media/edge34.png)

**Step 4** On Enable Storage Spaces Direct page, click Enable.

Once finished, click on Next: SDN

![](./media/edge35.png)

![](./media/edge36.png)

![](./media/edge37.png)

### SDN

For sake of complexity, SDN step will be skipped. Click on **Skip** to close Cluster Creation extension.

![](./media/edge38.png)

## Task 03 - Connect to Cluster

**Step 1** After Cluster Creation Extension finishes, click on Go to connection list button. Azure Stack HCI cluster will be present.

![](./media/edge39.png)

![](./media/edge40.png)

**Step 2** to avoid asking for credentials again, configure kerberos constrained delegation for CNO using following PowerShell command

```PowerShell
$GatewayServerName="WACGW"
#Configure Resource-Based constrained delegation
$gatewayObject = Get-ADComputer -Identity $GatewayServerName
$computers = (Get-ADComputer -Filter {OperatingSystem -eq "Azure Stack HCI"}).Name

foreach ($computer in $computers){
    $computerObject = Get-ADComputer -Identity $computer
    Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
}
 
```

**Step 3** In Windows Admin Center open azshci-cluster.corp.contoso.com. You can now explore your newly created cluster.

![](./media/edge41.png)

![](./media/edge42.png)