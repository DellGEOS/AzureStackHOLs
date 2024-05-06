#region variables
$MDTServer="MDT"
$DeploymentShareLocation="D:\DeploymentShare"
$Connection="TCPIP" #or "NamedPipes"
$downloadfolder="$env:USERPROFILE\Downloads"
$WDSRoot="D:\RemoteInstall"
$DHCPServer="DC"
$ScopeID="10.0.0.0"

$CredSSPUserName="CORP\LabAdmin"
$CredSSPPassword="LS1setup!"
#endregion

#region prereqs
#install management features (ADDS, DHCP,...)
$WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
If ($WindowsInstallationType -like "Server*"){
    Install-WindowsFeature -Name "RSAT-AD-PowerShell","RSAT-ADDS","RSAT-DHCP","RSAT-DNS-Server","WDS-AdminPack"
}else{
    $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.DHCP.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0","Rsat.Dns.Tools~~~~0.0.1.0"
    foreach ($Capability in $Capabilities){
        Add-WindowsCapability -Name $Capability -Online
    }
}

#download and install binaries
    #Download files
    $files=@()
    $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2196127" ; FileName="adksetup.exe" ; Description="Windows 11 22H2 ADK"}
    $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2196224" ; FileName="adkwinpesetup.exe" ; Description="WindowsPE for Windows 11 22H2"}
    #$Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2243390" ; FileName="adksetup.exe" ; Description="Windows 11 23H2 ADK"}
    #$Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2243391" ; FileName="adkwinpesetup.exe" ; Description="WindowsPE for Windows 11 23H2"}
    #$Files+=@{Uri="https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/5df19636-5b93-4aaa-865d-48b8d349d828/public/windows11.0-kb5034130-x64_b3cf34a9418baf27d88e2760c940e49875be9849.msu" ; FileName="WindowsServer23H2_CU.msu" ; Description="Cumulative update for Windows Server 23H2 (January 2024)"}
    $Files+=@{Uri="https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi" ; FileName="MicrosoftDeploymentToolkit_x64.msi" ; Description="Microsoft Deployment Toolkit"}
    #$Files+=@{Uri="https://software-download.microsoft.com/download/pr/AzureStackHCI_17784.1408_EN-US.iso" ; FileName="AzureStackHCI_17784.1408_EN-US.iso" ; Description="Azure Stack HCI ISO"}
    #$Files+=@{Uri="https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/AzureStackHCI_20348.587_en-us.iso" ; FileName="AzureStackHCI_20348.587_en-us.iso" ; Description="Azure Stack HCI ISO"}
    #$Files+=@{Uri="https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66750/AzureStackHCI_20349.1607_en-us.iso" ; FileName="AzureStackHCI_20349.1607_en-us.iso" ; Description="Azure Stack HCI ISO"}
    $Files+=@{Uri="https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/25398.469.231004-1141.zn_release_svc_refresh_SERVERAZURESTACKHCICOR_OEMRET_x64FRE_en-us.iso" ; FileName="25398.469.231004-1141.zn_release_svc_refresh_SERVERAZURESTACKHCICOR_OEMRET_x64FRE_en-us.iso" ; Description="Azure Stack HCI ISO"}
    #$Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=866658" ; FileName="SQL2019-SSEI-Expr.exe" ; Description="SQL Express 2019"}
    $Files+=@{Uri="https://download.microsoft.com/download/5/1/4/5145fe04-4d30-4b85-b0d1-39533663a2f1/SQL2022-SSEI-Expr.exe" ; FileName="SQL2022-SSEI-Expr.exe" ; Description="SQL Express 2022"}
    #$Files+=@{Uri="https://aka.ms/ssmsfullsetup" ; FileName="SSMS-Setup-ENU.exe" ; Description="SQL Management Studio"}
    $Files+=@{Uri="https://downloadmirror.intel.com/812544/Wired_driver_28.3_x64.zip" ; FileName="Intel_Wired_Driver.zip" ; Description="Intel Network Adapter driver v28.3 (E810)"}

    foreach ($file in $files){
        if (-not (Test-Path "$downloadfolder\$($file.filename)")){
            Start-BitsTransfer -Source $file.uri -Destination "$downloadfolder\$($file.filename)" -DisplayName "Downloading: $($file.filename)"
        }
    }

    #install ADK
    Start-Process -Wait -FilePath "$downloadfolder\adksetup.exe" -ArgumentList "/features OptionId.DeploymentTools OptionId.UserStateMigrationTool /quiet"
    #install ADK WinPE
    Start-Process -Wait -FilePath "$downloadfolder\adkwinpesetup.exe" -ArgumentList "/features OptionID.WindowsPreinstallationEnvironment /Quiet"
    #install MDT locally
    Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $downloadfolder\MicrosoftDeploymentToolkit_x64.msi /q"

    #prepare MDT Server
        #format and prepare "D" drive on MDT Server
        Get-Disk -CimSession $MDTServer | Where-Object PartitionStyle -eq RAW | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -Filesystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel "Storage"
        #enable SMB FIrewall rule
        Enable-NetFirewallRUle -CimSession $MDTServer -Name FPS-SMB-In-TCP
        #copy binaries
        New-Item -Path "\\$MDTServer\d$\" -Name INstall -ItemType Directory
        Copy-Item -Path "$env:UserProfile\Downloads\*" -Destination "\\$MDTServer\d$\Install" -Recurse

        #Install MDT and Prereqs to MDT Server
        Invoke-Command -ComputerName $MDTServer -ScriptBlock {
            $downloadfolder="d:\Install"
            #install ADK
            Start-Process -Wait -FilePath "$downloadfolder\adksetup.exe" -ArgumentList "/features OptionId.DeploymentTools OptionId.UserStateMigrationTool /quiet"
            #install ADK WinPE
            Start-Process -Wait -FilePath "$downloadfolder\adkwinpesetup.exe" -ArgumentList "/features OptionID.WindowsPreinstallationEnvironment /Quiet"
            #install MDT
            Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $downloadfolder\MicrosoftDeploymentToolkit_x64.msi /q"
        }

    #install SQL Express to MDT Machine (using credssp)
        # Temporarily enable CredSSP delegation to avoid double-hop issue
        $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
        If ($WindowsInstallationType -eq "Client"){
            winrm quickconfig -force #on client is winrm not configured
        }
        Enable-WSManCredSSP -Role "Client" -DelegateComputer $MDTServer -Force
        Invoke-Command -ComputerName $MDTServer -ScriptBlock { Enable-WSManCredSSP Server -Force }

        $SecureStringPassword = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
        $Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $SecureStringPassword)

        Invoke-Command -ComputerName $MDTServer -Credential $Credentials -Authentication Credssp -ScriptBlock {
            $downloadfolder="D:\Install"
            #install
            $exec="$downloadfolder\SQL2022-SSEI-Expr.exe"
            $params="/Action=Install /MediaPath=$downloadfolder\SQLMedia /IAcceptSqlServerLicenseTerms /quiet"
            Start-Process -FilePath $exec -ArgumentList $params -NoNewWindow -Wait
        }

        # Disable CredSSP
        Disable-WSManCredSSP -Role Client
        Invoke-Command -ComputerName $MDTServer -ScriptBlock {Disable-WSManCredSSP Server}
#endregion

#region configure MDT
#import MDT Module
Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
#list commands
Get-Command -Module MicrosoftDeploymentToolkit

#Create new Deployment Share
   #Create Deployment Share
Invoke-Command -ComputerName $MDTServer -ScriptBlock {
    New-Item -Path $using:DeploymentShareLocation -ItemType Directory -ErrorAction Ignore
    New-SmbShare -Name "DeploymentShare$" -Path "$using:DeploymentShareLocation" -FullAccess Administrators
}
#map MDT deployment share as PSDrive
#sometimes happens that script to complains: The process cannot access the file '\\MDT\DeploymentShare$\Control\Settings.xml' because it is being used by another process.
do{
    New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
    if (-not (get-psdrive -Name DS001)){
        Write-Output "Failed adding PSDrive - trying again"
    }
}until (get-psdrive -Name DS001)
#Configure SQL Services

Invoke-Command -ComputerName $MDTServer -scriptblock {
    if ($using:Connection -eq "NamedPipes"){
        #Named Pipes
        Set-ItemProperty -Path "hklm:\\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Np\" -Name Enabled -Value 1
    }

    if ($using:Connection -eq "TCPIP"){
        #TCP
        Set-ItemProperty -Path "hklm:\\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Tcp\" -Name Enabled -Value 1
        Set-ItemProperty -Path "hklm:\\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -Name TcpPort -Value 1433
    }

    Restart-Service 'MSSQL$SQLEXPRESS'
    Set-Service -Name SQLBrowser -StartupType Automatic
    Start-Service -Name SQLBrowser
}

#create Firewall rule for SQL Server

    if ($Connection -eq "TCPIP"){
        New-NetFirewallRule `
        -CimSession $MDTServer `
        -Action Allow `
        -Name "SQLExpress-In-TCP" `
        -DisplayName "SQLExpress (SQL-In)" `
        -Description "Inbound rule for SQL. [TCP-1433]" `
        -Enabled True `
        -Direction Inbound `
        -Program "%ProgramFiles%\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\Binn\sqlservr.exe" `
        -Protocol TCP `
        -LocalPort 1433 `
        -Profile Any `
        -Group "SQL Express" `
        -RemoteAddress Any
    }

    New-NetFirewallRule `
    -CimSession $MDTServer `
    -Action Allow `
    -Name "SQLBrowser-In-UDP" `
    -DisplayName "SQLBrowser (SQL-In-UDP)" `
    -Description "Inbound rule for SQLBrowser. [UDP-1434]" `
    -Enabled True `
    -Direction Inbound `
    -Program "%ProgramFiles% (x86)\Microsoft SQL Server\90\Shared\sqlbrowser.exe" `
    -Protocol UDP `
    -LocalPort 1434 `
    -Profile Any `
    -Group "SQL Express" `
    -RemoteAddress Any

#create DB in MDT
if ($Connection -eq "NamedPipes"){
    New-MDTDatabase -path "DS001:" -SQLServer $MDTServer -Instance "SQLExpress" -Netlib "DBNMPNTW" -Database "MDTDB" -SQLShare "DeploymentShare$" -Verbose
}elseif ($Connection -eq "TCPIP"){
    New-MDTDatabase -path "DS001:" -SQLServer $MDTServer  -Port "1433" -Netlib "DBMSSOCN" -Database "MDTDB" -Verbose
}

#Import Operating System
$ISO = Mount-DiskImage -ImagePath "$downloadfolder\25398.469.231004-1141.zn_release_svc_refresh_SERVERAZURESTACKHCICOR_OEMRET_x64FRE_en-us.iso" -PassThru
$ISOMediaPath = (Get-Volume -DiskImage $ISO).DriveLetter+':\'
Import-mdtoperatingsystem -path "DS001:\Operating Systems" -SourcePath $ISOMediaPath -DestinationFolder "Azure Stack HCI SERVERAZURESTACKHCICORE x64" -Verbose

$ISO | Dismount-DiskImage

    #region patch WinPE 23H2
    <# I was testing this for 23H2 WinPE
        #https://github.com/DeploymentResearch/DRFiles/blob/master/Scripts/MDTVBScript/Update-ADK25398BootImageInstallFolderWithCU.ps1
        #https://www.deploymentresearch.com/fixing-vbscript-support-in-windows-adk-sep-2023-update-build-25398/

        # Set path to the Windows Update for Windows Server, version 23H2 (used for ADK WinPE version 25398)
        $WinPECU = "$downloadfolder\windows1123H2_CU.msu"

        # Set architecture and mount folder
        $WinPEArchitecture = "amd64"
        $WinPEMountFolder = "C:\Mount"

        # Get ADK folders
        $InstalledRoots = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots'
        $KitsRoot10 = Get-ItemPropertyValue -Path $InstalledRoots -Name 'KitsRoot10'
        $AdkRoot = Join-Path $KitsRoot10 'Assessment and Deployment Kit'
        $WinPERoot = Join-Path $AdkRoot 'Windows Preinstallation Environment'
        $WinPEOCsRoot = Join-Path $WinPERoot\$WinPEArchitecture 'WinPE_OCs'
        $DeploymentToolsRoot = Join-Path $AdkRoot (Join-Path 'Deployment Tools' $WinPEArchitecture)
        $WinPERoot = Join-Path $WinPERoot $WinPEArchitecture

        # Set path to dism.exe
        $DISMFile = Join-Path $DeploymentToolsRoot 'DISM\Dism.exe'

        # Set path to CU to the boot image
        $BootImage = "$WinPERoot\en-us\winpe.wim"

        # Verify that files and folder exist
        If (!(Test-Path $DISMFile)){ Write-Warning "DISM in Windows ADK not found, aborting..."; Break }
        if (!(Test-Path -path $WinPECU)) {Write-Warning "Could not find the Windows Server, version 23H2 update. Aborting...";Break}
        if (!(Test-Path -path $BootImage)) {Write-Warning "Could not find Boot image. Aborting...";Break}

        # Create Mount folder if it does not exist
        if (!(Test-Path -path $WinPEMountFolder)) {New-Item -path $WinPEMountFolder -ItemType Directory}

        # Backup the Boot image
        Copy-Item -Path $BootImage -Destination "$($BootImage).bak"

        # Mount the Boot image
        Mount-WindowsImage -ImagePath $BootImage -Index 1 -Path $WinPEMountFolder

        # Add native WinPE optional component required by MDT (the ones you commented out in the LiteTouchPE.xml file)
        # winpe-hta
        # winpe-scripting
        # winpe-wmi
        # winpe-securestartup
        # winpe-fmapi

        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\WinPE-HTA.cab
        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\en-us\WinPE-HTA_en-us.cab

        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\WinPE-Scripting.cab
        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\en-us\WinPE-Scripting_en-us.cab

        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\WinPE-WMI.cab 
        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\en-us\WinPE-WMI_en-us.cab

        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\WinPE-SecureStartup.cab 
        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\en-us\WinPE-SecureStartup_en-us.cab

        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\WinPE-FMAPI.cab # Does not have a language file

        # Add MDAC optional component required if using the Database in MDT
        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\WinPE-MDAC.cab 
        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPEOCsRoot\en-us\WinPE-MDAC_en-us.cab

        # Add the Windows Server, version 23H2 Update to the Boot image
        & $DISMFile /Image:$WinPEMountFolder /Add-Package /PackagePath:$WinPECU

        # Component cleanup 
        & $DISMFile /Cleanup-Image /Image:$WinPEMountFolder /Startcomponentcleanup /Resetbase

        # Dismount the Boot image
        DisMount-WindowsImage -Path $WinPEMountFolder -Save
    #>
    #endregion

#configure Deployment Share properties
Set-ItemProperty DS001:\ -name SupportX86 -value False
Set-ItemProperty DS001:\ -name Boot.x86.GenerateLiteTouchISO -value False
Set-ItemProperty DS001:\ -name Boot.x64.SelectionProfile -value "All Drivers"
Set-ItemProperty DS001:\ -name Boot.x64.IncludeNetworkDrivers -value True
Set-ItemProperty DS001:\ -name Boot.x64.IncludeMassStorageDrivers -value True
Set-ItemProperty DS001:\ -name Boot.x64.IncludeAllDrivers -value False
Set-ItemProperty DS001:\ -name Boot.x64.GenerateGenericWIM -value True

#import Intel drivers
Expand-Archive -Path $downloadfolder\Intel_Wired_Driver.zip -DestinationPath $DownloadFolder\IntelNICDriver
$DriverFile=Get-Childitem -Path $downloadfolder\IntelNICDriver | Where-Object Name -Like Wired_Driver*
Rename-Item -Path $DriverFile.FullName -NewName "$($DriverFile.Basename).zip" -Verbose
$DriverFile=Get-Childitem -Path $downloadfolder\IntelNICDriver | Where-Object Name -Like Wired_Driver*
Expand-Archive -Path $DriverFile.FullName -DestinationPath $DownloadFolder\IntelNICDriver\Driver
import-mdtdriver -path "DS001:\Out-of-Box Drivers" -SourcePath "C:\Users\LabAdmin\Downloads\IntelNICDriver\Driver" -Verbose

#add PowerShell (winpe-scripting is removed as it's most likely needed in latestt 23H2 WinPE)
$Properties=@()
$Properties+=(Get-ItemPropertyValue DS001:\ -Name Boot.x64.FeaturePacks) -split (",")
$FeaturesToAdd="winpe-netfx","winpe-powershell"#,"winpe-scripting"
foreach ($FeatureToAdd in $FeaturesToAdd){
    if ($properties -notcontains $FeatureToAdd){
        $Properties+=$FeatureToAdd
    }
}
Set-ItemProperty DS001:\ -name Boot.x64.FeaturePacks -value ($Properties -Join (","))

#add Task Sequence
import-mdttasksequence -path "DS001:\Task Sequences" -Name "Azure Stack HCI Deploy" -Template "Server.xml" -Comments "" -ID "AzSHCI" -Version "1.0" -OperatingSystemPath "DS001:\Operating Systems\Azure Stack HCI SERVERAZURESTACKHCICORE in Azure Stack HCI SERVERAZURESTACKHCICORE x64 install.wim" -FullName "PFE" -OrgName "Contoso" -HomePage "about:blank" -AdminPassword "LS1setup!" -Verbose

#endregion

#region configure MDT run-as account (to be able domain join. Not needed if you don't djoin machines)
#create identity for MDT
$DefaultOUPath=(Get-ADDomain).UsersContainer
New-ADUser -Name MDTUser -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path $DefaultOUPath -PasswordNeverExpires $True

#add FileShare permissions for MDT Account
Invoke-Command -ComputerName $MDTServer -ScriptBlock {
    Grant-SmbShareAccess -Name DeploymentShare$ -AccessRight Read -AccountName MDTUser -Confirm:$false
}
#delegate djoin permissions https://www.sevecek.com/EnglishPages/Lists/Posts/Post.aspx?ID=48
$user = "$env:userdomain\MDTUser"
$ou = (Get-ADDomain).ComputersContainer

DSACLS $ou /R $user

DSACLS $ou /I:S /G "$($user):GR;;computer"
DSACLS $ou /I:S /G "$($user):CA;Reset Password;computer"
DSACLS $ou /I:S /G "$($user):WP;pwdLastSet;computer"
DSACLS $ou /I:S /G "$($user):WP;Logon Information;computer"
DSACLS $ou /I:S /G "$($user):WP;description;computer"
DSACLS $ou /I:S /G "$($user):WP;displayName;computer"
DSACLS $ou /I:S /G "$($user):WP;sAMAccountName;computer"
DSACLS $ou /I:S /G "$($user):WP;DNS Host Name Attributes;computer"
DSACLS $ou /I:S /G "$($user):WP;Account Restrictions;computer"
DSACLS $ou /I:S /G "$($user):WP;servicePrincipalName;computer"
DSACLS $ou /I:S /G "$($user):CC;computer;organizationalUnit"

#endregion

#region configure Bootstrap ini and generate WinPE
#populate bootstrap.ini
$content=@"
[Settings]
Priority=Default

[Default]
DeployRoot=\\$MDTServer\DeploymentShare$
UserDomain=$env:userdomain
UserID=MDTUser
UserPassword=LS1setup!
SkipBDDWelcome=YES
"@
#remove bootstrap.ini first (sometimes there is an error if just populating content)
Invoke-Command -ComputerName $MDTServer -ScriptBlock {Remove-Item -Path "$using:DeploymentShareLocation\Control\Bootstrap.ini" -Force}
#populate content
Set-Content -Path "\\$MDTServer\DeploymentShare$\Control\Bootstrap.ini" -Value $content


#update deployment share to generate new WIM for WDS
if (-not(get-module MicrosoftDeploymentToolkit)){
    Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
}
if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
    New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
}
update-mdtdeploymentshare -path "DS001:" -verbose -force

#endregion

#region Install and configure WDS
#install WDS
Install-WindowsFeature -Name WDS -ComputerName $MDTServer -IncludeManagementTools -IncludeAllSubFeature

# Temporarily enable CredSSP delegation to avoid double-hop issue
winrm quickconfig -force #on client is winrm not configured
Enable-WSManCredSSP -Role "Client" -DelegateComputer $MDTServer -Force
Invoke-Command -ComputerName $MDTServer -ScriptBlock { Enable-WSManCredSSP Server -Force }

$SecureStringPassword = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $SecureStringPassword)

#Configure WDS
Invoke-Command -ComputerName $MDTServer -Credential $Credentials -Authentication Credssp -ScriptBlock {
    $MDTServer=$using:MDTServer
    wdsutil /initialize-server /reminst:$using:WDSRoot
    wdsutil /start-server
    wdsutil.exe /Set-Server /AnswerClients:Known
    #WDSUTIL /Set-Server /AnswerClients:Known /ResponseDelay:4
    WDSUTIL /Set-Server /PxePromptPolicy /known:Noprompt /new:abort
    #WDSUTIL /Set-Server /PxePromptPolicy /known:Noprompt /new:Noprompt
}

#import the boot media to WDS
Invoke-Command -ComputerName $MDTServer -Credential $Credentials -Authentication Credssp -ScriptBlock {
    Get-WdsBootImage | Remove-WdsBootImage
    Import-wdsbootimage -path "$($using:DeploymentShareLocation)\Boot\LiteTouchPE_x64.wim" -Verbose
}


#Disable CredSSP
Disable-WSManCredSSP -Role Client
Invoke-Command -ComputerName $MDTServer -ScriptBlock {Disable-WSManCredSSP Server}


#Mitigate issue with Variable Window Extension
Invoke-Command -ComputerName $MDTServer -ScriptBlock {
    Wdsutil /Set-TransportServer /EnableTftpVariableWindowExtension:No
}

#endregion

#region configure MDT Monitoring
Invoke-Command -ComputerName $MDTServer -ScriptBlock {
    if (-not(get-module MicrosoftDeploymentToolkit)){
        Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
    }
    if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
        New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "$using:DeploymentShareLocation" -Description "MDT Deployment Share" -NetworkPath "\\$using:MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
    }
    #configure ports in MDT
    Set-ItemProperty DS001:\ -name MonitorHost -value $using:MDTServer
    #enable service
    Enable-MDTMonitorService -EventPort 9800 -DataPort 9801
}

#add firewall rule
New-NetFirewallRule `
    -CimSession $MDTServer `
    -Action Allow `
    -Name "MDT-Monitoring-In-TCP" `
    -DisplayName "MDT (Monitoring-In-TCP)" `
    -Description "Inbound rule for MDT Monitoring. [TCP-9800,9801]" `
    -Enabled True `
    -Direction Inbound `
    -Program "System" `
    -Protocol UDP `
    -LocalPort 9800,9801 `
    -Profile Any `
    -Group "MDT" `
    -RemoteAddress Any
#endregion

#region replace customsettings.ini with all DB data to query (wizard output)
if ($Connection -eq "NamedPipes"){
    $Netlib="DBNMPNTW"
}elseif($Connection -eq "TCPIP"){
    $Netlib="DBMSSOCN"
    $Creds=@"
DBID=MDTSQLUser
DBPwd=LS1setup!
"@
}

$content=@"
[Settings]
Priority=CSettings, CPackages, CApps, CAdmins, CRoles, Locations, LSettings, LPackages, LApps, LAdmins, LRoles, MMSettings, MMPackages, MMApps, MMAdmins, MMRoles, RSettings, RPackages, RApps, RAdmins, Default
Properties=MyCustomProperty

[Default]
OSInstall=Y
SkipCapture=YES
SkipAdminPassword=NO
SkipProductKey=YES
EventService=http://$($MDTServer):9800

[CSettings]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=ComputerSettings
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR

[CPackages]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=ComputerPackages
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR
Order=Sequence

[CApps]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=ComputerApplications
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR
Order=Sequence

[CAdmins]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=ComputerAdministrators
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR

[CRoles]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=ComputerRoles
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR

[Locations]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=Locations
Parameters=DefaultGateway

[LSettings]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=LocationSettings
Parameters=DefaultGateway

[LPackages]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=LocationPackages
Parameters=DefaultGateway
Order=Sequence

[LApps]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=LocationApplications
Parameters=DefaultGateway
Order=Sequence

[LAdmins]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=LocationAdministrators
Parameters=DefaultGateway

[LRoles]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=LocationRoles
Parameters=DefaultGateway

[MMSettings]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=MakeModelSettings
Parameters=Make, Model

[MMPackages]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=MakeModelPackages
Parameters=Make, Model
Order=Sequence

[MMApps]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=MakeModelApplications
Parameters=Make, Model
Order=Sequence

[MMAdmins]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=MakeModelAdministrators
Parameters=Make, Model

[MMRoles]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=MakeModelRoles
Parameters=Make, Model

[RSettings]
$creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=RoleSettings
Parameters=Role

[RPackages]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=RolePackages
Parameters=Role
Order=Sequence

[RApps]
$creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=RoleApplications
Parameters=Role
Order=Sequence

[RAdmins]
$creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=RoleAdministrators
Parameters=Role
"@


$CustomSettingsFile="\\$MDTServer\DeploymentShare$\Control\CustomSettings.ini"
Set-Content -Path $CustomSettingsFile -Value $Content -NoNewline #if NoNewLine not specified, scipt will add crlf at and of the file
#replace LF with CRLF as text will be displayed correctly in Deployment Workbench
$text = [IO.File]::ReadAllText($CustomSettingsFile) -replace "`n", "`r`n"
[IO.File]::WriteAllText($CustomSettingsFile, $text)

#endregion

#region configure SQL to be able to access it remotely using MDTUser account(NamedPipes) or create dedicated SQL user (TCPIP)
#Add permissions for MDT account to sql database
#note: added -TrustServerCertificate as I saw an error since  05/2023 when invoke-sqlcmd ran. "The certificate chain was issued by an authority that is not trusted..."
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name sqlserver -AllowClobber -Force
if ((Get-ExecutionPolicy) -eq "Restricted"){
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
}
if ($Connection -eq "NamedPipes"){
        #Named Pipes
$sqlscript=@"
USE [master]
GO
CREATE LOGIN [$env:userdomain\MDTUser] FROM WINDOWS WITH DEFAULT_DATABASE=[MDTDB]
GO
USE [MDTDB]
GO
CREATE USER [$env:userdomain\mdtuser] FOR LOGIN [$env:userdomain\mdtuser]
GO
USE [MDTDB]
GO
ALTER ROLE [db_datareader] ADD MEMBER [$env:userdomain\mdtuser]
GO

"@
Invoke-Sqlcmd -ServerInstance $MDTServer\sqlexpress -Database MDTDB -Query $sqlscript -TrustServerCertificate

}elseif($Connection -eq "TCPIP"){
#TCP (add user and change authentication mode to be able to use both SQL and Windows Auth
$sqlscript=@"
USE [master]
GO
CREATE LOGIN [MDTSQLUser] WITH PASSWORD='LS1setup!', DEFAULT_DATABASE=[MDTDB]
GO
USE [MDTDB]
GO
CREATE USER [MDTSQLUser] FOR LOGIN [MDTSQLUser]
GO
ALTER ROLE [db_datareader] ADD MEMBER [MDTSQLUser]
GO
USE [master]
GO
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2
GO

"@
#TCP
Invoke-Sqlcmd -ServerInstance "tcp:$MDTServer" -Database MDTDB -Query $sqlscript -TrustServerCertificate
#restart service to apply mixed auth mode
Invoke-Command -ComputerName $MDTServer -scriptblock {
    Restart-Service 'MSSQL$SQLEXPRESS'
}
}
#endregion

#region Final touch