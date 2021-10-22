#region variables
    $MDTServer="MDT"
    $DeploymentShareLocation="D:\DeploymentShare"
    $DHCPServer="DC"
    $ScopeID="10.0.0.0"

    #HVHosts example - if not queried from EventLog
    <#
    $HVHosts = @()
    $HVHosts+=@{ComputerName="AxNode1"  ;IPAddress="10.0.0.120" ; MACAddress="0C:42:A1:DD:57:DC" ; GUID="4C4C4544-004D-5410-8031-B4C04F373733"}
    $HVHosts+=@{ComputerName="AxNode2"  ;IPAddress="10.0.0.121" ; MACAddress="0C:42:A1:DD:57:C8" ; GUID="4C4C4544-004D-5410-8033-B4C04F373733"}
    #>
#endregion

#region create DHCP reservation for machines
    #Create DHCP reservations for Hyper-V hosts
        #Add DHCP Reservations
        foreach ($HVHost in $HVHosts){
            if (!(Get-DhcpServerv4Reservation -ErrorAction SilentlyContinue -ComputerName $DHCPServer -ScopeId $ScopeID -ClientId ($HVHost.MACAddress).Replace(":","") | Where-Object IPAddress -eq $HVHost.IPAddress)){
                Add-DhcpServerv4Reservation -ComputerName $DHCPServer -ScopeId $ScopeID -IPAddress $HVHost.IPAddress -ClientId ($HVHost.MACAddress).Replace(":","")
            }
        }

    #configure NTP server in DHCP (might be useful if Servers have issues with time)
        if (!(get-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeID -OptionId 042 -ErrorAction SilentlyContinue)){
            Set-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeID -OptionId 042 -Value "10.0.0.1"
        }
#endregion

#region add deploy info to AD Object and MDT Database
    #download and unzip mdtdb (blog available in web.archive only https://web.archive.org/web/20190421025144/https://blogs.technet.microsoft.com/mniehaus/2009/05/14/manipulating-the-microsoft-deployment-toolkit-database-using-powershell/)
    #Start-BitsTransfer -Source https://msdnshared.blob.core.windows.net/media/TNBlogsFS/prod.evol.blogs.technet.com/telligent.evolution.components.attachments/01/5209/00/00/03/24/15/04/MDTDB.zip -Destination $env:USERPROFILE\Downloads\MDTDB.zip
    Start-BitsTransfer -Source https://github.com/microsoft/MSLab/raw/master/Scenarios/AzSHCI%20and%20MDT/MDTDB.zip -Destination $env:USERPROFILE\Downloads\MDTDB.zip

    Expand-Archive -Path $env:USERPROFILE\Downloads\MDTDB.zip -DestinationPath $env:USERPROFILE\Downloads\MDTDB\
    if ((Get-ExecutionPolicy) -eq "Restricted"){
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
    }
    Import-Module $env:USERPROFILE\Downloads\MDTDB\MDTDB.psm1
    #make sure DS is connected
        if (-not(get-module MicrosoftDeploymentToolkit)){
            Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
        }
        if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
            New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
        }
    #Connect to DB
        #Connect-MDTDatabase -database mdtdb -sqlServer $MDTServer -instance SQLExpress
        Connect-MDTDatabase -drivePath "DS001:\"


    #add hosts to MDT DB
    foreach ($HVHost in $HVHosts){
        if (-not(Get-AdComputer  -Filter "Name -eq `"$($HVHost.ComputerName)`"")){
            New-ADComputer -Name $hvhost.ComputerName
        }
        #add to MDT DB
        if (-not (Get-MDTComputer -macAddress $HVHost.MACAddress)){
            New-MDTComputer -macAddress $HVHost.MACAddress -description $HVHost.ComputerName -uuid $HVHost.GUID -settings @{ 
                ComputerName        = $HVHost.ComputerName 
                OSDComputerName     = $HVHost.ComputerName 
                #SkipBDDWelcome      = 'Yes' 
            }
        }
        Get-MDTComputer -macAddress $HVHost.MACAddress | Set-MDTComputerRole -roles JoinDomain,AZSHCI
    }

    #Configure MDT DB Roles
        if (-not (Get-MDTRole -name azshci)){
            New-MDTRole -name AZSHCI -settings @{
                SkipTaskSequence    = 'YES'
                SkipWizard          = 'YES'
                SkipSummary         = 'YES'
                SkipApplications    = 'YES'
                TaskSequenceID      = 'AZSHCI'
                SkipFinalSummary    = 'YES'
                FinishAction        = 'LOGOFF'
            }
        }

        if (-not (Get-MDTRole -name JoinDomain)){
            New-MDTRole -name JoinDomain -settings @{
                SkipComputerName    ='YES'
                SkipDomainMembership='YES'
                JoinDomain          = $env:USERDNSDomain
                DomainAdmin         ='MDTUser'
                DomainAdminDomain   = $env:userdomain
                DomainAdminPassword ='LS1setup!'
            }
        }

    #allow machines to boot from PXE from DC by adding info into AD Object
    foreach ($HVHost in $HVHosts){
        [guid]$guid=$HVHost.GUID
        Set-ADComputer -identity $hvhost.ComputerName -replace @{netbootGUID = $guid}
        #Set-ADComputer -identity $hvhost.ComputerName -replace @{netbootMachineFilePath = "DC"}
    }

#endregion

#region update task sequence with powershell script to install OS to smallest disk right before "New Computer only" group
$TaskSequenceID="AzSHCI"
$PSScriptName="OSDDiskIndex.ps1"
$PSScriptContent=@'
$Disks=Get-CimInstance win32_DiskDrive
if ($Disks.model -contains "DELLBOSS VD"){
    #exact model for Dell AX node (DELLBOSS VD)
    $TSenv:OSDDiskIndex=($Disks | Where-Object Model -eq "DELLBOSS VD").Index
}else{
    #or just smallest disk
    $TSenv:OSDDiskIndex=($Disks | Where-Object MediaType -eq "Fixed hard disk media" | Sort-Object Size | Select-Object -First 1).Index
}
<# In case you need PowerShell and pause Task Sequence you can use this code:
#source: http://wiki.wladik.net/windows/mdt/powershell-scripting
#run posh
Start PowerShell
#pause TS
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Windows.Forms.MessageBox]::Show("Click to continue...")
#>
'@

    #update Tasksequence
    $TS=Invoke-Command -ComputerName $MDTServer -ScriptBlock {Get-Content -Path $using:DeploymentShareLocation\Control\$using:TaskSequenceID\ts.xml}
    $TextToSearch='    <group name="New Computer only" disable="false" continueOnError="false" description="" expand="false">'
    $PoshScript=@"
    <step type="BDD_RunPowerShellAction" name="Run PowerShell Script" description="" disable="false" continueOnError="false" successCodeList="0 3010">
      <defaultVarList>
        <variable name="ScriptName" property="ScriptName">$PSScriptName</variable>
        <variable name="Parameters" property="Parameters"></variable>
        <variable name="PackageID" property="PackageID"></variable>
      </defaultVarList>
      <action>cscript.exe "%SCRIPTROOT%\ZTIPowerShell.wsf</action>
    </step>
$TextToSearch
"@
    $NewTS=$TS.replace($TextToSearch,$PoshScript)
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {Set-Content -Path $using:DeploymentShareLocation\Control\$using:TaskSequenceID\ts.xml -Value $using:NewTS}
    #insert script
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {Set-Content -Path $using:DeploymentShareLocation\Scripts\$using:PSScriptName -Value $using:PSScriptContent}

#endregion

#region update task sequence with drivers

#Download DSU
#https://github.com/DellProSupportGse/Tools/blob/main/DART.ps1

    #grab DSU links from Dell website
    $URL="https://dl.dell.com/omimswac/dsu/"
    $Results=Invoke-WebRequest $URL -UseDefaultCredentials
    $Links=$results.Links.href | Select-Object -Skip 1
    #create PSObject from results
    $DSUs=@()
    foreach ($Link in $Links){
        $DSUs+=[PSCustomObject]@{
            Link = "https://dl.dell.com$Link"
            Version = $link -split "_" | Select-Object -Last 2 | Select-Object -First 1
        }
    }
    #download latest to separate folder
    $LatestDSU=$DSUs | Sort-Object Version | Select-Object -Last 1
    $Folder="$env:USERPROFILE\Downloads\DSU"
    if (-not (Test-Path $Folder)){New-Item -Path $Folder -ItemType Directory}
    Start-BitsTransfer -Source $LatestDSU.Link -Destination $Folder\DSU.exe

    #add DSU as application to MDT
    Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
    if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
        New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
    }
    $AppName="Dell DSU $($LatestDSU.Version)"
    Import-MDTApplication -path "DS001:\Applications" -enable "True" -Name $AppName -ShortName "DSU" -Version $LatestDSU.Version -Publisher "Dell" -Language "" -CommandLine "DSU.exe /silent" -WorkingDirectory ".\Applications\$AppName" -ApplicationSourcePath $Folder -DestinationFolder $AppName -Verbose
    #grap package ID for role config
    $DSUID=(Get-ChildItem -Path DS001:\Applications | Where-Object Name -eq $AppName).GUID

#download catalog and create answer file to run DSU
    #Dell Azure Stack HCI driver catalog https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz
    #Download catalog
    Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz"
    #unzip gzip to a folder https://scatteredcode.net/download-and-extract-gzip-tar-with-powershell/
    $Folder="$env:USERPROFILE\Downloads\DSUPackage"
    if (-not (Test-Path $Folder)){New-Item -Path $Folder -ItemType Directory}
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
    Expand-GZipArchive "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz" "$folder\ASHCI-Catalog.xml"
    #create answerfile for DU
    $content='@
    a
    c
    @'
    Set-Content -Path "$folder\answer.txt" -Value $content -NoNewline
    $content='"C:\Program Files\Dell\DELL EMC System Update\DSU.exe" --catalog-location=ASHCI-Catalog.xml --apply-upgrades <answer.txt'
    Set-Content -Path "$folder\install.cmd" -Value $content -NoNewline

    #add package to MDT
    [xml]$xml=Get-Content "$folder\ASHCI-Catalog.xml"
    $version=$xml.Manifest.version
    $AppName="Dell DSU AzSHCI Package $Version"
    $Commandline="install.cmd"
    Import-MDTApplication -path "DS001:\Applications" -enable "True" -Name $AppName -ShortName "DSUAzSHCIPackage" -Version $Version -Publisher "Dell" -Language "" -CommandLine $Commandline -WorkingDirectory ".\Applications\$AppName" -ApplicationSourcePath $Folder -DestinationFolder $AppName -Verbose
    #configure app to reboot after run
    Set-ItemProperty -Path DS001:\Applications\$AppName -Name Reboot -Value "True"
    #configure dependency on DSU
    $guids=@()
    $guids+=$DSUID
    Set-ItemProperty -Path DS001:\Applications\$AppName -Name Dependency -Value $guids
    #grap package ID for role config
    $DSUPackageID=(Get-ChildItem -Path DS001:\Applications | Where-Object Name -eq $AppName).GUID

    #Create Role
    $RoleName="AXNodeDrivers"
    if (-not (Get-MDTRole -name $RoleName)){
        New-MDTRole -name $RoleName -settings @{
            OSInstall    ='YES'
        }
    }
    #Add apps to role
    $ID=(get-mdtrole -name $RoleName).ID
    Set-MDTRoleApplication -id $ID -applications $DSUID,$DSUPackageID

    #add role that will install drivers to AX computers
        foreach ($HVHost in $HVHosts){
            $MDTComputer=Get-MDTComputer -macAddress $HVHost.MACAddress
            $Roles=($MDTComputer | Get-MDTComputerRole).Role
            $Roles+=$RoleName
            #Get-MDTComputer -macAddress $HVHost.MACAddress | Set-MDTComputerRole -roles JoinDomain,AZSHCI
            $MDTComputer | Set-MDTComputerRole -roles $Roles
        }
#endregion