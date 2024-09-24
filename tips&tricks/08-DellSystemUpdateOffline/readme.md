
The following code is useful as it will download updates you might need for offline patching your servers.

It might be useful if you use MDT to provision your servers. You can then simply run DSU to install all updates and point it to the folder. Otherwise you can just use SBE package that you can sideload on cluster.


## Download catalog and necessary files (DSU and IC)

```PowerShell

$BinariesLocation="$env:USERPROFILE\Downloads\Dell"

$Servers="AXNode3","AXNode4" #servers that 

#Set up web client to download files with autheticated web request
$WebClient = New-Object System.Net.WebClient
#$proxy = new-object System.Net.WebProxy
$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
#$proxy.Address = $proxyAdr
#$proxy.useDefaultCredentials = $true
$WebClient.proxy = $proxy

#Download DSU
#https://github.com/DellProSupportGse/Tools/blob/main/DART.ps1
#download latest DSU to Downloads
    $LatestDSU="https://dl.dell.com/FOLDER10889507M/1/Systems-Management_Application_RPW7K_WN64_2.0.2.3_A00.EXE"
    if (-not (Test-Path $BinariesLocation -ErrorAction Ignore)){New-Item -Path $BinariesLocation -ItemType Directory}
    #Start-BitsTransfer -Source $LatestDSU -Destination $BinariesLocation\DSU.exe
    $WebClient.DownloadFile($LatestDSU,"$BinariesLocation\DSU.exe")

#download IC
    $LatestIC="https://downloads.dell.com/omimswac/ic/invcol_T4M1J_WIN64_23_03_00_44_A00.exe"
    if (-not (Test-Path $BinariesLocation -ErrorAction Ignore)){New-Item -Path $BinariesLocation -ItemType Directory}
    #Start-BitsTransfer -Source $LatestDSU -Destination $BinariesLocation\DSU.exe
    $WebClient.DownloadFile($LatestIC,"$BinariesLocation\IC.exe")

#Download catalog and unpack
    #Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$BinariesLocation\ASHCI-Catalog.xml.gz"
    $WebClient.DownloadFile("https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz","$BinariesLocation\ASHCI-Catalog.xml.gz")

    #unzip gzip to a folder https://scatteredcode.net/download-and-extract-gzip-tar-with-powershell/
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
    Expand-GZipArchive "$BinariesLocation\ASHCI-Catalog.xml.gz" "$BinariesLocation\ASHCI-Catalog.xml"
 
```

## Download updates that are listed in catalog

```PowerShell
#process catalog and download updates
$XML = New-Object xml
$XML.Load("$BinariesLocation\ASHCI-Catalog.xml")
$Packages=$XML.Manifest.SoftwareComponent

$PackagesToDownload=$Packages | Out-Gridview -OutputMode Multiple -Title "Please select what updates you want to download"

foreach ($Package in $PackagesToDownload){
    #create destination folder
    New-Item -Path ("$BinariesLocation\Updates\$($Package.Path)" | Split-Path -Parent) -ItemType Directory -Force
    Start-BitsTransfer -Source https://dl.dell.com/$($Package.Path) -Destination "$BinariesLocation\Updates\$($Package.Path)"
}
```

## Or download updates that are found on remote system

```PowerShell
#region prepare DSU binaries
    #upload DSU to servers
    $Sessions=New-PSSession -ComputerName $Servers
    Invoke-Command -Session $Sessions -ScriptBlock {
        if (-not (Test-Path $using:BinariesLocation -ErrorAction Ignore)){New-Item -Path $using:BinariesLocation -ItemType Directory}
    }
    foreach ($Session in $Sessions){
        Copy-Item -Path "$BinariesLocation\DSU.exe" -Destination "$BinariesLocation" -ToSession $Session -Force -Recurse
    }
    #install DSU
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Start-Process -FilePath "$using:BinariesLocation\DSU.exe" -ArgumentList "/silent" -Wait 
    }

    #upload IC.exe to servers
        foreach ($Session in $Sessions){
            Copy-Item -Path "$BinariesLocation\IC.exe" -Destination "$BinariesLocation" -ToSession $Session -Force -Recurse
        }


    #upload catalog
    foreach ($Session in $Sessions){
        Copy-Item -Path "$BinariesLocation\ASHCI-Catalog.xml" -Destination "$BinariesLocation" -ToSession $Session -Force -Recurse
    }

    #close sessions
    $Sessions | Remove-PSSession
#endregion

#perform scan
Invoke-Command -ComputerName $Servers -ScriptBlock {
    & "C:\Program Files\Dell\DELL System Update\DSU.exe" --compliance --catalog-location="$using:BinariesLocation\ASHCI-Catalog.xml" --ic-location="$using:BinariesLocation\ic.exe" --output-format="json" --output="$using:BinariesLocation\Compliance.json"
}

#collect results
$Compliance=@()
foreach ($Node in $Servers){
    $json=Invoke-Command -ComputerName $node -ScriptBlock {Get-Content "$using:BinariesLocation\Compliance.json"}
    $object = $json | ConvertFrom-Json 
    $components=$object.SystemUpdateCompliance.UpdateableComponent
    $components | Add-Member -MemberType NoteProperty -Name "ClusterName" -Value $ClusterName
    $components | Add-Member -MemberType NoteProperty -Name "NodeName" -Value $Node
    $Compliance+=$Components
}

#download updates from compliance scan
    $DellUpdatesList=($Compliance | Group-Object PackageFilePath | ForEach-Object {$_.Group | Select-Object PackageFilePath -First 1}).PackageFilePath
    foreach ($Update in $DellUpdatesList){
        #create destination folder
        New-Item -Path ("$BinariesLocation\Updates\$update" | Split-Path -Parent) -ItemType Directory -Force
        Start-BitsTransfer -Source https://dl.dell.com/$Update -Destination "$BinariesLocation\Updates\$update"
    }

```

## Apply updates on remote system

To apply updates (after transferring to node) you can simply run following code:

```PowerShell
#Upload drivers
    $Sessions=New-PSSession -ComputerName $Servers
    foreach ($session in $sessions){
        Copy-Item -Path "$BinariesLocation\Updates\" -Destination $BinariesLocation -Recurse -ToSession $Session
    }
    #close sessions
    $Sessions | Remove-PSSession

#perform update
    Invoke-Command -ComputerName $Servers -ScriptBlock {
    & "C:\Program Files\Dell\DELL System Update\DSU.exe" --source-location="$using:BinariesLocation\Updates" --source-type="Repository" --catalog-location="$using:BinariesLocation\ASHCI-Catalog.xml" --ic-location="$using:BinariesLocation\IC.exe" --apply-upgrades
    }

```