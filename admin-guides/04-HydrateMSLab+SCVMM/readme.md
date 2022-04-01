# Admin Lab 04 - Hydrating MSLab with SCVMM

<!-- TOC -->

- [Admin Lab 04 - Hydrating MSLab with SCVMM](#admin-lab-04---hydrating-mslab-with-scvmm)
    - [Lab overview](#lab-overview)
    - [Task 1 - Check hardware requirements](#task-1---check-hardware-requirements)
    - [Task 2 - Download all necessary files](#task-2---download-all-necessary-files)
    - [Task 3 - Run "Prereqs" script](#task-3---run-prereqs-script)
    - [Task 4 - Populate SCVMM files](#task-4---populate-scvmm-files)
    - [Task 5 - Hydrate lab](#task-5---hydrate-lab)
        - [Expected result](#expected-result)

<!-- /TOC -->


## Lab overview

In this lab you will learn how to prepare MSLab to be able to setup labs. As result, you will have a folder with MSLab files (Domain Controller - ready to be imported, and three parent disks - Windows Server 2022 and Azure Stack HCI)

## Task 1 - Check hardware requirements

* Client or Server Operating System that supports Hyper-V (Windows 10 Pro, Windows 11 Pro or Windows Server)

* Hyper-V feature has to be enabled (tool will check it for you)

* at least 16GB RAM

* at least 100GB free space on SSD

Optionally you can setup VM in Azure Virtual Machine.

## Task 2 - Download all necessary files

In this task you will download all necessary files required to setup [MSLab](https://aka.ms/mslab).

**1.** Download MSLab scripts by navigating to [MSLab Download](https://aka.ms/mslab/download)

**2.** Dowload latest Windows Server ISO - either from [MSDN Downloads](https://my.visualstudio.com/downloads), [Eval Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022) or [VLSC Portal](https://www.microsoft.com/licensing/servicecenter)

**3.** Download latest [Azure Stack HCI OS ISO](https://azure.microsoft.com/en-us/products/azure-stack/hci/hci-download/)

![](./media/explorer01.png)

**4.** Download [Windows 11 ADK](https://go.microsoft.com/fwlink/?linkid=2165884)

**5.** Download [Windows PE add-on for ADK](https://go.microsoft.com/fwlink/?linkid=2166133)

**6.** Download [SQL 2019 Eval](https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2019)

**7.** Download [System Center 2022 Eval](https://www.microsoft.com/en-us/evalcenter/evaluate-system-center-2022)


## Task 3 - Run "Prereqs" script

**1.** Unzip files from downloaded zip into a folder on SSD, where is enough available space (at least 100GB)

**2.** Replace content of LabConfig.ps1 with following code. You can double-click the file to open it in Notepad.

```PowerShell
$LabConfig=@{ 
DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; DCEdition='4';InstallSCVMM='yes'}
 
```
> Above labconfig will create custom Domain Controller. Built on top of Windows Server Datacenter with GUI together with System Center Virtual Machine Manager 2022

![](./media/explorer03.png)

**3.** Right-click 1_Prereq.ps1 and select **Run with PowerShell**. The script will automatically elevate. Allow it run as administrator

![](./media/explorer04.png)

**4.** The script will finish. It will download necessary files and create folders. You can close PowerShell window now by pressing enter.

![](./media/explorer05.png)

## Task 4 - Populate SCVMM files

**1.** Navigate to downloads folder and run **adksetup.exe**. Windows Assessment and Deployment kit window will be displayed.

**2.** In Windows Assessment and Deployment Kit window specify location to extract the files (C:\MSLab\Temp\ToolsVHD\SCVMM\ADK)

![](./media/adk01.png)

![](./media/adk02.png)

**3.** From Downloads folder run **adkwinpesetup.exe**. Windows Assessment and Deployment kit window will be displayed.

**4.** In Windows Assessment and Deployment Kit window specify location to extract the files (C:\MSLab\Temp\ToolsVHD\SCVMM\ADKWinPE)

![](./media/adk03.png)

![](./media/adk04.png)

**5.** From Downloads folder run **SCVMM_2022.exe**. System Center Virtual Machine Manager extraction tool will appear.

**6.** System Center Virtual Machine Manager extraction tool window specify location to extract the files (C:\MSLab\Temp\ToolsVHD\SCVMM\SCVMM)

![](./media/scvmm01.png)

![](./media/scvmm02.png)

**7.** From Downloads folder run **SQL2019-SSEI-Eval.exe**. SQL Server 2019 installer will appear. Select Download Media. Select Defaults (Downloads as a download folder) and Click on Download. Close the windows once finished downloading.

![](./media/sql01.png)

![](./media/sql02.png)

**8.** In Downloads open **SQLServer2019-x64-ENU.iso** and copy content into SQL folder (C:\MSLab\Temp\ToolsVHD\SCVMM\SQL)

result:

![](./media/explorer06.png)

**9.** After files were copied, you can now eject the ISO file by right-clicking on the volume and selecting eject

![](./media/explorer07.png)

## Task 5 - Hydrate lab

**1.** In MSLab folder Right-click 2_CreateParentDisks.ps1 and select **Run with PowerShell**

![](./media/explorer08.png)

**2.** When asked for ISO file, choose Windows Server 2022

![](./media/explorer09.png)

**3.** When asked for Windows Server Update (msu), click **cancel**

> Script will now create Domain Controller and Windows Server 2022 parent disks and will install SCVMM. It will take ~60 minutes to finish. Once Finished, press Enter to close window (it will cleanup unnecessary files and folders).

![](./media/powershell01.png)

### Expected result

In MSLab folder you should see LAB and ParentDisks folder along with three PowerShell scripts and log files.

![](./media/explorer10.png)

Once lab is deployed, you will notice that SCVMM is installed

![](./media/scvmm03.png)

![](./media/scvmm04.png)


