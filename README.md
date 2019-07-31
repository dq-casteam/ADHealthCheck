# ADHealthCheck

- [DQ-ADHealthCheck.ps1](DQ-ADHealthCheck.ps1) file creates the Save Location and downloads the start and run scripts.
- [DQ-ADHealthCheck-Run.ps1](DQ-ADHealthCheck-Run.ps1) file uses [PSWinDocumentation](https://github.com/EvotecIT/PSWinDocumentation), [PSWinReporting](https://github.com/EvotecIT/PSWinReporting), and [Dashimo](https://github.com/EvotecIT/Dashimo) to create an HTML Active Directory information and health report.


## How-To Run

- Script should be ran on a Domain Controller with [Windows Management Framework](https://docs.microsoft.com/en-us/powershell/wmf/) [5.1](https://aka.ms/wmf51download) or above installed.
- If the script has previously run on a machine, the folder 'C:\Admin\DQ' will exist with the files listed [above](#ADHealthCheck) inside.
  - If the folder 'C:\Admin\DQ' does not exist or the file [DQ-ADHealthCheck.ps1](DQ-ADHealthCheck.ps1) is not inside, skip to [How-To Install](#How-To-Install) in this document.
- Run 'C:\Admin\DQ\DQ-ADHealthCheck.ps1' from an elevated Command Prompt or PowerShell.
  - Command Prompt
    ```cmd
    Powershell.exe -ExecutionPolicy RemoteSigned -File C:\Admin\DQ\DQ-ADHealthCheck.ps1
    ```
  - PowerShell
    ```powershell
    C:\Admin\DQ\DQ-ADHealthCheck.ps1
    ```
- All required modules and files will be downloaded and installed as part of the script process.
- Depending on number of domains, domain controllers, and users, the script can take several minutes to an hour to complete.
- Multiple files will generate in the folder 'C:\Admin\DQ\ADHealthCheck' named with the root domain name and a date and timestamp.
  - ADDashboard_contoso.com_2019-07-24T16-05-20.html
  - DCDiag_contoso.com_2019-07-24T16-05-20.txt
  - RepAdmin_contoso.com_2019-07-24T16-05-20.txt


## How-To Install

- Run the following commands in an elevated PowerShell to create the required 'C:\Admin\DQ' folder and download the [DQ-ADHealthCheck.ps1](DQ-ADHealthCheck.ps1) file.
  - PowerShell
    ```powershell
    $SaveLocation = 'C:\Admin\DQ'
    $Repository = 'https://raw.githubusercontent.com/dq-casteam/DQ-ADHealthCheck/master'
    $Script = 'DQ-ADHealthCheck'
    New-Item -ItemType Directory -Path $SaveLocation -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri $Repository/$Script.ps1 -OutFile $SaveLocation\$Script.ps1 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    ```
- Refer to [How-To Run](#How-To-Run) in this document for instructions to run the script.


## Errors

- PowerShell Execution Policy
  ```powershell
  C:\Admin\DQ\DQ-ADHealthCheck.ps1 : File C:\Admin\DQ\DQ-ADHealthCheck.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.
  ```
  - Execution Policy for PowerShell needs to be changed to RemoteSigned or Unrestricted.
    ```powershell
    Set-ExecutionPolicy RemoteSigned -Force
    ```
- Access Denied
  ```powershell
  Invoke-WebRequest : Access to the path 'C:\Admin\DQ\DQ-ADHealthCheck.ps1' is denied.
  ```
  - The script is trying to copy over itself while running, this is normal and can be ignored.
- PowerShell Version
  ```powershell
  [FAILURE] This script requires PowerShell $PSMinimumVersion or higher. Go to https://docs.microsoft.com/en-us/powershell/wmf/ to download and install the latest version.
  ```
  - The script requires a higher version of PowerShell installed. Follow the link to download the latest [Windows Management Framework](https://docs.microsoft.com/en-us/powershell/wmf/).
- Module Installation or Loading 
  ```powershell
  [FAILURE] PowerShell Module $Module Installation Failed
  ```
  ```powershell
  [FAILURE] PowerShell Module $Module Loading Failed
  ```
  - Review logs and try again. All modules that load are required and need to be installed for the script to work correctly.
- For any other failure, try to [re-install](#How-To-Install) the script and try to run it again. 


## Changelog

- v1.0.20190724
  - Initial Release
