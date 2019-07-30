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
    Powershell.exe -ExecutionPolicy RemoteSigned -File 'C:\Admin\DQ\DQ-ADHealthCheck.ps1'
    ```
  - PowerShell
    ```powershell
    Set-ExecutionPolicy RemoteSigned -Force
    C:\Admin\DQ\DQ-ADHealthCheck.ps1
    ```
- All required modules and files will be downloaded and installed as part of the script process.
- Depending on number of domains, domain controllers, and users, the script can take several minutes to an hour to complete.
- An html file will generate in the folder 'C:\Admin\DQ' named with the root domain name and a date and timestamp.
  - *Example: 'C:\Admin\DQ\ADDashboard_contoso.com_2019-07-24T16-05-20.html'*


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


## Changelog

- v1.0.20190724
  - Initial Release
