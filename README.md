# ADHealthCheck

- [DQ-ADHealthCheck.ps1](DQ-ADHealthCheck.ps1) file cretes the Save Location and downloads the start and run scripts.
- [DQ-ADHealthCheck-Run.ps1](DQ-ADHealthCheck-Run.ps1) file uses [PSWinDocumentation](https://github.com/EvotecIT/PSWinDocumentation), [PSWinReporting](https://github.com/EvotecIT/PSWinReporting), and [Dashimo](https://github.com/EvotecIT/Dashimo) to create an HTML Active Directory information and health report.


# How-To Run

- Script should be ran on a Domain Controller with [Windows Management Framework](https://docs.microsoft.com/en-us/powershell/wmf/) [5.1](https://aka.ms/wmf51download) or above installed.
- If the script has already been ran on machine, the folder 'C:\Admin\DQ' will exist with the files listed above inside.
  - If the folder 'C:\Admin\DQ' does not exist or the file [DQ-ADHealthCheck.ps1](DQ-ADHealthCheck.ps1) is not inside, skip to [How-To Install](#How-To-Install) in this document.
  - Note that all files listed [above](#ADHealthCheck) are required to run, only [DQ-ADHealthCheck.ps1](DQ-ADHealthCheck.ps1) as it will download all necessary files to complete.
- Run 'C:\Admin\DQ\DQ-ADHealthCheck.ps1' from an elevated command prompt.
- Depending on number of domains, domain controllers, and users, the script can take several minutes to an hour to complete.
- An html file will generate in the folder 'C:\Admin\DQ' named with the root domain name and a date and timestamp.
  - Example: 'C:\Admin\DQ\ADDashboard_contoso.com_2019-07-24T16-05-20.html'


# How-To Install

- Run the following commands from an elevated command prompt to create the required 'C:\Admin\DQ' folder and download the [DQ-ADHealthCheck.ps1](DQ-ADHealthCheck.ps1) file.
```powershell
$SaveLocation = 'C:\Admin\DQ'
$Repository = 'https://raw.githubusercontent.com/dq-casteam/DQ-ADHealthCheck/master'
$Script = 'DQ-ADHealthCheck'
New-Item -ItemType Directory -Path $SaveLocation -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri $Repository/$Script.ps1 -OutFile $SaveLocation\$Script.ps1 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
```
- Refer to [How-To Run](#How-To-Run) in this document for instructions to run the script.
