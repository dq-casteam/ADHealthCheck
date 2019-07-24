# ADHealthCheck

- [DQ-ADHealthCheck.ps1](DQ-ADHealthCheck.ps1) file cretes the Save Location and downloads the start and run scripts.
- [DQ-ADHealthCheck-Run.ps1](DQ-ADHealthCheck-Run.ps1) file uses [PSWinDocumentation](https://github.com/EvotecIT/PSWinDocumentation), [PSWinReporting](https://github.com/EvotecIT/PSWinReporting), and [Dashimo](https://github.com/EvotecIT/Dashimo) to create an HTML Active Directory information and health report.


# How-To Run

- Script should be ran on a Domain Controller with [Windows Management Framework](https://docs.microsoft.com/en-us/powershell/wmf/) [5.1](https://aka.ms/wmf51download) or above installed.
- If the script has already been ran on machine, the folder 'C:\Admin\DQ' will exist with the files listed above inside.
- Run [DQ-ADHealthCheck.ps1](DQ-ADHealthCheck.ps1) from an elevated command prompt
