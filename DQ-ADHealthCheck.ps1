Param(
	$SaveLocation = 'C:\Admin\DQ',
	$Repository = 'https://raw.githubusercontent.com/dq-casteam/DQ-ADHealthCheck/master',
	$Script = 'DQ-ADHealthCheck'
)
Write-Host ("[INFO] Creating Save Location $SaveLocation")
New-Item -ItemType Directory -Path $SaveLocation -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri $Repository/$Script.ps1 -OutFile $SaveLocation\$Script.ps1 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri $Repository/$Script-Run.ps1 -OutFile $SaveLocation\$Script-Run.ps1 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
$SaveLocation\$Script-Run.ps1
