Param(
	$SaveLocation = 'C:\Admin\DQ',
	$URL = 'https://raw.githubusercontent.com/dq-casteam/DQ-ADHealthCheck/master',
	$StartScript = 'DQ-ADHealthCheck.ps1',
	$RunScript = 'DQ-ADHealthCheck-Run.ps1'
)
Write-Host ("[INFO] Creating Save Location $SaveLocation")
New-Item -ItemType Directory -Path $SaveLocation -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri $URL/$StartScript -OutFile $SaveLocation\$StartScript -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri $URL/$RunScript -OutFile $SaveLocation\$RunScript -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
& "$SaveLocation\$RunScript"
