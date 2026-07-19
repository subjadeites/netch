param (
	[Parameter()]
	[ValidateSet('Debug', 'Release')]
	[string]
	$Configuration = 'Release',

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]
	$OutputPath = 'release',

	[Parameter()]
	[bool]
	$SelfContained = $True,

	[Parameter()]
	[bool]
	$PublishSingleFile = $True,

	[Parameter()]
	[bool]
	$PublishReadyToRun = $False
)

Push-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)

function Invoke-MSBuild {
	param (
		[Parameter(Mandatory = $True)]
		[string]
		$Project
	)

	$MSBuild = Get-Command msbuild -ErrorAction SilentlyContinue
	if ( -Not $MSBuild ) {
		$VSWhere = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
		if ( Test-Path $VSWhere ) {
			$MSBuildPath = & $VSWhere -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
			if ( $MSBuildPath ) {
				$MSBuild = Get-Command $MSBuildPath -ErrorAction SilentlyContinue
			}
		}
	}

	if ( -Not $MSBuild ) {
		Write-Error 'MSBuild was not found. Install Visual Studio Build Tools or run microsoft/setup-msbuild before build.ps1.'
		exit 1
	}

	& $MSBuild.Path `
		-property:Configuration=$Configuration `
		-property:Platform=x64 `
		$Project
}

if ( Test-Path -Path $OutputPath ) {
    rm -Recurse -Force $OutputPath
}
New-Item -ItemType Directory -Name $OutputPath | Out-Null

Push-Location $OutputPath
New-Item -ItemType Directory -Name 'bin'  | Out-Null
cp -Recurse -Force '..\Storage\i18n' '.'  | Out-Null
cp -Recurse -Force '..\Storage\mode' '.'  | Out-Null
cp -Recurse -Force '..\Storage\stun.txt' 'bin'  | Out-Null
cp -Recurse -Force '..\Storage\nfdriver.sys' 'bin'  | Out-Null
cp -Recurse -Force '..\Storage\aiodns.conf' 'bin'  | Out-Null
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb' -OutFile 'bin\GeoLite2-Country.mmdb'
#cp -Recurse -Force '..\Storage\GeoLite2-Country.mmdb' 'bin'  | Out-Null
cp -Recurse -Force '..\Storage\tun2socks.bin' 'bin'  | Out-Null
cp -Recurse -Force '..\Storage\README.md' 'bin'  | Out-Null
Pop-Location

if ( -Not ( Test-Path '.\Other\release' ) ) {
	.\Other\build.ps1
	if ( -Not $? ) {
		exit $lastExitCode
	}
}
cp -Force '.\Other\release\*.bin' "$OutputPath\bin"
cp -Force '.\Other\release\*.dll' "$OutputPath\bin"
cp -Force '.\Other\release\*.exe' "$OutputPath\bin"

if ( -Not ( Test-Path ".\Netch\bin\$Configuration" ) ) {
	Write-Host
	Write-Host 'Building Netch'

	dotnet publish `
		-c $Configuration `
		-r 'win-x64' `
		-p:Platform='x64' `
		-p:SelfContained=$SelfContained `
		-p:PublishTrimmed=$PublishReadyToRun `
		-p:PublishSingleFile=$PublishSingleFile `
		-p:PublishReadyToRun=$PublishReadyToRun `
		-p:PublishReadyToRunShowWarnings=$PublishReadyToRun `
		-p:IncludeNativeLibrariesForSelfExtract=$SelfContained `
		-o ".\Netch\bin\$Configuration" `
		'.\Netch\Netch.csproj'
	if ( -Not $? ) { exit $lastExitCode }
}
cp -Force ".\Netch\bin\$Configuration\Netch.exe" $OutputPath

if ( -Not ( Test-Path ".\Redirector\bin\$Configuration" ) ) {
	Write-Host
	Write-Host 'Building Redirector'

	Invoke-MSBuild '.\Redirector\Redirector.vcxproj'
	if ( -Not $? ) { exit $lastExitCode }
}
cp -Force ".\Redirector\bin\$Configuration\nfapi.dll"      "$OutputPath\bin"
cp -Force ".\Redirector\bin\$Configuration\Redirector.bin" "$OutputPath\bin"

if ( -Not ( Test-Path ".\RouteHelper\bin\$Configuration" ) ) {
	Write-Host
	Write-Host 'Building RouteHelper'

	Invoke-MSBuild '.\RouteHelper\RouteHelper.vcxproj'
	if ( -Not $? ) { exit $lastExitCode }
}
cp -Force ".\RouteHelper\bin\$Configuration\RouteHelper.bin" "$OutputPath\bin"

if ( $Configuration.Equals('Release') ) {
	rm -Force "$OutputPath\*.pdb"
	rm -Force "$OutputPath\*.xml"
}

Pop-Location
exit 0
