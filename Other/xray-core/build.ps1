Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)

$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/XTLS/Xray-core/releases/latest'
$asset = $release.assets | Where-Object { $_.name -eq 'Xray-windows-64.zip' } | Select-Object -First 1
if ( $null -eq $asset ) {
    Write-Host 'Xray windows amd64 release asset not found'
    exit 1
}

Invoke-WebRequest -Uri $asset.browser_download_url -OutFile 'xray.zip'
Expand-Archive -Force -Path 'xray.zip' -DestinationPath 'xray'
mv -Force 'xray\xray.exe' '..\release\xray.exe'

exit $lastExitCode
