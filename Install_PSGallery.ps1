##########################################
Write-Output "Installing PSGallery..."
##########################################

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name PSWindowsUpdate
