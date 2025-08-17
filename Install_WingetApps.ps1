$winget_apps = @(
		"7zip.7zip"
		"Microsoft.VCRedist.2015+.x64"
		"Microsoft.VCRedist.2015+.x86"
		"Microsoft.OneDrive"
		"VideoLAN.VLC"
		"Google.Chrome"
		"Adobe.Acrobat.Reader.64-bit"
		"Microsoft.DotNet.DesktopRuntime.8"
		"9NKSQGP7F2NH"
	)

foreach ($appz in $winget_apps) {
	Write-Output "Installing $appz ..."
	winget install --id=$appz --scope machine --accept-source-agreements --accept-package-agreements --disable-interactivity
}
