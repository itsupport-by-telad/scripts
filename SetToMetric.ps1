# Set Measurement System to Metric (0) for all users on the system
# Run as Administrator

$measurementValue = "0"
$profileRoot = "C:\Users"

# Loop through each profile (excluding system ones)
Get-ChildItem $profileRoot -Directory | ForEach-Object {
    $userProfile = $_.FullName
    $ntUserDat = Join-Path $userProfile "NTUSER.DAT"

    if (Test-Path $ntUserDat) {
        $tempHiveName = "TempHive_$($_.Name)"
        try {
            # Load the user hive
            reg load "HKU\$tempHiveName" $ntUserDat | Out-Null

            $regPath = "HKU:\$tempHiveName\Control Panel\International"
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "MeasurementSystem" -Value $measurementValue
            }

        } catch {
            Write-Warning "Could not update profile $($_.Name): $_"
        } finally {
            # Unload the hive
            reg unload "HKU\$tempHiveName" | Out-Null
        }
    }
}

# Also update Default User profile so new accounts get Metric
$defaultUserHive = "C:\Users\Default\NTUSER.DAT"
if (Test-Path $defaultUserHive) {
    reg load "HKU\DefaultUserTemp" $defaultUserHive | Out-Null
    $defaultRegPath = "HKU:\DefaultUserTemp\Control Panel\International"
    if (Test-Path $defaultRegPath) {
        Set-ItemProperty -Path $defaultRegPath -Name "MeasurementSystem" -Value $measurementValue
    }
    reg unload "HKU\DefaultUserTemp" | Out-Null
}

# Update current user immediately
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "MeasurementSystem" -Value $measurementValue
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters

Write-Host "Measurement system set to Metric for all users and future profiles."
