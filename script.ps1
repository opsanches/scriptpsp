#######################################
################ Chris Titurs Debloater
###############
iwr -useb https://christitus.com/win | iex

#######################################
################ Chrome Policies
###############
Write-Output "##################################"
Write-Output "##                              ##"
Write-Output "##                              ##"
Write-Output "##   Applying Chrome Policies   ##"
Write-Output "##                              ##"
Write-Output "##                              ##"
Write-Output "##################################"
$pathGoogle = 'HKLM:\Software\Policies\Google\'  
$pathChrome = 'HKLM:\Software\Policies\Google\Chrome\'
$pathPopupSites = 'HKLM:\Software\Policies\Google\Chrome\PopupsAllowedForUrls'
$pathStartOI = 'HKLM:\Software\Policies\Google\Chrome\RestoreOnStartupURLs'
New-item -Path $pathGoogle  
New-item -Path $pathChrome
New-item -Path $pathPopupSites
New-item -Path $pathStartOI

## Disable Print Preview
New-ItemProperty -Path $pathChrome -Name 'DisablePrintPreview' -Value 1 -PropertyType DWord

## Do not allow Notifications
New-ItemProperty -Path $pathChrome -Name 'DefaultNotificationsSetting' -Value 2 -PropertyType DWord

## Allow Popup for OficinaInteligete
New-ItemProperty -Path $pathPopupSites -Name '1' -Value '[*.]sistemaoficinainteligente.com.br' -PropertyType String

## Disable Password Auto-fill
New-ItemProperty -Path $pathChrome -Name 'PasswordManagerEnabled' -Value 0 -PropertyType DWord
New-ItemProperty -Path $pathChrome -Name 'AutoFillEnabled' -Value 0 -PropertyType DWord

## Startup Page is sistemaoficinainteligente.com.br
New-ItemProperty -Path $pathStartOI -Name '4' -Value 'sistemaoficinainteligente.com.br' -PropertyType String
New-ItemProperty -Path $pathChrome -Name 'RestoreOnStartup' -Value 4 -PropertyType DWord

#######################################
################ PSP Policies
###############
# Change Hostname
Write-output "Give this computer a new name - (PSPMA001)"
$computerName = Read-Host
Rename-Computer -NewName $computerName

# Enable Local Admin
Write-Output "Enter new Password for Administrator:"
$Password = Read-Host
$UserAccount = Get-LocalUser -Name Administrator
$UserAccount | Set-LocalUser -Password $Password
Enable-LocalUser -Name "administrator"

# Change Password local_user
Write-Output "Enter new Password for this user:"
$Password = Read-Host -AsSecureString
$UserAccount = Get-LocalUser -Name $env:UserName
$UserAccount | Set-LocalUser -Password $Password

# Remove Administrator Privileges
Write-Output "Revoke Administrator Privileges..."
$currentUser = whoami
Add-LocalGroupMember -Group "users" -Member $currentUser
Remove-LocalGroupMember -Group Administrators -Member $currentUser

# Grant Administrator Privileges
# Write-Output "Granting Administrator Privileges..."
# $currentUser = whoami
# Add-LocalGroupMember -Group “Administrators” -Member $currentUser
# Remove-LocalGroupMember -Group "users" -Member $currentUser

# Add new user
# Write-Output "Creating new user"
# Write-Output "Type the username:"
# $newUser = Read-host
# Write-Output "Create a password:"
# $Password = Read-Host -AsSecureString
# New-LocalUser -Name $newUser -Description $newUser -Password $Password
# Add-LocalGroupMember -Group "users" -Member $newUser

# Delete Local_User
# Write-Output "Creating new user"
# Write-Output "Type the username you want to delete:"
# $deleteUser = Read-host
# Remove-LocalUser -Name $deleteUser

## Do not use sign-in info to automatically finish setting up device and reopen apps after an update or restart
Write-Output "Do not use sign-in info to automatically finish setting up device"
$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID"))
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -PropertyType DWord -Value 1 -Force

# Do not let websites provide locally relevant content by accessing language list
Write-Output "Do not let websites provide locally relevant content by accessing language list"
New-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -PropertyType DWord -Value 1 -Force

# Do not allow apps to use advertising ID
Write-Output "Do not allow apps to use advertising ID"
if (-not (Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -PropertyType DWord -Value 0 -Force

# Do not show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested
Write-Output "Do not show the Windows welcome experiences"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-310093Enabled -PropertyType DWord -Value 0 -Force

# Turn off automatic installing suggested apps
Write-Output "Turn off automatic installing suggested apps"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -PropertyType DWord -Value 0 -Force

# Do not suggest ways I can finish setting up my device to get the most out of Windows
Write-Output "Do not suggest ways I can finish setting up my device to get the most out of Windows"
if (-not (Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -PropertyType DWord -Value 0 -Force

# Do not offer tailored experiences based on the diagnostic data setting
Write-Output "Do not offer tailored experiences based on the diagnostic data setting"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -PropertyType DWord -Value 0 -Force

# Do not show "Recent files" in Quick access
Write-Output "Do not show Recent files in Quick access"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -PropertyType DWord -Value 0 -Force

# Set the large icons in the Control Panel
Write-Output "Set the large icons in the Control Panel"
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 1 -Force

# Do not add the "- Shortcut" for created shortcuts
Write-Output "Do not add the "- Shortcut" for created shortcuts"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name link -PropertyType Binary -Value ([byte[]](00, 00, 00, 00)) -Force

# Display the Stop error information on the BSoD
Write-Output "Display the Stop error information on the BSoD"
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name DisplayParameters -PropertyType DWord -Value 1 -Force

# Turn off Admin Approval Mode for administrators
# New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -PropertyType DWord -Value 0 -Force

# Set the default input method to English
#Set-WinDefaultInputMethodOverride "0409:00000409"

# Run the Command Prompt shortcut from the Start menu as Administrator
#[byte[]]$bytes = Get-Content -Path "$env:APPDATA\Microsoft\Windows\Start menu\Programs\System Tools\Command Prompt.lnk" -Encoding Byte -Raw
#$bytes[0x15] = $bytes[0x15] -bor 0x20
#Set-Content -Path "$env:APPDATA\Microsoft\Windows\Start menu\Programs\System Tools\Command Prompt.lnk" -Value $bytes -Encoding Byte -Force

# Make Portuguese default language
# Get-WinUserLanguageList
Write-Output "###################################"
Write-Output "##                               ##"
Write-Output "## Setting Portuguese as Default ##"
Write-Output "##  Finish this in the Settings  ##"
Write-Output "##   You can close this window   ##"
Write-Output "##                               ##"
Write-Output "###################################"
Set-WinSystemLocale pt-BR
Set-WinUserLanguageList pt-BR -Force
install-language pt-BR -CopyToSettings
