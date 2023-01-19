# #WIN-10 Hardening


## #STIG HIGH Severity

#Anonymous access to Named Pipes and Shares must be restricted  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f"  
#Anonymous enumeration of shares must be restricted  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f"  
#The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f"  
#LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f"  
#Solicited Remote Assistance must not be allowed
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f"  
#default autorun behavior must be configured to prevent autorun  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f"  
#Structured Exception Handling Overwrite Protection (SEHOP) must be enabled  
cmd.exe /c "regreg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 0x00000000 /f"  
#Windows Installer Always install with elevated privileges must be disabled  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f"  
#Windows Remote Management (WinRM) client must not use Basic authentication  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowBasic /t REG_DWORD /d 0 /f"  
#(WinRM) service must not use Basic authentication  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowBasic /t REG_DWORD /d 0 /f"  
#Autoplay must be turned off for non-volume device  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f"  
#Disable Autorun   
cmd.exe /c "reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f"
cmd.exe /c "reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f"  
#Anonymous enumeration of SAM accounts must not be allowed  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f"  
#Autoplay must be disabled for all drives  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f"  

## #STIG Medium Severity  

#Enable anti-spoofing for facial recognition  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f"  
#Disable Disable SMBv3 compression to block unauthenticated attackers from exploiting the vulnerability against an SMBv3 Server (not in STIG) 
cmd.exe /c "reg add "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableCompression /t REG_DWORD /d 1 /f"
#The Windows Defender SmartScreen for Explorer must be enabled  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f"  
#Explorer Data Execution Prevention must be enabled  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f"  
#Allow only basic Windows telemetry 0 - enterprise only, Basic - 1  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 1 /f"  
#Enhanced diagnostic data is enabled it must be limited to the minimum required to support Windows Analytics  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f"  
#Remote calls to the Security Account Manager (SAM) must be restricted to Administrators  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f"  
#prevent anonymous users from having the same rights as the Everyone group  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f"  
#Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f"  
#PKU2U authentication using online identities must be prevented  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u" /v AllowOnlineID /t REG_DWORD /d 0 /f"  
#NTLM must be prevented from falling back to a Null session  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f"  
#The system must be configured to the required LDAP client signing level  
cmd.exe /c "regreg add "HKLM\System\CurrentControlSet\Services\ldap" /v "LDAPClientIntegrity " /t REG_DWORD /d 1 /f"  
#The Application event log size must be configured to 32768 KB or greater  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" /v MaxSize /t REG_DWORD /d 32768 /f"  
#Unauthenticated RPC clients must be restricted from connecting to the RPC server
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f"  
#Users must be prompted for a password on resume from sleep (on battery)  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f"  
#Local users on domain-joined computers must not be enumerated  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnumerateLocalUsers /t REG_DWORD /d 0 /f"  
#The user must be prompted for a password on resume from sleep (plugged in)  
cmd.exe /c reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f"  
#Windows 10 Kernel (Direct Memory Access) DMA Protection must be enabled  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" /v DeviceEnumerationPolicy /t REG_DWORD /d 0 /f"  
#The Security event log size must be configured to 1024000 KB or greater  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" /v MaxSize /t REG_DWORD /d 1024000 /f"  
#The System event log size must be configured to 32768 KB or greater  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" /v MaxSize /t REG_DWORD /d 32768 /f"  
#File Explorer shell protocol must run in protected mode  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f"  
#The system must be configured to require a strong session key  
cmd.exe /c "regreg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f" 
#Outgoing secure channel traffic must be encrypted when possible  
cmd.exe /c "reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f"  
#Outgoing secure channel traffic must be encrypted or signed  
cmd.exe /c "reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f"  
#Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'  
cmd.exe /c "reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f"  
#Remote Desktop Services must always prompt a client for passwords upon connection  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fPromptForPassword /t REG_DWORD /d 1 /f"
#Passwords must not be saved in the Remote Desktop Client  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v DisablePasswordSaving /t REG_DWORD /d 1 /f"
#Local drives must be prevented from sharing with Remote Desktop Session Hosts  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f"  
#The Remote Desktop Session Host must require secure RPC communications  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f"  
#Remote Desktop Services must be configured with the client connection encryption set to the required level (3 - "High Level")  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel /t REG_DWORD /d 3 /f"  
#Disabling RPC usage from a remote asset interacting with scheduled tasks  
cmd.exe /c "reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f"  
#The Windows Remote Management (WinRM) client must not use Digest authentication  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowDigest /t REG_DWORD /d 0 /f"  
#The Windows Remote Management (WinRM) client must not allow unencrypted traffic  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f"  
#The Windows Remote Management (WinRM) service must not allow unencrypted traffic
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f"  
#The Windows Remote Management (WinRM) service must not store RunAs credentials  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v DisableRunAs /t REG_DWORD /d 1 /f"     
#Windows 10 must be configured to enable Remote host allows delegation of non-exportable credentials  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f"  
#Attachments must be prevented from being downloaded from RSS feeds  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v DisableEnclosureDownload /t REG_DWORD /d 1 /f"  
#Basic authentication for RSS feeds over HTTP must not be used   
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v AllowBasicAuthInClear /t REG_DWORD /d 0 /f"  
#Indexing of encrypted files must be turned off  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f"   
#Users must be prevented from changing installation options  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v EnableUserControl /t REG_DWORD /d 0 /f"  
#Users must be notified if a web-based program attempts to install software  
cmd.exe /c "reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f"  
#EDGE
#The Windows Defender SmartScreen filter for Microsoft Edge must be enabled 
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v EnabledV9 /t REG_DWORD /d 1 /f"
#The password manager function in the Edge browser must be disabled (2 locations below, dunno which one key correct 1st from STIG!) 
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f"
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "FormSuggest Passwords" /t REG_SZ /d no /f"  
#Windows 10 must be configured to prevent certificate error overrides in Microsoft Edge  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings" /v PreventCertErrorOverrides /t REG_DWORD /d 1 /f"   
#Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in Microsoft Edge  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v PreventOverrideAppRepUnknown /t REG_DWORD /d 1 /f"   
#Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in Microsoft Edge  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v PreventOverride /t REG_DWORD /d 1 /f"   
#
#Automatically signing in the last interactive user after a system-initiated restart must be disabled  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f"  
#chatGPT - This will prevent the Bluetooth service from starting automatically when the system boots up  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters" /v "Start" /t REG_DWORD /d 4 /f"  
#Camera access from the lock screen must be disabled  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f"   
#The system must be configured to prevent IP source routing  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f"  
#The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f"  
#IPv6 source routing must be configured to highest protection  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f"    
#Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.  
#https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f"  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f  
#The Server Message Block (SMB) v1 protocol must be disabled on the SMB client  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f"  
#The Server Message Block (SMB) v1 protocol must be disabled on the SMB server  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f"  
#  
#ChatGPT - The system must notify the user when a Bluetooth device attempts to connect  
cmd.exe /c "reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}" /v Value /t REG_DWORD /d 1 /f"  
#ChatGPT -   Windows 10 account lockout duration must be configured to 15 minutes or greater
cmd.exe /c "reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "LockoutDuration" /t REG_SZ /d 900 /f"  
#Windows 10 must be configured to require a minimum pin length of six characters or greater  
cmd.exe /c "regreg add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" /v MinimumPINLength /t REG_DWORD /d 6 /f"  
#The use of a hardware security device with Windows Hello for Business must be enabled  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /v RequireSecurityDevice /t REG_DWORD /d 1 /f"  
#Windows 10 must be configured to disable Windows Game Recording and Broadcasting  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f"   
#Local drives must be prevented from sharing with Remote Desktop Session Hosts  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f"  
#Unencrypted passwords must not be sent to third-party SMB Servers (Could impact consumer grade file shares!)  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f"  
#Administrator accounts must not be enumerated during elevation  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v EnumerateAdministrators /t REG_DWORD /d 0 /f"  
#  
#PASSWORD
#ChatGPT - The minimum password age must be configured to at least 1 day (86400 seconds = 1 day)
cmd.exe /c "reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "MinimumPasswordAge" /t REG_DWORD /d 86400 /f"  
#ChatGPT - Passwords must, at a minimum, be 14 characters
cmd.exe /c "reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v minPwdLength /t REG_DWORD /d 14 /f"  
#ChatGPT - The built-in Microsoft password complexity filter must be enabled  
cmd.exe /c "reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordFilter /t REG_DWORD /d 1 /f"
#ChatGPT - The number of allowed bad logon attempts must be configured to 3 or less  
cmd.exe /c "reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "LockoutThreshold" /t REG_DWORD /d 3 /f"  
#ChatGPT - The period of time before the bad logon counter is reset must be configured to 15 minutes  
cmd.exe /c "reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "LockoutDuration" /t REG_DWORD /d 900 /f"  
#The convenience PIN for Windows 10 must be disabled  
cmd.exe /c "reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v AllowDomainPINLogon /t REG_DWORD /d 0 /f"  
#  
#Windows Ink Workspace must be configured to disallow access above the lock  
cmd.exe /c "reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowWindowsInkWorkspace /t REG_DWORD /d 1 /f"   
#The network selection user interface (UI) must not be displayed on the logon screen and cant be changed without signing into Windows  
#Prevent Local windows wireless exploitation: the Airstrike attack https://shenaniganslabs.io/2021/04/13/Airstrike.html
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f"  
#WDigest Authentication must be disabled. When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security Authority  
#Subsystem Service (LSASS) exposing them to theft.  
cmd.exe /c "regreg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0"  
#Local accounts with blank passwords must be restricted to prevent access from the network  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f" 
#  
#POWERSHELL  
#PowerShell Transcription must be enabled on Windows 10  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f" 
#Enable PowerShell Logging  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f"  
#PowerShell script block logging must be enabled on Windows 10
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f"  
#  
#The system must be configured to meet the minimum session security requirement for NTLM SSP based clients  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f"  
#The system must be configured to meet the minimum session security requirement for NTLM SSP based servers  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f"  
#The Windows Explorer Preview pane must be disabled for Windows 10  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPreviewPane /t REG_DWORD /d 1 /f"  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoReadingPane /t REG_DWORD /d 1 /f"  
#Outgoing secure channel traffic must be signed when possible  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f"  
#Zone information must be preserved when saving attachments  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f"  
#User Account Control must virtualize file and registry write failures to per-user locations  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f"  
#User Account Control must run all administrators in Admin Approval Mode, enabling UAC, limiting the elevation of privileges  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f"  
#Downloading print driver packages over HTTP must be prevented  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f"  
#Web publishing and online ordering wizards must be prevented from downloading a list of providers  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWebServices /t REG_DWORD /d 1 /f"   
#Printing over HTTP must be prevented  
cmd.exe /c "regreg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f"  
#Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers
#8 - Good only, 1 - Good and unknown, 3 - Good, unknown and bad but critical, 7 - All (which includes "Bad" and would be a finding) 
cmd.exe /c "reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f"  
#User Account Control must automatically deny elevation requests for standard users
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f"  
#User Account Control must, at minimum, prompt administrators for consent on the secure desktop  
cmd.exe /c "regreg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f"  
#User Account Control must be configured to detect application installations and prompt for elevation  
cmd.exe /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f"  
#The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" /v Enabled /t REG_DWORD /d 1 /f"  
#User Account Control must only elevate UIAccess applications that are installed in secure locations  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f"  
#Command line data must be included in process creation events (eventid 4688)   
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f"  
#Wi-Fi Sense must be disabled (as of v1803 of Windows 10; Wi-Fi sense is no longer available)  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f"  
#Windows 10 must be configured to prioritize ECC Curves with longer key lengths first
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v EccCurves /t REG_MULTI_SZ /d NistP384 NistP256 /f"  
#Internet connection sharing must be disabled 
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f"  
#Insecure logons to an SMB server must be disabled (guest acc SMB)  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f"  
#Run as different user must be removed from context menus  
cmd.exe /c "reg add HKEY_LOCAL_MACHINE\SOFTWARE\Classes\batfile\shell\runasuser /v SuppressionPolicy /t REG_DWORD /d 4096 /f"  
cmd.exe /c "reg add HKEY_LOCAL_MACHINE\SOFTWARE\Classes\cmdfile\shell\runasuser /v SuppressionPolicy /t REG_DWORD /d 4096 /f"  
cmd.exe /c "reg add HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runasuser /v SuppressionPolicy /t REG_DWORD /d 4096 /f"  
cmd.exe /c "reg add HKEY_LOCAL_MACHINE\SOFTWARE\Classes\mscfile\shell\runasuser /v SuppressionPolicy /t REG_DWORD /d 4096 /f"  
#The required legal notice must be configured to display before console logon  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LegalNoticeText /t REG_SZ /d "You are accessing a United Federation Government Information System (IS) that is provided for Starfleet-authorized use only. System is inside puma cat protected" /f"  
#The Smart Card removal option must be configured to Force Logoff or Lock Workstation (Set to "2" for logoff, set to "1" for lock)  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SCRemoveOption /t REG_DWORD /d 2 /f"  
#The Windows SMB client must be configured to always perform SMB packet signing  
cmd.exe /c "reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f"  
#The Windows SMB server must be configured to always perform SMB packet signing  
cmd.exe /c "reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f"  
#Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f"  

## #STIG Low Severity

#Windows Update must not obtain updates from other PCs on the Internet  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f"    
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f"  
#Turning off File Explorer heap termination on corruption must be disabled  
cmd.exe /c "regreg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f"  
#The system must be configured to ignore NetBIOS name release requests except from WINS servers (prevents a denial of service (DoS) attack)  
cmd.exe /c "regreg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f"  
#he Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f"  
#Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f"  
#The default permissions of global system objects must be increased (Windows systems maintain a global list of shared system resources such as DOS device names,  
#mutexes, and semaphores, allowing non-admin users to read shared objects, but not modify shared objects)  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f"  
#
#  
#GPO policies  
#  
#Group Policy objects must be reprocessed even if they have not changed. Any unauthorized changes are forced to match the domain-based group policy settings again  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoGPOListChanges /t REG_DWORD /d 0 /f"  
#Connections to non-domain networks when connected to a domain authenticated network must be blocked  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fBlockNonDomain /t REG_DWORD /d 1 /f"  
#Simultaneous connections to the Internet or a Windows domain must be limited  
cmd.exe /c "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f"  
#  
#
#AUDIT  
#Audit policy using subcategories must be enabled  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f"






#No remote clients may launch servers or connect to objects on this computer. Local clients cannot access remote DCOM servers; all DCOM traffic is blocked  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Ole" /v EnableDCOM /t REG_DWORD /d N /f"  

## DEFENDER   
#Enable Windows Defender sandboxing  
setx /M MP_FORCE_USE_SANDBOX 1  
#Signature update interval 4h interval  
Set-MpPreference -SignatureUpdateInterval 4
#Update signatures - Microsoft Malware Protection Center (MMPC)  
Update-MpSignature -UpdateSource mmpc  
#Enable Defender signatures for Potentially Unwanted Applications (PUA)  
Set-MpPreference -PUAProtection enable  
#Windows Defender does not exceed the percentage of CPU usage that you specify. The default value is 50%  
Set-MpPreference -ScanAvgCPULoadFactor 20  
#Enable Windows Defender real time monitoring  
cmd.exe /c "reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f"  
#Force update new signatures before each scan starts  
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1  

#Block Office applications from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
#Block Office applications from injecting code into other processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
#Block Win32 API calls from Office macro
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
#Block Office applications from creating executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
#Block Office communication application from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Adobe Reader from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled
::
:: Block execution of potentially obfuscated scripts
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
::
:: Block executable content from email client and webmail
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block JavaScript or VBScript from launching downloaded executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
::
:: Block executable files from running unless they meet a prevalence, age, or trusted list criteria
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled
::
:: Use advanced protection against ransomware
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block credential stealing from the Windows local security authority subsystem (lsass.exe)
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block untrusted and unsigned processes that run from USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block persistence through WMI event subscription
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled
::
:: Block process creations originating from PSExec and WMI commands
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
::
:: Block abuse of exploited vulnerable signed drivers
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 56A863A9-875E-4185-98A7-B882C64B5CE5 -AttackSurfaceReductionRules_Actions Enabled
::
:: Enable Controlled Folder
powershell.exe Set-MpPreference -EnableControlledFolderAccess Enabled












## FILE TYPES EXTENSION BLOCK TO NOTEPAD

ftype batfile="%systemroot%\system32\notepad.exe" "%1"
ftype chmfile="%systemroot%\system32\notepad.exe" "%1"
ftype cmdfile="%systemroot%\system32\notepad.exe" "%1"
ftype htafile="%systemroot%\system32\notepad.exe" "%1"
ftype jsefile="%systemroot%\system32\notepad.exe" "%1"
ftype jsfile="%systemroot%\system32\notepad.exe" "%1"
ftype vbefile="%systemroot%\system32\notepad.exe" "%1"
ftype vbsfile="%systemroot%\system32\notepad.exe" "%1"
ftype wscfile="%systemroot%\system32\notepad.exe" "%1"
ftype wsffile="%systemroot%\system32\notepad.exe" "%1"
ftype wsfile="%systemroot%\system32\notepad.exe" "%1"
ftype wshfile="%systemroot%\system32\notepad.exe" "%1"
ftype sctfile="%systemroot%\system32\notepad.exe" "%1"
ftype urlfile="%systemroot%\system32\notepad.exe" "%1"

#https://seclists.org/fulldisclosure/2019/Mar/27
ftype regfile="%systemroot%\system32\notepad.exe" "%1"
#https://www.trustwave.com/Resources/SpiderLabs-Blog/Firework--Leveraging-Microsoft-Workspaces-in-a-Penetration-Test/
ftype wcxfile="%systemroot%\system32\notepad.exe" "%1"
#https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
ftype mscfile="%systemroot%\system32\notepad.exe" "%1"
reg delete "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /f
reg add "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /t REG_SZ /d "" /f
#https://rinseandrepeatanalysis.blogspot.com/2018/09/dde-downloaders-excel-abuse-and.html
ftype slkfile="%systemroot%\system32\notepad.exe" "%1"
ftype iqyfile="%systemroot%\system32\notepad.exe" "%1"
ftype prnfile="%systemroot%\system32\notepad.exe" "%1"
ftype diffile="%systemroot%\system32\notepad.exe" "%1"
#https://posts.specterops.io/remote-code-execution-via-path-traversal-in-the-device-metadata-authoring-wizard-a0d5839fc54f
reg delete "HKLM\SOFTWARE\Classes\.devicemetadata-ms" /f
reg delete "HKLM\SOFTWARE\Classes\.devicemanifest-ms" /f
#CVE-2020-0765 impacting Remote Desktop Connection Manager (RDCMan) configuration files - MS won't fix
ftype rdgfile="%systemroot%\system32\notepad.exe" "%1"
#Mitigate ClickOnce .application and .deploy files vector
#https://blog.redxorblue.com/2020/07/one-click-to-compromise-fun-with.html
ftype applicationfile="%systemroot%\system32\notepad.exe" "%1"
ftype deployfile="%systemroot%\system32\notepad.exe" "%1"

















