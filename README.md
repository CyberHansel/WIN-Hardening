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
#














