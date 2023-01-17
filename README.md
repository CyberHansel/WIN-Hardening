# WIN-10 Hardening


## STIG HIGH Severity

#Anonymous access to Named Pipes and Shares must be restricted  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f"  
#Anonymous enumeration of shares must be restricted  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f"  
#The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f"  
#LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM  
cmd.exe /c "reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f'





