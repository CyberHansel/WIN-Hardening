# WIN-Hardening


## STIG HIGH Severity

\#Anonymous access to Named Pipes and Shares must be restricted  
cmd.exe /c "regreg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f"  
\#Anonymous enumeration of shares must be restricted  
cmd.exe /c "regreg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f"  





