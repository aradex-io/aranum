@echo off
REM Quick no-PowerShell enumeration. Useful when PS is blocked or restricted.
REM Output is plain text — pipe to a file: enum.bat > out.txt

echo === SYSTEMINFO ===
systeminfo
echo.
echo === WHOAMI /ALL ===
whoami /all
echo.
echo === LOCAL GROUP MEMBERSHIP (admins, RDP) ===
net localgroup administrators
net localgroup "Remote Desktop Users"
net localgroup "Remote Management Users"
echo.
echo === USERS ===
net user
echo.
echo === SCHEDULED TASKS (verbose) ===
schtasks /query /fo LIST /v
echo.
echo === SERVICES (running) ===
sc query state= all type= service
echo.
echo === UNQUOTED SERVICE PATHS ===
wmic service get name,displayname,pathname,startmode ^| findstr /i "auto" ^| findstr /i /v "C:\Windows\\"
echo.
echo === DRIVERS ===
driverquery /v
echo.
echo === HOTFIXES ===
wmic qfe get description,hotfixid,installedon
echo.
echo === NETWORK CONFIG ===
ipconfig /all
route print
arp -a
echo.
echo === LISTENING PORTS ===
netstat -ano | findstr /i "LISTENING"
echo.
echo === SHARES (local) ===
net share
echo.
echo === SAVED CREDENTIALS ===
cmdkey /list
echo.
echo === ALWAYSINSTALLELEVATED ===
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2^>nul
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2^>nul
echo.
echo === WSUS CONFIG ===
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer 2^>nul
echo.
echo === LAPS ===
reg query HKLM\Software\Policies\Microsoft Services\AdmPwd 2^>nul
echo.
echo === AUTOLOGON ===
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2^>nul ^| findstr /i "DefaultDomain DefaultUser DefaultPassword"
echo.
echo === HISTORY / TEMP files (browse interesting) ===
dir /a /s /b %USERPROFILE%\Desktop\*.txt %USERPROFILE%\Desktop\*.config 2^>nul
dir /a /s /b C:\Users\Public\*.txt C:\inetpub\wwwroot\*.config 2^>nul
echo.
echo === DONE ===
